"""The canonical alert contract + shared, source-agnostic helpers that used to
live scattered across `gatherer.py`/`store.py`.

Everything downstream of a source adapter's `parse()` operates on
`ParsedAlert` and ONLY `ParsedAlert` — this is the narrow waist. Kept as a
plain dict + a tiny frozen dataclass (stdlib only, no pydantic: portability
means zero dependencies, and there is nothing here to version).
"""
import re
from dataclasses import dataclass

# Idempotency-key prefix convention: every source adapter's key starts with
# "<source>:" so keys can never collide across sources.
# Synthetic canaries (heartbeat probes) use this fixed prefix so the store can
# exclude them from cross-alert correlation without a source-specific check
# (rather than a magic string inline in store.py).
CANARY_PREFIX = "canary:"


@dataclass(frozen=True)
class ParsedAlert:
    """What every source adapter must produce.

    key: str        idempotency key, unique per notification event, adapter-
                     derived. Convention: "<source>:<stable-fields>", e.g.
                     "checkmk:host01/CPU load/12345/PROBLEM/1". ALWAYS prefix
                     with the source name so keys can never collide.
    alert: dict      canonical fields — see the module docstring below.
    raw_text: str    human-readable one-line-or-few rendering of the native
                     payload; ships on the raw-fallback path and is embedded
                     under every enriched message. Must be meaningful alone.
    """
    key: str
    alert: dict
    raw_text: str


# alert dict canonical fields (all optional except host):
#   host: str         — the affected host/instance ("web-1", "10.0.0.5")
#   service: str|None — service/check/container/alertname; None for host-level
#   state: str        — native severity/state string ("CRIT", "firing", ...)
#   severity: str     — normalized via normalize_severity()
#   output: str       — the alert's message/annotation/plugin output
#   timestamp: str    — native event time, informational
#   source: str       — adapter name that produced it ("checkmk", "grafana")
#   category: str|None— optional adapter hint; when absent, categorize() runs
#   synthetic: bool   — canaries; excluded from correlation + quality stats
#
# An adapter MAY also set extra keys beyond these -- but only a FIXED
# ALLOWLIST of canonical extra keys actually flows into the prompt's ##
# Alert block (see nuncio.prompt._EXTRA_FIELD_SPECS: details/perfdata/
# check_command/event/ack/downtime/groups/address/recurrence/value/links,
# each length-capped, tail-preserving on overflow). Every other key an
# adapter or an untrusted ingest payload (e.g. NUNCIO_EXTRA_SOURCES posting
# straight at /ingest/generic) might set is silently dropped, never rendered
# -- this allowlist is a deliberate boundary above nuncio.engine's per-field
# VALUE redaction: it bounds prompt-injection surface and token burn by
# key, not just by content, since an attacker who can't smuggle a malicious
# value into a KNOWN field could otherwise still smuggle one into an
# arbitrary NEW field name.


# --- severity normalization (every adapter + the dashboard share one table) ---

_SEVERITY_MAP = {
    "critical": "critical", "crit": "critical", "down": "critical",
    "fatal": "critical", "emergency": "critical", "alert": "critical",
    "warning": "warning", "warn": "warning", "err": "warning",
    "error": "warning", "degraded": "warning",
    "info": "info", "notice": "info", "information": "info",
    "ok": "ok", "up": "ok", "resolved": "ok", "recovered": "ok",
    "recovery": "ok", "cleared": "ok", "good": "ok", "pending": "unknown",
    "unknown": "unknown",
}


def normalize_severity(raw):
    """Map a native severity/state string to one of
    critical|warning|info|ok|unknown — every adapter uses this table so the
    dashboard can aggregate across sources."""
    if not raw:
        return "unknown"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "unknown")


# --- disposition: the determinism doctrine's enrichment-framing gate -------
#
# Severity is a fact about the source's lifecycle state (see
# normalize_severity + Phase 1's adapter-side lifecycle rules); disposition
# is what that fact means for how an enrichment may be FRAMED. Exactly two
# severities carry a non-"problem" disposition -- "ok" (a lifecycle
# recovery: the problem has ended, there is nothing left to diagnose) and
# "info" (an informational event: never a problem to begin with). Every
# other severity, INCLUDING "unknown" (a genuine problem notification whose
# severity just couldn't be determined -- see the CheckMK adapter's
# _severity_from ladder and normalize_severity's own "unknown" fallback),
# is "problem" -- the conservative default, so an unclassifiable alert still
# gets full cause/checks framing rather than being silently muted.
#
# One function so nuncio.prompt (the addendum that asks the model nicely)
# and nuncio.engine (the post-LLM gate that enforces it regardless of model
# compliance -- see Engine._run_structured_call) can never drift on what
# counts as "not a problem".
_DISPOSITION_MAP = {"ok": "recovery", "info": "info"}


def disposition(severity):
    """Deterministic enrichment-framing disposition for a normalized
    `severity` value: "ok" -> "recovery", "info" -> "info", everything else
    (incl. "unknown") -> "problem"."""
    return _DISPOSITION_MAP.get(severity, "problem")


# --- host identity: placeholder guard + canonicalization (Phase 3 gate) ----
#
# "A placeholder host is not a host" (Determinism doctrine): several source
# adapters emit the literal "-" (or an empty/synthetic value) when the
# native payload carries no real instance/host field. Correlation must never
# treat that placeholder as a shared identity -- doing so is exactly the
# live bug (nuncio/correlate.py's old `\b-\b` regex matching the hyphen in
# unrelated names like TEST-NUNCIO). `real_host` is the single guard every
# persist/compare site uses so this can never be reimplemented slightly
# differently in two places.


def real_host(value):
    """`value` iff it is a genuine host identity: a non-empty string, not the
    "-" placeholder, and containing at least one alphanumeric character.
    Otherwise None. Pure, never raises."""
    v = str(value or "").strip()
    if v and v != "-" and any(c.isalnum() for c in v):
        return v
    return None


def canonical_host(value, domains=()):
    """Deterministic, pure string canonicalization of a host identity for
    CORRELATION COMPARISON ONLY -- never persisted (see nuncio/server.py's
    persist call site, which stores the real host verbatim so a later
    `domains` config change applies retroactively to already-stored rows).

    Steps: placeholder-guard `value` via `real_host` (None short-circuits);
    lowercase; strip exactly one trailing "." (FQDN dot); then, in the given
    `domains` order, strip the FIRST configured suffix `value` ends with
    (each `d` in `domains` is itself normalized: stripped of whitespace and
    leading dots, lowercased) -- first-match-wins is deterministic given a
    fixed, ordered `domains` tuple. Never strips a value down to the empty
    string (a value that IS the bare suffix, e.g. "kirits.net" itself with
    domains=("kirits.net",), is returned unstripped) -- an empty "host"
    would silently defeat `real_host`'s own guard downstream.

    This is a TOTAL string function of (value, domains) -- no DNS/IP
    resolution, no free-text scraping. "10.13.37.2" and "svr" remain
    distinct identities by design; that is deliberate, not a gap."""
    v = real_host(value)
    if v is None:
        return None
    v = v.lower()
    if v.endswith("."):
        v = v[:-1]
    for d in domains or ():
        d = str(d or "").strip().lstrip(".").lower()
        if not d:
            continue
        suffix = "." + d
        if v.endswith(suffix):
            stripped = v[: -len(suffix)]
            if stripped:
                return stripped
            return v  # never strip to empty -- keep the pre-strip value
    return v


# --- categorization (moved from gatherer.py) ---
#
# Word-boundary matches so container names don't false-trigger: 'smart' must
# not match a name like smartgallery, 'port' must not match portainer, and a
# real access-point hostname like drawing-ap must still match the network
# category. Kept as a plain module constant documented as a heuristic (not a
# claim of completeness); `add_category_rule()` is the extension point for
# operator-specific wording (the `category_rules:` NUNCIO_CONFIG YAML key).
_HARDWARE_RE = re.compile(
    r"\b(gpf|general protection|kernel|mce|machine check|ecc|thermal|oom|"
    r"segfault|watchdog|smart|nvme)\b", re.I)
_STORAGE_RE = re.compile(
    r"\b(cifs|mount|smb|xfs|btrfs|filesystem|disk full|read-only file system|"
    r"no space)\b", re.I)
_NETWORK_RE = re.compile(
    r"(\b(unifi|interface|switch|access point|wan|wifi|stp|poe|port|ap)\b|-ap\b|link down)", re.I)
_CONTAINER_RE = re.compile(
    r"\b(container|docker|compose|restart(?:ing|ed)?|unhealthy|healthcheck|"
    r"exit(?:ed)?|crash(?:ed|ing)?|image)\b", re.I)

# category -> list of compiled patterns; extendable at runtime via
# add_category_rule(). Only the 4 fixed categories are valid extension
# targets — the collector-selection table (gatherer.py) only knows these.
_CATEGORY_RES = {
    "hardware": [_HARDWARE_RE],
    "storage": [_STORAGE_RE],
    "network": [_NETWORK_RE],
    "container": [_CONTAINER_RE],
}

# Weighted multi-signal scoring: every keyword/regex hit counts, so a mixed
# alert ("container restarting: CIFS mount lost") scores in BOTH categories.
_HIT_WEIGHT = 2
_SERVICE_PRESENT_WEIGHT = 1   # a service field alone is weak container evidence
SECONDARY_MIN = 4             # >= two real keyword hits to add a secondary set
CATEGORY_PRIORITY = ["hardware", "storage", "network", "container", "generic"]


def add_category_rule(category, pattern):
    """Extend categorize()'s regex set for `category` with an additional
    `pattern` (str or compiled re.Pattern) — the `category_rules:`
    NUNCIO_CONFIG YAML extension point.
    `category` must be one of the 4 built-in categories (hardware/storage/
    network/container); the collector-selection table only knows those."""
    if category not in _CATEGORY_RES:
        raise ValueError(
            f"unknown category {category!r}; must be one of {sorted(_CATEGORY_RES)}"
        )
    if isinstance(pattern, str):
        pattern = re.compile(pattern, re.I)
    _CATEGORY_RES[category].append(pattern)


def score_categories(alert):
    """Deterministic per-category relevance scores from host+service+output.
    Every category is scored (not first-match), enabling secondary selection."""
    blob = " ".join(str(alert.get(k, "")) for k in ("host", "service", "output"))
    scores = {cat: _HIT_WEIGHT * sum(len(rx.findall(blob)) for rx in patterns)
              for cat, patterns in _CATEGORY_RES.items()}
    if alert.get("service"):
        scores["container"] = scores.get("container", 0) + _SERVICE_PRESENT_WEIGHT
    scores["generic"] = 0
    return scores


def categorize(alert):
    """Best-effort primary category = argmax of score_categories (ties
    resolved by fixed priority order). Default is safe (generic). This is the
    "core categorize() runs" behavior referenced in the ParsedAlert docstring
    when a source adapter doesn't supply an explicit `category` hint."""
    scores = score_categories(alert)
    best = max(CATEGORY_PRIORITY, key=lambda c: (scores[c], -CATEGORY_PRIORITY.index(c)))
    return best if scores[best] > 0 else "generic"
