"""Entity resolution — pure, deterministic, no I/O.

From an alert's STRUCTURED fields (never LLM-driven), derive the best
identifiers to query:

- `resolve_unit(alert)`   -> likely container / log-stream name (normalizes
  CheckMK-style service names: strips "Docker container " prefixes,
  "host/service" forms, ".service"/" status"/compose "_1" suffixes).
- `resolve_unit_strict(alert)` -> the same normalization, but sourced ONLY
  from `unit`/`service` -- see its own docstring for why the host fallback
  below must never leak into a causal-entity gate.
- `extract_error_tokens(alert)` -> salient error keywords + identifiers from the
  alert output, used as extra log-search / correlation terms.

All never raise: on garbage input they return None / [].
"""
import re

# CheckMK / systemd style noise around the real unit name.
_PREFIX_RE = re.compile(
    r"^(?:docker\s+container|container|systemd\s+service|systemd|service|"
    r"process|proc|http|https)\s+", re.I)
_SUFFIX_RE = re.compile(r"(?:\.service|\s+status|[_-]\d+)$", re.I)

# Curated error-keyword vocabulary (word-boundary; HTTP codes included).
_ERROR_KEYWORD_RE = re.compile(
    r"\b(fatal|error|err|fail(?:ed|ure|ing)?|timeout|timed.out|refused|denied|"
    r"unreachable|unavailable|unhealthy|oom|out.of.memory|mount|read-?only|"
    r"segfault|sigsegv|sigterm|sigkill|panic|corrupt(?:ed|ion)?|wedged|"
    r"restart(?:ing|ed)?|crash(?:ed|ing)?|exit(?:ed)?|dropped|stalled|stale|"
    r"down|lost|missing|full|leak(?:ed|ing)?|throttl(?:ed|ing)|"
    r"40[013489]|429|5\d{2})\b", re.I)
# CamelCase / dotted identifiers worth searching logs for (AuxiliaryProcs, ...).
_IDENT_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b")


def _normalize_unit_raw(raw):
    """Shared prefix/suffix-peeling + lowercasing core of resolve_unit /
    resolve_unit_strict. `raw` must already be a non-empty stripped string;
    returns the normalized string or None."""
    raw = str(raw).strip()
    if not raw:
        return None
    if "/" in raw:  # "host/service" form -> the service part
        raw = raw.rsplit("/", 1)[-1].strip()
    prev = None
    while prev != raw:  # peel stacked prefixes/suffixes to a fixpoint
        prev = raw
        raw = _PREFIX_RE.sub("", raw).strip()
        raw = _SUFFIX_RE.sub("", raw).strip()
    return raw.lower() or None


def resolve_unit(alert):
    """Best-effort container/log-stream name from the alert. None if unusable.

    Preference order: `unit` > `service` > `host` (Phase 4.1) -- an adapter
    or operator can name the real docker container / log unit explicitly
    (e.g. openobserve.py's optional `unit`/`container` template field), so
    the alert name stops masquerading as the unit once a real one is known.
    Falls back to `alert["host"]` when there is no `unit`/`service` --
    correct for log/metrics queries (a host-level alert's logs live under
    the host's name), but this fallback must NEVER be used to derive a
    correlation gate key -- see resolve_unit_strict below, which is the one
    gate callers must use instead."""
    try:
        raw = alert.get("unit") or alert.get("service") or alert.get("host") or ""
        return _normalize_unit_raw(raw)
    except Exception:
        return None


def resolve_unit_strict(alert):
    """Like resolve_unit, but sourced ONLY from `alert.get("unit")` or
    `alert.get("service")` -- NEVER the host fallback.

    This is the identity `nuncio.correlate`'s causal-entity gate uses to
    compare "same container/check" across alerts. resolve_unit's host
    fallback exists for a different purpose (so log/metrics queries for a
    bare host-level alert still have something to query) and would smuggle
    the host back into the gate as a fake "unit" if reused here -- exactly
    the kind of one-level-removed host-equality bleed the ratified
    correlation model (see nuncio/correlate.py's module docstring) demotes
    host to a grouping-only signal to avoid. A "-" (or otherwise placeholder)
    service is not a unit either -- same guard as nuncio.model.real_host,
    applied to unit/service instead of host.

    Never raises: returns None on garbage/missing input."""
    try:
        raw = alert.get("unit") or alert.get("service") or ""
        raw = str(raw).strip()
        if not raw or raw == "-" or not any(c.isalnum() for c in raw):
            return None
        return _normalize_unit_raw(raw)
    except Exception:
        return None


def extract_error_tokens(alert, max_tokens=8):
    """Salient error tokens from the alert output (+ service), deduped
    case-insensitively in first-seen order, capped at `max_tokens`."""
    try:
        blob = " ".join(
            str(alert.get(k) or "") for k in ("output", "service"))
        tokens, seen = [], set()
        for m in _ERROR_KEYWORD_RE.finditer(blob):
            t = m.group(0)
            if t.lower() not in seen:
                seen.add(t.lower())
                tokens.append(t)
        for m in _IDENT_RE.finditer(blob):
            t = m.group(0)
            if t.lower() not in seen:
                seen.add(t.lower())
                tokens.append(t)
        # deterministic: first-seen order (keywords first, then identifiers)
        return tokens[:max_tokens]
    except Exception:
        return []
