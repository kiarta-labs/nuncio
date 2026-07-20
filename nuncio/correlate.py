"""Correlation scoring — pure, deterministic, no I/O.

**The ratified model (2026-07-20 — normative):** a row may enter the
returned CAUSAL context (eligible for "possible root"/"possible symptom"
annotations, ranked among the primary candidates) ONLY through a genuine
CAUSAL-ENTITY relation to the alert being enriched:

  (a) fingerprint match (recurrence of the same signature),
  (b) unit/service equality (same container / same CheckMK service), or
  (c) a declared `dependency_hints` edge (an operator-authored upstream
      relation, e.g. "infisical" depends on "infisical-postgres").

Host co-location is deliberately **NOT** a gate key. On a largely
single-host fleet, "same host" is near-universal — using it as a causal key
would fabricate a root/symptom chain between every unrelated alert on the
box (the original #2 production bug: an instance-less alert's `"-"`
placeholder even matched hyphens inside unrelated names via a bare regex).
A row sharing the alert's (canonicalized) host but failing the gate may
still be surfaced, but only LABELED `also active on <host>` — context, never
cause. Recency, error-token overlap, category, and shared path tokens are
RANK-ONLY signals: they order rows that already passed the gate (or order
grouping rows among themselves) — they never admit a row on their own.

Two-tier output:
  - Tier 0 (causal) = gated rows — reasons from whichever gate key(s) hit,
    plus rank-only annotations (tokens/category/paths/host-grouping) that
    order the tier.
  - Tier 1 (grouping) = host-grouped rows that failed the gate — rendered
    with the single `also active on <host>` annotation, ranked by recency
    only, and structurally ineligible for the causal root/symptom hint.
  - Everything else (no gate hit, no host match) is excluded entirely, even
    with token/category/path overlap.

`canonical_host()`/`real_host()` (nuncio.model) and `resolve_unit_strict()`
(nuncio.resolver) are pure string functions — no DNS/IP resolution, no
free-text host scraping. A host-less/unit-less alert correlates nothing
rather than guessing. Summary-text regex matching survives ONLY as a
best-effort fallback for legacy rows that predate the host/service store
columns (3-/7-tuple `store.recent()` shapes) — it can gate via
service/unit/dependency but, even on a legacy row, can NEVER gate via host;
it can only ever produce the weak grouping label.

Never raises: a garbage row scores as unrelated; a total failure returns [].

Accepts every row shape store.recent() has produced across versions:
  - legacy 3-tuple: (key, payload, created_at) — scored on token/recency
    signals plus summary-regex service/unit/dependency/host-grouping
    fallbacks only (no fingerprint/category, no column-based matching).
  - legacy 7-tuple: (key, payload, created_at, source, category, severity,
    fingerprint) — adds fingerprint/category; host/service still fall back
    to the summary-regex path.
  - current 9-tuple: (key, payload, created_at, source, category, severity,
    fingerprint, host, service) — the full signal set, column-matched.
"""
import re

from nuncio.fingerprint import fingerprint as _compute_fingerprint
from nuncio.model import canonical_host, real_host
from nuncio.resolver import resolve_unit_strict

_HOST_WEIGHT = 3.0  # rank-only now (grouping label weight), never a gate contributor
_SERVICE_WEIGHT = 2.0
_TOKEN_WEIGHT = 1.0
_MAX_TOKEN_SCORE = 3.0
_RECENCY_WEIGHT = 2.0  # scaled by closeness inside the window
_FINGERPRINT_WEIGHT = 4.0
_UNIT_WEIGHT = 2.5
_CATEGORY_WEIGHT = 1.5
_PATH_WEIGHT = 1.0
_MAX_PATH_SCORE = 2.0
_DEP_WEIGHT = 2.0
_SUMMARY_LEN = 160
_MAX_PATH_TOKENS = 4

_PATH_TOKEN_RE = re.compile(r"(?<!\S)/(?:[\w.\-]+/)+[\w.\-]*")


def _word_re(term):
    return re.compile(r"\b" + re.escape(str(term)) + r"\b", re.I)


def _norm(value):
    """Placeholder-guarded lowercase/strip normalization for direct service
    string equality (a coarser, cheaper comparison than resolve_unit_strict's
    prefix/suffix peeling — used for the "same service" gate key). None for
    a missing/"-"/non-alnum value, same posture as nuncio.model.real_host."""
    v = str(value or "").strip()
    if v and v != "-" and any(c.isalnum() for c in v):
        return v.lower()
    return None


def _unpack(row):
    """Normalize a row to (key, payload, created_at, source, category,
    severity, fingerprint, host, service) — legacy 3-/7-tuples get None for
    the fields they don't carry."""
    if len(row) >= 9:
        return row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]
    if len(row) >= 7:
        return row[0], row[1], row[2], row[3], row[4], row[5], row[6], None, None
    key, payload, created_at = row[0], row[1], row[2]
    return key, payload, created_at, None, None, None, None, None, None


def _age_suffix(created_at, now):
    """`{int(m)}m ago` when the row is under 90 minutes old, else `{h:.1f}h
    ago` -- best-effort, returns "" (omit) on any cast failure so a garbage
    `created_at` never breaks the rendered line."""
    try:
        age_s = max(0.0, float(now) - float(created_at))
    except (TypeError, ValueError):
        return ""
    minutes = age_s / 60.0
    if minutes < 90:
        return f"{int(minutes)}m ago"
    return f"{minutes / 60.0:.1f}h ago"


def rank_correlated(rows, alert, tokens=(), now=0.0, window_s=600, top_n=8, deps=None, host_domains=()):
    """`rows`: store.recent() shape (3-/7-/9-tuple), oldest-first.
    Returns rendered `- summary [reasons]` lines, best-correlated first,
    capped to `top_n` across BOTH tiers (tier 0 causal rows always precede
    tier 1 grouping rows). `deps` is an optional {service: [upstream, ...]}
    map (see nuncio.config's `dependency_hints`). `host_domains` is the
    ordered tuple of DNS suffixes (NUNCIO_HOST_DOMAINS) stripped when
    comparing hosts — see nuncio.model.canonical_host. See the module
    docstring for the full causal-entity-gate model."""
    try:
        a_host = canonical_host(alert.get("host"), host_domains)
        # Legacy-row regex fallback needs the RAW (pre-canonicalization) real
        # host text, since a legacy row's summary line carries the native
        # hostname string, not a canonicalized form.
        a_host_raw = real_host(alert.get("host"))
        host_re = _word_re(a_host_raw) if a_host_raw else None
        service = alert.get("service") or ""
        a_service = _norm(service)
        # Gate on the placeholder-guarded a_service, not the raw service
        # text -- a raw "-" (CheckMK HOST-level notifications) builds a bare
        # `\b-\b` regex that matches the literal hyphen in unrelated
        # hostnames/summaries ("db-primary", "TEST-NUNCIO", ...). host_re
        # and unit_re already gate on their guarded values (real_host(),
        # resolve_unit_strict()); this mirrors that posture for service.
        service_re = _word_re(service) if a_service else None
        token_res = [(str(t), _word_re(t)) for t in (tokens or []) if t]
        alert_fp = _compute_fingerprint(alert)
        a_unit = resolve_unit_strict(alert)
        unit_re = _word_re(a_unit) if a_unit else None
        alert_category = alert.get("category")
        path_tokens = _PATH_TOKEN_RE.findall(str(alert.get("output") or ""))[:_MAX_PATH_TOKENS]
        upstreams = []
        if deps and service:
            up = deps.get(service)
            if up:
                upstreams = [str(u) for u in up if u]

        entries = []
        for idx, row in enumerate(rows or []):
            try:
                (key, payload, created_at, r_source, r_category, r_severity,
                 r_fp, r_host, r_service) = _unpack(row)
                summary = str(payload).splitlines()[0][:_SUMMARY_LEN]

                r_service_norm = _norm(r_service) if r_service is not None else None
                r_unit = resolve_unit_strict({"service": r_service}) if r_service is not None else None
                r_host_c = canonical_host(r_host, host_domains) if r_host is not None else None

                fingerprint_hit = bool(alert_fp and r_fp and r_fp == alert_fp)

                if r_service is not None:
                    service_hit = bool(a_service and r_service_norm == a_service)
                else:  # legacy fallback -- compat only, never a gate for host
                    service_hit = bool(service_re and service_re.search(summary))

                if r_service is not None:
                    unit_hit = bool(a_unit and r_unit and r_unit == a_unit)
                else:
                    unit_hit = bool(unit_re and unit_re.search(summary))

                dep_hit = False
                if upstreams:
                    if r_service is not None:
                        dep_hit = any(
                            (r_service_norm is not None and r_service_norm == _norm(u))
                            or (r_unit is not None and r_unit == resolve_unit_strict({"service": u}))
                            for u in upstreams
                        )
                    else:  # legacy fallback
                        dep_hit = any(_word_re(u).search(summary) for u in upstreams)

                if r_host is not None:
                    host_grouped = bool(a_host and r_host_c == a_host)
                else:  # legacy fallback -- grouping ONLY, never a gate
                    host_grouped = bool(a_host and host_re and host_re.search(summary))

                gated = fingerprint_hit or service_hit or unit_hit or dep_hit

                score, reasons = 0.0, []
                if fingerprint_hit:
                    score += _FINGERPRINT_WEIGHT
                    reasons.append("same recurring signature")
                if service_hit:
                    score += _SERVICE_WEIGHT
                    reasons.append("same service")
                if unit_hit and not service_hit:
                    score += _UNIT_WEIGHT
                    reasons.append("same unit")
                if dep_hit:
                    score += _DEP_WEIGHT
                    reasons.append(f"upstream dependency of {service}")

                if gated:
                    tier = 0
                    shared = [t for t, tr in token_res if tr.search(summary)]
                    if shared:
                        score += min(_TOKEN_WEIGHT * len(shared), _MAX_TOKEN_SCORE)
                        reasons.append("similar error: " + ", ".join(shared[:3]))
                    if alert_category and r_category and r_category == alert_category:
                        score += _CATEGORY_WEIGHT
                        reasons.append(f"same category ({alert_category})")
                    path_score = 0.0
                    for p in path_tokens:
                        if p in summary:
                            path_score += _PATH_WEIGHT
                            reasons.append(f"shared path: {p}")
                            if path_score >= _MAX_PATH_SCORE:
                                break
                    score += min(path_score, _MAX_PATH_SCORE)
                    if host_grouped:
                        score += _HOST_WEIGHT
                        reasons.append(f"also active on {a_host}")
                elif host_grouped:
                    tier = 1
                    reasons = [f"also active on {a_host}"]
                else:
                    continue  # neither gated nor host-grouped -- excluded

                try:
                    age = max(0.0, float(now) - float(created_at))
                    score += _RECENCY_WEIGHT * max(0.0, 1.0 - age / float(window_s))
                except (TypeError, ValueError):
                    pass

                annot = "; ".join(reasons)  # every surviving row has >=1 reason
                age_suffix = _age_suffix(created_at, now)
                line = f"- {summary} [{annot}]"
                if age_suffix:
                    line += f"; {age_suffix}"
                # tie-break within a tier: newer row (higher idx) first — deterministic
                entries.append((tier, -score, -idx, gated, created_at, line))
            except Exception:
                continue  # one garbage row never poisons the rest
        entries.sort(key=lambda t: t[:3])

        # Cap across BOTH tiers -- tier 0 sorts first (tier is the primary
        # sort key), so tier 1 rows only appear once every tier-0 row fits.
        top = entries[:top_n]

        # Causal hint: TEMPORAL only, hedged with "possible" -- among the
        # capped rows that are GATED (tier 0; tier-1 grouping rows are
        # structurally unreachable here), the earliest created_at gets
        # "possible root", later gated rows get "possible symptom".
        gated_idxs = [i for i, t in enumerate(top) if t[3]]

        def _sort_key(i):
            ca = top[i][4]
            try:
                return float(ca)
            except (TypeError, ValueError):
                return float("inf")

        if len(gated_idxs) >= 2:
            gated_idxs.sort(key=_sort_key)
            earliest = gated_idxs[0]
            top[earliest] = (*top[earliest][:5], top[earliest][5] + "; possible root (earliest)")
            for i in gated_idxs[1:]:
                top[i] = (*top[i][:5], top[i][5] + "; possible symptom (later)")

        return [line for *_rest, line in top]
    except Exception:
        return []
