"""Learned co-occurrence edges (C3) -- rank-only topology hints.

Static `dependency_hints` (operator-authored, highest authority) rot: nobody
updates them when the fleet changes. This module learns a second edge set
from the alert history itself: services that repeatedly fire on the SAME
calendar days are probably related (shared dependency, shared host fate,
common upstream) -- worth ranking higher, never worth gating on.

Why rank-only (never a gate key): co-occurrence is not causation. A weekly
backup window, a Watchtower wave, or a fleet-wide outage makes unrelated
services co-fire. The deterministic gate (fingerprint/service/unit/declared
dependency -- see nuncio.correlate's ratified model) keeps sole admission
authority; learned edges only re-order already-admitted rows, so a bogus
edge can mis-rank but never admit, suppress, or fabricate a causal chain.

Anti-mesh guards (each targets one observed false-edge class):
- warning/critical severities ONLY -- info/ok floods (weekly updater waves,
  resolve storms) never enter the learner;
- same-day presence counts once per service per day (a flap-repeat storm
  within one day is one vote, not fifty);
- an edge needs >= LEARN_MIN_DAYS distinct co-fire days inside the lookback
  (a single fleet-wide outage day can never form an edge alone);
- 30-day TTL on the input (stale edges age out as the fleet evolves);
- cap of LEARN_MAX_EDGES_PER_SERVICE partners per service (keeps one
  hyperactive service from meshing the whole fleet).

Recompute is hourly-cached per gatherer lifetime (see nuncio.config's
closure): one bounded store query per hour, never per alert.
"""
import time

_LEARN_WINDOW_S = 30 * 86400
_LEARN_MIN_DAYS = 3
_LEARN_TTL_S = 3600
_LEARN_QUERY_LIMIT = 20000
_LEARN_MAX_EDGES_PER_SERVICE = 5
_LEARN_SEVERITIES = ("warning", "critical")
_LEARNED_WEIGHT = 1.0


def _norm_service(value):
    """Placeholder-guarded lowercase service identity -- mirrors
    correlate._norm's posture (None for missing/"-"/non-alnum) without
    importing the correlate module (this module must stay importable from
    anywhere; correlate already imports semantic, not vice versa)."""
    try:
        v = str(value or "").strip()
    except Exception:
        return None
    if v and v != "-" and any(c.isalnum() for c in v):
        return v.lower()
    return None


def learn_edges(store, state, now=None, window_s=_LEARN_WINDOW_S,
                min_days=_LEARN_MIN_DAYS, ttl_s=_LEARN_TTL_S,
                limit=_LEARN_QUERY_LIMIT):
    """{service: [co-firing services, best first]} from the store. `state`
    is a caller-owned {"at": float, "edges": dict} cache (per-gatherer
    lifetime in production); recomputes at most once per `ttl_s`. Never
    raises -- any failure (store hiccup, shape drift) returns {} (no
    learned signal) rather than breaking correlation."""
    try:
        now = float(now) if now is not None else time.time()
        if not isinstance(state, dict):
            state = {}
        if now - float(state.get("at", 0.0)) < ttl_s and isinstance(state.get("edges"), dict):
            return state["edges"]
        rows = store.service_day_rows(since=now - window_s, limit=limit) or []
        days = {}
        for row in rows:
            try:
                service, severity, created_at, fp = row[0], row[1], row[2], row[3]
            except (TypeError, ValueError, IndexError):
                continue
            s = _norm_service(service)
            if not s or severity not in _LEARN_SEVERITIES:
                continue
            try:
                day = int(float(created_at) // 86400)
            except (TypeError, ValueError):
                continue
            days.setdefault(s, {}).setdefault(day, set()).add(fp if fp else (s, day))
        services = sorted(days)
        pairs = {}
        for i, a in enumerate(services):
            for b in services[i + 1:]:
                common = set(days[a]) & set(days[b])
                if len(common) >= min_days:
                    pairs.setdefault(a, []).append((b, len(common)))
                    pairs.setdefault(b, []).append((a, len(common)))
        out = {}
        for s, lst in pairs.items():
            lst.sort(key=lambda t: (-t[1], t[0]))
            out[s] = [name for name, _n in lst[:_LEARN_MAX_EDGES_PER_SERVICE]]
        state["at"] = now
        state["edges"] = out
        return out
    except Exception:
        return {}
