"""Token-Jaccard near-duplicate similarity (C1).

Same meaning, different wording ("disk full" vs "storage exhausted" never
share a fingerprint) is invisible to the deterministic causal gate. This
module scores it cheaply (no dependencies, no embeddings): Jaccard overlap
over 3+-char lowercase alphanumeric tokens minus a small stop set.

Known limits (documented, not fixed here): synonym-blind ("disk full" vs
"storage exhausted" scores ~0) and order-insensitive ("A triggers B" vs
"B triggers A" score identically). The upgrade path is a hashing-embedding
cosine gated behind the operational distribution below -- ship Jaccard
first, watch the metric, upgrade on evidence.

The score is RANK-ONLY inside nuncio.correlate's already-gated rows: it
can never admit an unrelated row, only re-order related ones. A
strong-label conflict (both sides carry a service/unit and they differ)
vetoes even the bonus -- see correlate._services_conflict.

Operational telemetry: every scored pair is recorded into a bounded
in-memory window (plus a lifetime counter) surfaced on /metrics, so the
operator can see the similarity distribution and decide whether the
embedding upgrade is worth it.
"""
import re
import threading
from collections import deque

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_STOP = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "than", "then",
    "are", "was", "were", "has", "have", "had", "will", "would", "its",
    "our", "your", "you", "not", "but", "all", "any", "can", "had",
    "alert", "alerts", "firing", "resolved",
})

# Below this similarity, no bonus (indistinguishable from chance overlap on
# short operational strings). At/above it the bonus ramps to the cap.
SIM_THRESHOLD = 0.3
SIM_MAX_SCORE = 1.5
# Bounded operational window for the /metrics distribution (+ lifetime total
# alongside, since the window alone can't show volume).
_WINDOW_MAX = 512

_window = deque(maxlen=_WINDOW_MAX)
_total = 0
_lock = threading.Lock()


def tokenize(text):
    """Lowercase alphanumeric 3+-char token set minus stopwords. Pure, never
    raises (garbage in -> empty set out). Input is length-capped so a huge
    alert output can't make one comparison expensive."""
    try:
        words = _TOKEN_RE.findall(str(text or "")[:8000].lower())
    except Exception:
        return frozenset()
    return frozenset(w for w in words if w not in _STOP)


def jaccard(a, b):
    """Set overlap in [0, 1]. Empty either side -> 0.0 (no signal, not
    "identical")."""
    try:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)
    except Exception:
        return 0.0


def record(value):
    """Add one scored pair to the operational window. Never raises."""
    global _total
    try:
        with _lock:
            _window.append(float(value))
            _total += 1
    except Exception:
        pass


def similarity(text_a, text_b):
    """Jaccard similarity of two texts + records the pair for telemetry.
    The single entry point correlate.py uses (so every scored pair is
    observed exactly once)."""
    score = jaccard(tokenize(text_a), tokenize(text_b))
    record(score)
    return score


def bonus_for(similarity_score):
    """Rank bonus in [0, SIM_MAX_SCORE], 0 below threshold. Linear ramp so
    a bare-threshold match contributes less than a near-identical one."""
    try:
        if similarity_score < SIM_THRESHOLD:
            return 0.0
        return min(SIM_MAX_SCORE, similarity_score * 3.0)
    except Exception:
        return 0.0


def distribution():
    """{"total", "n", "p50", "p90", "max"} over the window. Never raises;
    empty window -> zeros (the metrics renderer omits... no -- emits zeros,
    which correctly reads as "no pairs scored yet")."""
    try:
        with _lock:
            ordered = sorted(_window)
            total = _total
        if not ordered:
            return {"total": total, "n": 0, "p50": 0.0, "p90": 0.0, "max": 0.0}

        def _pct(p):
            idx = min(len(ordered) - 1, int(p * len(ordered)))
            return ordered[idx]

        return {
            "total": total,
            "n": len(ordered),
            "p50": _pct(0.50),
            "p90": _pct(0.90),
            "max": ordered[-1],
        }
    except Exception:
        return {"total": 0, "n": 0, "p50": 0.0, "p90": 0.0, "max": 0.0}
