"""Alert fingerprinting — pure, deterministic, no I/O.

`fingerprint()` derives a stable identity for "this same kind of alert keeps
happening" so the engine can ANNOTATE an alert's headline with its recurrence
("3rd in 2h") and a collector can surface the recurrence history as extra
context for the LLM.

This is annotation only, never suppression. Nuncio's never-lose invariant means
every alert that arrives is enriched and delivered — recurrence is a signal
folded INTO that one message, not a reason to drop, merge, or delay it.
De-duplicating noisy alerts (e.g. collapsing a flood of near-identical pages
into one) is the monitoring source's job (CheckMK/Alertmanager grouping,
Grafana notification policies, etc.), not Nuncio's.

`signature()`/`fingerprint()` never raise: on any error `signature()` degrades
to `""` and `fingerprint()` degrades to `None`.
"""
import hashlib
import re

_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b", re.I)
_RFC_TS_RE = re.compile(
    r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+"
    r"\d{2}:\d{2}:\d{2}(?:\s+\S+)?\b", re.I)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
# Optional "0x" prefix so hex literals like 0xdeadbeef collapse too (the "x"
# breaks \b's word-boundary logic since it's itself a word character).
_HEX_RUN_RE = re.compile(r"\b0x[0-9a-f]{6,}\b|\b[0-9a-f]{6,}\b", re.I)
_DIGIT_RUN_RE = re.compile(r"\d+")
_WS_RE = re.compile(r"\s+")

_MAX_LEN = 200


def signature(alert) -> str:
    """A normalized, near-invariant signature of an alert's shape: strips
    timestamps/UUIDs/hex/digit runs so two occurrences of "the same kind of
    alert" (different address, different timestamp) collapse to the same
    string. Never raises — degrades to "" on any error."""
    try:
        alert = alert or {}
        text = f"{alert.get('output', '') or ''} {alert.get('state', '') or ''}"
        text = text.lower()
        text = _ISO_TS_RE.sub("<ts>", text)
        text = _RFC_TS_RE.sub("<ts>", text)
        text = _UUID_RE.sub("<uuid>", text)
        text = _HEX_RUN_RE.sub("<hex>", text)
        text = _DIGIT_RUN_RE.sub("<n>", text)
        text = _WS_RE.sub(" ", text).strip()
        return text[:_MAX_LEN]
    except Exception:
        return ""


def fingerprint(alert) -> "str | None":
    """A short, stable identity for `alert`'s recurring signature: sha1 of
    `source|host|signature`, truncated to 16 hex chars. None when the alert
    has no usable signature (nothing to fingerprint)."""
    try:
        alert = alert or {}
        sig = signature(alert)
        if not sig:
            return None
        basis = f"{alert.get('source', '') or ''}|{alert.get('host', '') or ''}|{sig}"
        return hashlib.sha1(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]
    except Exception:
        return None
