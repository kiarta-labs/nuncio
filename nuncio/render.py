"""Final delivery-message rendering — builds the `Envelope` that
`nuncio/delivery/__init__.py`'s `Dispatch` renders per-channel.

The raw alert is ALWAYS embedded verbatim in an enriched message's detail;
the fallback ALWAYS carries the [enrichment unavailable] marker. These
markers are part of the fail-safe invariant, not cosmetics.
"""
from nuncio.envelope import (
    Envelope, _EVIDENCE_LABELS, build_detail_html, build_headline, severity_to_notify_type,
)

RAW_FALLBACK_MARKER = "[enrichment unavailable]"

_EVIDENCE_APPENDIX_LINES = 12
_EVIDENCE_APPENDIX_MAX_BYTES = 8000


def _first_line(text):
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _evidence_appendix(sections_red, evidence_max_bytes):
    """Plain-text evidence appendix for brief-unaware full-detail channels
    (slack/stdout/webhook full mode) that don't render `detail_html`: a
    `--- Evidence:` block with `[Label]` + the first 12 lines of each
    section, same order/labels as `build_detail_html`, capped at
    `min(evidence_max_bytes // 4, 8000)` bytes -- deliberately much smaller
    than the HTML cap since this is a supplementary appendix, not the
    primary evidence surface."""
    if not sections_red:
        return ""
    parts = []
    for name, label in _EVIDENCE_LABELS:
        text = sections_red.get(name)
        if not text:
            continue
        lines = [ln for ln in str(text).splitlines() if ln.strip()][:_EVIDENCE_APPENDIX_LINES]
        if not lines:
            continue
        parts.append(f"[{label}]\n" + "\n".join(lines))
    if not parts:
        return ""
    appendix = "\n\n--- Evidence:\n" + "\n\n".join(parts)
    limit = max(0, min(int(evidence_max_bytes or 0) // 4, _EVIDENCE_APPENDIX_MAX_BYTES)) \
        if evidence_max_bytes else _EVIDENCE_APPENDIX_MAX_BYTES
    encoded = appendix.encode("utf-8", errors="ignore")
    if len(encoded) > limit:
        appendix = encoded[:limit].decode("utf-8", errors="ignore")
    return appendix


def build_envelope(enrichment_text, red_raw, severity="unknown", host="", service="",
                    marker=False, detail_html=None, recurrence_count=0, window_label="",
                    sections_red=None, evidence_max_bytes=32000) -> Envelope:
    """Build the one Envelope delivered for an alert.

    `enrichment_text` is the (already knowledge-garnished, if applicable)
    private-plane result; `red_raw` is the already-redacted raw alert text,
    embedded verbatim so nothing is lost even if enrichment misleads.
    `sections_red`, when given, feeds BOTH `build_detail_html`'s structured
    evidence blocks AND a plain-text `--- Evidence:` appendix on `detail`
    itself (for full-verbosity channels that render plain text only, e.g.
    slack/stdout/webhook) -- brief renders never read `detail`/`detail_html`
    (already structural, see nuncio/delivery/__init__.py's Dispatch), so this
    never affects a brief channel.
    """
    enrichment_text = enrichment_text or ""
    summary = _first_line(enrichment_text)
    prefix = (RAW_FALLBACK_MARKER + "\n") if marker else ""
    detail = f"{prefix}{enrichment_text.rstrip()}\n\n--- Raw alert:\n{red_raw}"
    detail += _evidence_appendix(sections_red, evidence_max_bytes)
    headline = build_headline(
        severity, host, service, summary,
        recurrence_count=recurrence_count, window_label=window_label,
    )
    envelope = Envelope(
        severity=severity, host=host or "", service=service or "",
        headline=headline, summary=summary, detail=detail,
        detail_html=None, notify_type=severity_to_notify_type(severity), marker=marker,
    )
    if detail_html is None:
        try:
            detail_html = build_detail_html(envelope, sections_red=sections_red,
                                             cap_bytes=evidence_max_bytes)
        except Exception:
            detail_html = None
    return Envelope(
        severity=envelope.severity, host=envelope.host, service=envelope.service,
        headline=envelope.headline, summary=envelope.summary, detail=envelope.detail,
        detail_html=detail_html, notify_type=envelope.notify_type, marker=envelope.marker,
    )
