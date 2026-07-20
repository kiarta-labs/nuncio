"""The delivery envelope — a rendering-agnostic bundle of everything a
delivery adapter might want to show (title, terse body, full detail, an
optional HTML rendering) built ONCE per alert and handed to every configured
channel. Channels then pick brief vs. full framing (see
`nuncio/delivery/__init__.py`'s `Dispatch`).

Pure module: only `dataclasses`, `html`, `re`. Every public function is
wrapped so degenerate/garbage input degrades to a safe default rather than
raising -- a formatting bug here must never be able to strand an alert.
"""
import re
from dataclasses import dataclass
from html import escape as _html_escape

# severity -> ntfy's 1(min)-5(max) priority header. Canonical home for this
# table; nuncio/delivery/ntfy.py imports it under its old local name so that
# module's diff stays a one-liner.
SEVERITY_PRIORITY = {"critical": "5", "warning": "4", "info": "3", "ok": "2", "unknown": "3"}

# severity -> colored emoji token. Emoji are used (rather than text labels)
# because they render in color in push notifications (iOS/Bark) where plain
# text cannot be colored; this is the ONE definition other modules import
# from (e.g. nuncio/sources/checkmk.py's raw_text) so the mapping never drifts.
_SEV_LABEL = {"critical": "❗", "warning": "🟡", "info": "🔵", "ok": "✅", "unknown": "❔"}


def severity_symbol(severity) -> str:
    """Map a severity string to its colored-emoji token. Unknown/garbage
    severities default to the "unknown" token, same fallback as build_headline."""
    try:
        return _SEV_LABEL.get(severity, _SEV_LABEL["unknown"])
    except Exception:
        return _SEV_LABEL["unknown"]

_SOFT_CAP = 70
_HARD_CAP = 120
_ENTITY_CAP = 32

_ORDINAL_SUFFIX = {1: "st", 2: "nd", 3: "rd"}


def _ordinal(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if 10 <= (n % 100) <= 20:
        suffix = "th"
    else:
        suffix = _ORDINAL_SUFFIX.get(n % 10, "th")
    return f"{n}{suffix}"


def severity_to_notify_type(severity) -> str:
    """Map a severity string to ntfy's 1-5 priority string. Unknown/garbage
    severities default to "3" (the same default as SEVERITY_PRIORITY.get)."""
    try:
        return SEVERITY_PRIORITY.get(severity, "3")
    except Exception:
        return "3"


@dataclass(frozen=True)
class Envelope:
    severity: str
    host: str
    service: str
    headline: str
    summary: str
    detail: str
    detail_html: "str | None" = None
    notify_type: str = "3"
    marker: bool = False


def _truncate(s, limit):
    if len(s) <= limit:
        return s
    cut = s.rfind(" ", 0, limit)
    if cut <= 0:
        cut = limit
    return s[:cut].rstrip() + "…"


# Split on the FIRST of ".", "—", ";" -- but a "." must be followed by
# whitespace/EOL (or preceded+followed by non-digits handled implicitly,
# since a bare "10.0.0.2" or "web.service" has no space after the dot) to
# avoid splitting inside an IP address or a dotted service name.
_CLAUSE_SPLIT = re.compile(r"(\.(?=\s|$))|(—)|(;)")


def _first_clause(text):
    m = _CLAUSE_SPLIT.search(text)
    if not m:
        return text.strip()
    return text[: m.start()].strip()


def build_headline(severity, host, service, summary_line, raw_first_line=None,
                    recurrence_count=0, window_label="") -> str:
    """Build a terse, deterministic one-line headline for an alert."""
    try:
        sev = _SEV_LABEL.get(severity, _SEV_LABEL["unknown"])

        host = (host or "").strip()
        service = (service or "").strip()
        if host and service:
            entity = f"{host}/{service}"
        elif host:
            entity = host
        elif service:
            entity = service
        else:
            entity = ""
        if len(entity) > _ENTITY_CAP:
            entity = entity[:_ENTITY_CAP] + "…"

        crux_source = summary_line if summary_line and summary_line.strip() else (raw_first_line or "")
        crux_source = crux_source.strip()
        # RAW_FALLBACK_MARKER may be imported lazily to avoid a circular
        # import at module load time (render.py doesn't import envelope.py
        # at import time in a way that would cycle, but this keeps the
        # dependency one-directional and explicit).
        marker = "[enrichment unavailable]"
        if crux_source.startswith(marker):
            crux_source = crux_source[len(marker):].strip()
        crux = _first_clause(crux_source) or "alert"
        crux = _truncate(crux, _SOFT_CAP)
        if len(crux) > _HARD_CAP:
            crux = crux[:_HARD_CAP - 1].rstrip() + "…"

        if entity:
            headline = f"{sev} {entity} — {crux}"
        else:
            headline = f"{sev} — {crux}"

        if recurrence_count and recurrence_count > 1:
            headline += f" ({_ordinal(recurrence_count)} in {window_label})"
        return headline
    except Exception:
        return "❔ alert"


# Evidence-section labels + fixed rendering order, shared by build_detail_html
# and build_envelope's plain-text appendix.
_EVIDENCE_LABELS = [
    ("recent_logs", "Log excerpt"),
    ("metrics", "Metrics"),
    ("container_state", "Container state"),
    ("kernel", "Kernel/journal"),
    ("correlated", "Correlated"),
    ("history", "Alert history"),
    ("recurrence", "Recurrence"),
]

_RAW_ALERT_MARK = "--- Raw alert:"
# The plain-text evidence appendix marker (see nuncio.render.build_envelope) --
# _raw_text stops here so the HTML raw-alert <pre> never doubles up with the
# plain-text appendix when both are present in the same `detail` string.
_EVIDENCE_MARK = "--- Evidence:"


def _findings_text(detail):
    """The enrichment portion of `detail` -- everything before the raw-alert
    embed marker (see nuncio.render.build_envelope, which always appends
    `--- Raw alert:\\n<red_raw>`)."""
    idx = detail.find(_RAW_ALERT_MARK)
    return detail[:idx].rstrip() if idx != -1 else detail.rstrip()


def _raw_text(detail):
    idx = detail.find(_RAW_ALERT_MARK)
    if idx == -1:
        return ""
    tail = detail[idx + len(_RAW_ALERT_MARK):]
    ev_idx = tail.find(_EVIDENCE_MARK)
    if ev_idx != -1:
        tail = tail[:ev_idx]
    return tail.strip()


def build_detail_html(envelope, sections_red=None, cap_bytes=32000) -> str:
    """Full HTML rendering: an escaped findings paragraph (the enrichment
    text, first line bolded), then labeled EVIDENCE blocks in a fixed order
    (each `<h4>label</h4><pre>escaped section</pre>`), then the raw alert in
    its own escaped `<pre>`. Every section is `html.escape`d -- untrusted log
    lines are an injection vector. Truncates to `cap_bytes`,
    least-important-first (nuncio.bundle._TRUNCATE_ORDER), never dropping the
    findings paragraph or the raw-alert embed. Falls back to a minimal
    headline+detail rendering (Batch A shape) when `sections_red` isn't
    given, or on ANY internal failure -- never raises, never strands the
    alert."""
    try:
        headline = getattr(envelope, "headline", "") or ""
        detail = getattr(envelope, "detail", "") or ""
        if not sections_red:
            html = f"<p><strong>{_html_escape(headline)}</strong></p><pre>{_html_escape(detail)}</pre>"
            if cap_bytes and len(html.encode("utf-8", errors="ignore")) > cap_bytes:
                html = html.encode("utf-8", errors="ignore")[:cap_bytes].decode("utf-8", errors="ignore")
            return html

        findings = _findings_text(detail)
        findings_lines = [ln for ln in findings.splitlines() if ln.strip()]
        if findings_lines:
            first, rest = findings_lines[0], findings_lines[1:]
            findings_html = f"<p><strong>{_html_escape(first)}</strong>"
            if rest:
                findings_html += "<br>" + "<br>".join(_html_escape(ln) for ln in rest)
            findings_html += "</p>"
        else:
            findings_html = f"<p><strong>{_html_escape(headline)}</strong></p>"

        raw = _raw_text(detail)
        raw_html = f"<h4>Raw alert</h4><pre>{_html_escape(raw)}</pre>"

        # from nuncio.bundle import here (not at module top) -- avoids a
        # potential import cycle since bundle.py has no reason to know about
        # envelope.py, but keeping the dependency one-directional/explicit.
        from nuncio.bundle import _TRUNCATE_ORDER

        blocks = {}
        for name, label in _EVIDENCE_LABELS:
            text = sections_red.get(name)
            if text:
                blocks[name] = f"<h4>{_html_escape(label)}</h4><pre>{_html_escape(text)}</pre>"

        def render():
            parts = [findings_html]
            for name, _label in _EVIDENCE_LABELS:
                if name in blocks:
                    parts.append(blocks[name])
            parts.append(raw_html)
            return "".join(parts)

        html = render()
        if cap_bytes:
            for name in _TRUNCATE_ORDER:
                if len(html.encode("utf-8", errors="ignore")) <= cap_bytes:
                    break
                if name in blocks:
                    del blocks[name]
                    html = render()
            # findings + raw are never dropped; if still over cap, hard-cut
            # bytes (last resort -- keeps the fail-safe "never raise" spirit).
            encoded = html.encode("utf-8", errors="ignore")
            if len(encoded) > cap_bytes:
                html = encoded[:cap_bytes].decode("utf-8", errors="ignore")
        return html
    except Exception:
        return ""
