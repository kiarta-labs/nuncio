"""Context-bundle assembly with a hard total cap.

Fixed section order (cache-friendly prompts, reviewable diffs). When the bundle
exceeds the cap, sections are truncated/dropped in least-important-first order
(logs, kernel, state, metrics) so the cross-alert correlation section — the whole
point of Level B — survives.
"""

# Order the sections appear in the bundle. 'history' (Phase B, full depth
# only -- the wider 24h store-only lookback, see nuncio.collectors.collect_history)
# sits right after 'correlated', the section it complements.
_ORDER = ["container_state", "recent_logs", "metrics", "kernel", "correlated", "history", "recurrence"]
# Order to truncate when over the cap (least important first). 'recurrence' is
# LAST: it's a single line, so it survives even the tightest cap. 'history'
# drops before 'correlated' (the fresher, narrower-window section) -- the
# wider historical lookback is the first thing to go under pressure.
_TRUNCATE_ORDER = ["recent_logs", "kernel", "container_state", "metrics", "history", "correlated", "recurrence"]
# Log-shaped sections are newest-LAST -> cut the OLD head, keep the recent tail.
_HEAD_CUT = {"recent_logs", "kernel", "container_state"}


def _shrink(name, text, target_len):
    """Shrink `text` to ~`target_len`, keeping its header line and — for log-shaped
    sections — the NEWEST (tail) content."""
    if name in _HEAD_CUT:
        header, _, body = text.partition("\n")
        marker = "\n…[older lines truncated]\n"
        budget = target_len - len(header) - len(marker)
        if budget <= 0:
            return header[:max(0, target_len)]
        return header + marker + body[-budget:]
    marker = "\n…[truncated]"
    return text[: max(0, target_len - len(marker))] + marker


def assemble_bundle(sections, max_bytes=16000):
    """`sections`: dict of {name: text}. Returns the assembled (capped) bundle."""
    parts = {n: sections[n] for n in _ORDER if sections.get(n)}

    def render():
        return "\n\n".join(parts[n] for n in _ORDER if n in parts)

    for name in _TRUNCATE_ORDER:
        body = render()
        if len(body) <= max_bytes:
            break
        if name not in parts:
            continue
        excess = len(body) - max_bytes
        if len(parts[name]) > excess + 30:
            parts[name] = _shrink(name, parts[name], len(parts[name]) - excess)
        else:
            del parts[name]  # dropping this whole section still isn't enough; drop it

    return render()
