"""Log relevance ranking — pure, deterministic, no I/O.

Instead of blindly keeping the last N log lines, group lines into BLOCKS
(a traceback/stack-dump and its continuation lines stay together; every other
line is its own singleton block), score each block by relevance to the alert
(error-token overlap, service/host mention, severity words, recency, plus a
small bonus for a real multi-line block), and keep the highest-scoring blocks
within the line/byte budget — a block is included WHOLE or not at all (except
the single best block, when nothing else fit, which is included head+tail
within budget so at least something relevant survives). Output is re-sorted
back to chronological order.

Adjacent identical lines (after rstrip) are collapsed to one + a "… (×N)"
marker before scoring, so a repeated line doesn't crowd out everything else.

Degrades gracefully: any internal failure falls back to a plain tail (the old
behavior), never raises.
"""
import re

_SEVERITY_WEIGHTS = (
    (re.compile(r"\b(fatal|crit(?:ical)?|panic|emerg(?:ency)?)\b", re.I), 3),
    (re.compile(r"\b(error|err|fail(?:ed|ure)?|exception|traceback)\b", re.I), 2),
    (re.compile(r"\b(warn(?:ing)?)\b", re.I), 1),
)

_TOKEN_WEIGHT = 3
_ENTITY_WEIGHT = 1
_BLOCK_BONUS = 1

# A traceback/stack-dump opener...
_TRACE_START = re.compile(r"^(Traceback \(most recent call last\)|panic:|goroutine \d|fatal error:)")
# ...and its continuation lines: indented, "at ...", "...", "Caused by", 'File "'.
_CONT = re.compile(r'^(\s+|at\s|\.{3}|Caused by|File ")')


def _score_line(line, token_res, entity_res):
    score = 0
    for tr in token_res:
        if tr.search(line):
            score += _TOKEN_WEIGHT
    for sev_re, w in _SEVERITY_WEIGHTS:
        if sev_re.search(line):
            score += w
            break  # highest severity tier only
    for er in entity_res:
        if er.search(line):
            score += _ENTITY_WEIGHT
    return score


def extract_blocks(lines):
    """Group `lines` into blocks: a `_TRACE_START` line opens a block that
    swallows subsequent `_CONT` lines (indent / "at " / "..." / "Caused by" /
    'File "'); everything else is a singleton block. Order-preserving."""
    lines = list(lines or [])
    blocks = []
    i, n = 0, len(lines)
    while i < n:
        line = str(lines[i])
        if _TRACE_START.match(line):
            block = [line]
            j = i + 1
            while j < n and _CONT.match(str(lines[j])):
                block.append(str(lines[j]))
                j += 1
            blocks.append(block)
            i = j
        else:
            blocks.append([line])
            i += 1
    return blocks


def _collapse_adjacent(lines):
    """Collapse RUNS of adjacent identical (post-rstrip) lines to one
    original line + a "… (×N)" marker (N = total run length)."""
    lines = list(lines or [])
    out = []
    i, n = 0, len(lines)
    while i < n:
        key = str(lines[i]).rstrip()
        j = i + 1
        while j < n and str(lines[j]).rstrip() == key:
            j += 1
        run = j - i
        out.append(lines[i])
        if run > 1:
            out.append(f"… (×{run})")
        i = j
    return out


def _cost(block):
    return sum(len(str(l)) + 1 for l in block)


def _fit_head_tail(block, max_lines, max_bytes):
    """Best-effort head+tail slice of a single (too-large) block within
    budget -- used only when it's the single best block and nothing else was
    picked, so at least a taste of it survives."""
    if max_lines <= 0 or max_bytes <= 0:
        return []
    if len(block) <= max_lines and _cost(block) <= max_bytes:
        return list(block)
    half = max(1, max_lines // 2)
    head = list(block[:half])
    tail = list(block[-half:]) if half < len(block) else []
    combined = head + tail
    while combined and _cost(combined) > max_bytes:
        if tail:
            tail = tail[:-1]
        elif head:
            head = head[:-1]
        else:
            break
        combined = head + tail
    return combined


def rank_log_lines(lines, tokens=(), service=None, host=None,
                   max_lines=100, max_bytes=8000):
    """Return the most alert-relevant `lines` within budget, chronological.

    `lines` are newest-LAST (as produced by the log store). Ties are broken by
    recency (a later block wins), so zero-signal input degrades to a plain
    tail. Budget is consumed by whole BLOCKS (a traceback stays together);
    a block that doesn't fit is skipped, except the single best block when
    nothing has been picked yet, which is included head+tail within budget.
    """
    lines = list(lines or [])
    if not lines:
        return []
    try:
        token_res = [re.compile(r"\b" + re.escape(str(t)) + r"\b", re.I)
                     for t in (tokens or []) if t]
        entity_res = [re.compile(r"\b" + re.escape(str(e)) + r"\b", re.I)
                      for e in (service, host) if e]

        collapsed = _collapse_adjacent(lines)
        blocks = extract_blocks(collapsed)

        scored = []
        for bi, block in enumerate(blocks):
            line_scores = [_score_line(str(l), token_res, entity_res) for l in block]
            score = max(line_scores) if line_scores else 0
            if len(block) > 1:
                score += _BLOCK_BONUS
            scored.append((score, bi, block))
        # best first; ties -> newest (highest block index) first
        scored.sort(key=lambda t: (-t[0], -t[1]))

        picked = []  # [(bi, block_lines)]
        used_lines = used_bytes = 0
        tried_best_partial = False
        for score, bi, block in scored:
            bl_lines, bl_bytes = len(block), _cost(block)
            if used_lines + bl_lines <= max_lines and used_bytes + bl_bytes <= max_bytes:
                picked.append((bi, block))
                used_lines += bl_lines
                used_bytes += bl_bytes
            elif not picked and not tried_best_partial:
                # the single best block doesn't fit whole and nothing has
                # been picked yet -> take a head+tail slice within budget.
                partial = _fit_head_tail(block, max_lines - used_lines, max_bytes - used_bytes)
                tried_best_partial = True
                if partial:
                    picked.append((bi, partial))
                    used_lines += len(partial)
                    used_bytes += _cost(partial)
            if used_lines >= max_lines or used_bytes >= max_bytes:
                break

        picked.sort(key=lambda t: t[0])  # back to chronological order
        out = []
        for _bi, block in picked:
            out.extend(block)
        return out
    except Exception:
        # degrade to the old plain-tail behavior, bounded the same way
        tail = lines[-max_lines:]
        while tail and sum(len(str(l)) + 1 for l in tail) > max_bytes:
            tail = tail[1:]
        return tail
