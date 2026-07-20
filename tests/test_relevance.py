"""Log relevance ranking: score candidate lines against the alert's error
tokens / service / severity words, keep the best within budget, PRESERVE
chronological order, and degrade to a plain tail on any internal failure."""
from nuncio.relevance import extract_blocks, rank_log_lines


NOISE = [f"GET /api/health 200 ok {i}" for i in range(200)]


def test_on_topic_old_line_beats_recent_noise():
    # The relevant FATAL line is OLD (index 3) — a naive tail-N would drop it.
    lines = NOISE[:3] + ["FATAL: all AuxiliaryProcs are in use"] + NOISE[3:]
    kept = rank_log_lines(lines, tokens=["FATAL", "AuxiliaryProcs"], max_lines=20)
    assert any("AuxiliaryProcs" in l for l in kept)
    assert len(kept) <= 20


def test_output_preserves_chronological_order():
    lines = ["ERROR early", *NOISE[:50], "ERROR late"]
    kept = rank_log_lines(lines, tokens=[], max_lines=10)
    assert kept.index("ERROR early") < kept.index("ERROR late")


def test_severity_words_score_over_plain_noise():
    lines = NOISE[:30] + ["WARN disk latency rising"] + NOISE[30:60]
    kept = rank_log_lines(lines, tokens=[], max_lines=5)
    assert "WARN disk latency rising" in kept


def test_service_name_match_scores():
    lines = NOISE[:30] + ["infisical-postgres exited"] + NOISE[30:60]
    kept = rank_log_lines(lines, tokens=[], service="infisical-postgres", max_lines=5)
    assert "infisical-postgres exited" in kept


def test_no_signal_degrades_to_recent_tail():
    kept = rank_log_lines(NOISE, tokens=[], max_lines=10)
    assert kept == NOISE[-10:]  # all-equal scores -> newest win, order kept


def test_byte_budget_respected():
    lines = ["ERROR " + "x" * 200 for _ in range(100)]
    kept = rank_log_lines(lines, tokens=[], max_lines=100, max_bytes=1000)
    assert sum(len(l) + 1 for l in kept) <= 1100  # ~budget incl. newlines


def test_word_boundary_token_matching():
    # token 'port' must not score 'portainer' lines
    lines = NOISE[:20] + ["portainer heartbeat ok"] + NOISE[20:40] + ["port 443 refused"]
    kept = rank_log_lines(lines, tokens=["port"], max_lines=2)
    assert "port 443 refused" in kept
    assert "portainer heartbeat ok" not in kept


def test_degrades_to_tail_on_internal_failure():
    class Boom:  # str() explodes while compiling token patterns
        def __str__(self):
            raise RuntimeError("boom")
    kept = rank_log_lines(["a", "b", "c"], tokens=[Boom()], max_lines=2)
    assert kept == ["b", "c"]  # plain tail fallback, never raises


def test_empty_input():
    assert rank_log_lines([], tokens=["x"]) == []


# --- B3: block extraction ---

TRACEBACK = [
    "Traceback (most recent call last):",
    '  File "app.py", line 10, in <module>',
    "    main()",
    '  File "app.py", line 5, in main',
    "    raise ValueError('boom')",
    "ValueError: boom",
]


def test_extract_blocks_groups_traceback_as_one_block():
    lines = ["INFO starting"] + TRACEBACK + ["INFO done"]
    blocks = extract_blocks(lines)
    trace_block = next(b for b in blocks if b[0].startswith("Traceback"))
    # every traceback frame line landed in the SAME block
    assert len(trace_block) == 5  # header + 4 continuation lines ("ValueError: boom" is not indented/at/.../Caused by/File)
    assert all(TRACEBACK[i] in trace_block for i in range(5))


def test_extract_blocks_singleton_for_plain_lines():
    lines = ["a", "b", "c"]
    blocks = extract_blocks(lines)
    assert blocks == [["a"], ["b"], ["c"]]


def test_traceback_kept_contiguous_in_ranked_output():
    lines = ([f"noise {i}" for i in range(20)] + TRACEBACK
             + [f"noise {i}" for i in range(20, 40)])
    kept = rank_log_lines(lines, tokens=[], max_lines=50, max_bytes=8000)
    # every traceback frame line is present, and adjacent to each other
    idxs = [kept.index(l) for l in TRACEBACK if l in kept]
    assert len(idxs) >= 2  # the block wasn't split up and dropped piecemeal
    assert idxs == sorted(idxs)
    assert all(b - a == 1 for a, b in zip(idxs, idxs[1:]))  # contiguous


def test_panic_start_also_grouped():
    lines = ["panic: runtime error: nil pointer", "\tgoroutine 1 [running]:", "\tmain.main()"]
    blocks = extract_blocks(lines)
    assert len(blocks) == 1
    assert len(blocks[0]) == 3


# --- B3: adjacent-identical collapse ---

def test_adjacent_identical_lines_collapse_with_count_marker():
    lines = ["repeated line"] * 5 + ["FATAL something else"]
    kept = rank_log_lines(lines, tokens=[], max_lines=20, max_bytes=8000)
    assert kept.count("repeated line") == 1
    assert any("×5" in l for l in kept)


def test_non_adjacent_identical_lines_not_collapsed():
    lines = ["same"] + [f"other {i}" for i in range(5)] + ["same"]
    kept = rank_log_lines(lines, tokens=[], max_lines=20, max_bytes=8000)
    assert kept.count("same") == 2  # not adjacent -> both kept, no marker


# --- B3: budget consumed by whole blocks ---

def test_budget_by_block_traceback_all_or_head_tail_never_split_mid_block():
    # A traceback whose lines individually would fit but the middle would be
    # cut by a naive per-line budget must NOT be sliced arbitrarily -- it's
    # either whole, or (if it's the sole best block) a head+tail slice.
    huge_trace = ["Traceback (most recent call last):"] + [
        f'  File "app.py", line {i}, in frame{i}' for i in range(200)
    ]
    kept = rank_log_lines(huge_trace, tokens=[], max_lines=20, max_bytes=8000)
    assert kept  # something survived
    assert kept[0] == huge_trace[0]  # head kept (best-block partial include)


def test_budget_by_block_skips_non_fitting_secondary_block():
    small_relevant = ["FATAL: small on-topic line"]
    huge_block = ["Traceback (most recent call last):"] + [
        f'  File "x.py", line {i}' for i in range(500)
    ]
    lines = small_relevant + huge_block
    kept = rank_log_lines(lines, tokens=["FATAL"], max_lines=5, max_bytes=200)
    assert "FATAL: small on-topic line" in kept


# --- B3: fallback path preserved ---

def test_fallback_path_still_works_with_block_extraction():
    class Boom:
        def __str__(self):
            raise RuntimeError("boom")
    kept = rank_log_lines(["a", "b", "c"], tokens=[Boom()], max_lines=2)
    assert kept == ["b", "c"]
