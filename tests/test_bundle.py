"""Bundle assembly with hard cap. Fixed section order for cache-
friendly prompts; when over the cap, truncate least-important first (logs before
metrics before correlated — correlated is the cross-alert insight, kept longest)."""
from nuncio.bundle import assemble_bundle


def test_fixed_section_order():
    body = assemble_bundle({
        "correlated": "## Correlated\nx",
        "recent_logs": "## Logs\ny",
        "container_state": "## State\nz",
    })
    # container_state before recent_logs before correlated, regardless of input order
    assert body.index("## State") < body.index("## Logs") < body.index("## Correlated")


def test_under_cap_keeps_everything():
    sections = {"recent_logs": "## Logs\n" + "a" * 100, "correlated": "## Corr\nb"}
    body = assemble_bundle(sections, max_bytes=16000)
    assert "## Logs" in body and "## Corr" in body


def test_over_cap_truncates_logs_before_correlated():
    sections = {
        "recent_logs": "## Logs\n" + ("L" * 5000),
        "correlated": "## Correlated\n" + ("C" * 500),
    }
    body = assemble_bundle(sections, max_bytes=1000)
    assert len(body) <= 1000
    assert "## Correlated" in body           # the important section survives
    assert "CCCCCCCCCC" in body              # its content intact
    assert body.count("L") < 5000            # logs got cut


def test_empty_sections_omitted():
    body = assemble_bundle({"recent_logs": "", "correlated": "## Corr\nx"})
    assert "Corr" in body
    assert "recent_logs" not in body


# --- Phase B: 'history' section ---

def test_history_ordered_after_correlated_before_recurrence():
    body = assemble_bundle({
        "correlated": "## Correlated\nx",
        "history": "## Alert history (24h)\ny",
        "recurrence": "## Recurrence\nz",
    })
    assert body.index("## Correlated") < body.index("## Alert history") < body.index("## Recurrence")


def test_history_drops_before_correlated_under_pressure():
    sections = {
        "correlated": "## Correlated\n" + ("C" * 500),
        "history": "## Alert history (24h)\n" + ("H" * 5000),
        "recurrence": "## Recurrence\none line",
    }
    body = assemble_bundle(sections, max_bytes=1000)
    assert len(body) <= 1000
    assert "## Correlated" in body
    assert "CCCCCCCCCC" in body
    assert "## Recurrence" in body


def test_log_section_truncation_keeps_newest_lines():
    # logs are newest-last; over-cap must cut the OLD (head), keep recent (tail)
    logs = "## Recent logs\n" + "\n".join(f"line{i}" for i in range(1000))
    body = assemble_bundle({"recent_logs": logs, "correlated": "## Corr\nx"}, max_bytes=200)
    assert len(body) <= 200
    assert "line999" in body        # newest kept
    assert "line0\n" not in body    # oldest cut
    assert "## Recent logs" in body  # header preserved
