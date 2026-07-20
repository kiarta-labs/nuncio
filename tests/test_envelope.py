"""nuncio/envelope.py: headline determinism + never-raises behavior."""
from nuncio import envelope as env_mod
from nuncio.envelope import build_headline, severity_to_notify_type, SEVERITY_PRIORITY
from nuncio.delivery import ntfy


def test_ntfy_priority_table_is_the_same_object_as_envelope_severity_priority():
    assert ntfy._PRIORITY is SEVERITY_PRIORITY


# --- severity_to_notify_type ---

def test_severity_to_notify_type_known_values():
    assert severity_to_notify_type("critical") == "5"
    assert severity_to_notify_type("warning") == "4"
    assert severity_to_notify_type("info") == "3"
    assert severity_to_notify_type("ok") == "2"
    assert severity_to_notify_type("unknown") == "3"


def test_severity_to_notify_type_defaults_for_garbage():
    assert severity_to_notify_type("bogus") == "3"
    assert severity_to_notify_type(None) == "3"


# --- build_headline: severity label ---

def test_headline_severity_labels():
    assert build_headline("critical", "h", "", "x").startswith("❗")
    assert build_headline("warning", "h", "", "x").startswith("🟡")
    assert build_headline("info", "h", "", "x").startswith("🔵")
    assert build_headline("ok", "h", "", "x").startswith("✅")
    assert build_headline("unknown", "h", "", "x").startswith("❔")
    assert build_headline("totally-bogus", "h", "", "x").startswith("❔")


def test_severity_symbol_matches_map():
    from nuncio.envelope import severity_symbol
    assert severity_symbol("critical") == "❗"
    assert severity_symbol("warning") == "🟡"
    assert severity_symbol("info") == "🔵"
    assert severity_symbol("ok") == "✅"
    assert severity_symbol("unknown") == "❔"
    assert severity_symbol("bogus") == "❔"


# --- entity composition ---

def test_headline_entity_host_and_service():
    h = build_headline("critical", "host01", "db", "down")
    assert "host01/db" in h


def test_headline_entity_host_only():
    h = build_headline("critical", "host01", "", "down")
    assert "host01" in h
    assert "/" not in h.split("—")[0]


def test_headline_entity_service_only():
    h = build_headline("critical", "", "db", "down")
    assert "db" in h


def test_headline_entity_omitted_when_neither():
    h = build_headline("critical", "", "", "down")
    assert "—" in h
    assert " · " not in h  # no entity separator when there's no entity


def test_headline_entity_truncated_over_32_chars():
    long_host = "a" * 40
    h = build_headline("critical", long_host, "", "down")
    assert "…" in h.split("—")[0]


# --- crux: clause splitting ---

def test_headline_crux_splits_on_period_followed_by_space():
    h = build_headline("info", "h", "", "First sentence. Second sentence.")
    assert "First sentence" in h
    assert "Second sentence" not in h


def test_headline_crux_does_not_split_on_ip_address():
    h = build_headline("info", "h", "", "connection to 10.0.0.2 failed")
    assert "10.0.0.2" in h


def test_headline_crux_does_not_split_on_dotted_service_name():
    h = build_headline("info", "h", "", "web.service crashed")
    assert "web.service" in h


def test_headline_crux_splits_on_em_dash():
    h = build_headline("info", "h", "", "primary cause — secondary detail")
    assert "primary cause" in h
    assert "secondary detail" not in h


def test_headline_crux_splits_on_semicolon():
    h = build_headline("info", "h", "", "cause one; cause two")
    assert "cause one" in h
    assert "cause two" not in h


def test_headline_crux_falls_back_to_raw_first_line_when_summary_blank():
    h = build_headline("info", "h", "", "   ", raw_first_line="raw fallback text here")
    assert "raw fallback text here" in h


def test_headline_crux_strips_leading_raw_fallback_marker():
    h = build_headline("info", "h", "", "[enrichment unavailable]\nsomething broke")
    assert "enrichment unavailable" not in h


# --- length caps ---

def test_headline_soft_cap_70_cuts_at_word_boundary():
    long_crux = "word " * 30  # far over 70 chars, single clause (no '.', '—', ';')
    h = build_headline("info", "h", "", long_crux)
    crux_part = h.split("— ", 1)[1]
    assert len(crux_part) <= 75  # 70 + ellipsis + slack
    assert crux_part.endswith("…")


def test_headline_hard_cap_120():
    long_crux = "x" * 300
    h = build_headline("info", "h", "", long_crux)
    assert len(h) <= 130  # generous slack for the "SEV · entity — " prefix


# --- recurrence suffix ---

def test_headline_recurrence_suffix_appended():
    h = build_headline("warning", "h", "", "disk full", recurrence_count=2, window_label="10m")
    assert h.endswith("(2nd in 10m)")


def test_headline_recurrence_ordinals():
    assert build_headline("info", "h", "", "x", recurrence_count=3, window_label="1h").endswith("(3rd in 1h)")
    assert build_headline("info", "h", "", "x", recurrence_count=11, window_label="1h").endswith("(11th in 1h)")
    assert build_headline("info", "h", "", "x", recurrence_count=21, window_label="1h").endswith("(21st in 1h)")


def test_headline_no_recurrence_suffix_when_count_is_1_or_0():
    h1 = build_headline("info", "h", "", "x", recurrence_count=1, window_label="1h")
    h0 = build_headline("info", "h", "", "x", recurrence_count=0, window_label="1h")
    assert "in 1h" not in h1
    assert "in 1h" not in h0


# --- never raises ---

def test_headline_never_raises_on_none_inputs():
    h = build_headline(None, None, None, None)
    assert isinstance(h, str) and h


def test_headline_never_raises_on_garbage_types():
    h = build_headline(12345, {"a": 1}, [1, 2], object())
    assert isinstance(h, str) and h


def test_headline_never_raises_on_garbage_recurrence():
    h = build_headline("info", "h", "s", "x", recurrence_count="not-a-number", window_label=123)
    assert isinstance(h, str) and h


def test_build_detail_html_never_raises_on_garbage_envelope():
    class Garbage:
        pass
    out = env_mod.build_detail_html(Garbage())
    assert isinstance(out, str)


def test_build_detail_html_escapes_script_tags():
    from nuncio.envelope import Envelope
    e = Envelope(severity="critical", host="h", service="s", headline="hl",
                 summary="sum", detail="</pre><script>alert(1)</script>")
    html = env_mod.build_detail_html(e)
    assert "<script" not in html
    assert "&lt;script" in html


# --- Batch B: build_detail_html with sections_red (full evidence rendering) ---

def test_build_detail_html_with_sections_renders_labeled_blocks():
    from nuncio.envelope import Envelope
    detail = ("CRIT db-primary is down.\n\n--- Raw alert:\nhost01 / db-primary / CRIT: down")
    e = Envelope(severity="critical", host="host01", service="db-primary", headline="hl",
                 summary="db-primary is down", detail=detail)
    sections = {
        "recent_logs": "connection refused at 10:00",
        "correlated": "- host01 GPF escalation [same host]",
        "recurrence": "2nd occurrence of this signature in 2h",
    }
    html = env_mod.build_detail_html(e, sections_red=sections)
    assert "<strong>CRIT db-primary is down.</strong>" in html
    assert "<h4>Log excerpt</h4>" in html
    assert "connection refused" in html
    assert "<h4>Correlated</h4>" in html
    assert "<h4>Recurrence</h4>" in html
    assert "<h4>Raw alert</h4>" in html
    assert "host01 / db-primary / CRIT: down" in html


def test_build_detail_html_escapes_every_section():
    from nuncio.envelope import Envelope
    detail = "finding\n\n--- Raw alert:\nraw text"
    e = Envelope(severity="critical", host="h", service="s", headline="hl", summary="finding", detail=detail)
    hostile = '</pre><script>alert(1)</script><img onerror=x>'
    html = env_mod.build_detail_html(e, sections_red={"recent_logs": hostile})
    assert "<script" not in html
    assert "&lt;script" in html


def test_build_detail_html_findings_and_raw_never_dropped_under_tight_cap():
    from nuncio.envelope import Envelope
    detail = "the finding line\n\n--- Raw alert:\nthe raw alert line"
    e = Envelope(severity="critical", host="h", service="s", headline="hl",
                 summary="the finding line", detail=detail)
    sections = {"recent_logs": "x" * 5000, "correlated": "y" * 5000}
    html = env_mod.build_detail_html(e, sections_red=sections, cap_bytes=200)
    assert "the finding line" in html
    assert "the raw alert line" in html


def test_build_detail_html_never_raises_with_sections_on_garbage():
    class Garbage:
        pass
    out = env_mod.build_detail_html(Garbage(), sections_red={"recent_logs": "x"})
    assert isinstance(out, str)


# --- Batch B: build_envelope's plain-text --- Evidence: appendix ---

def test_build_envelope_evidence_appendix_present_when_sections_given():
    from nuncio.render import build_envelope
    env = build_envelope(
        "the finding", "raw alert text", severity="critical", host="h", service="s",
        sections_red={"recent_logs": "log line one\nlog line two", "correlated": "- corr entry"},
    )
    assert "--- Evidence:" in env.detail
    assert "[Log excerpt]" in env.detail
    assert "log line one" in env.detail
    assert "[Correlated]" in env.detail


def test_build_envelope_no_evidence_appendix_when_sections_absent():
    from nuncio.render import build_envelope
    env = build_envelope("the finding", "raw alert text", severity="critical", host="h", service="s")
    assert "--- Evidence:" not in env.detail


def test_build_envelope_evidence_appendix_capped():
    from nuncio.render import build_envelope
    env = build_envelope(
        "the finding", "raw alert text", severity="critical", host="h", service="s",
        sections_red={"recent_logs": "x" * 50000},
        evidence_max_bytes=4000,
    )
    idx = env.detail.find("--- Evidence:")
    appendix = env.detail[idx:]
    assert len(appendix.encode("utf-8")) <= 1000 + 200  # min(4000//4, 8000) + slack
