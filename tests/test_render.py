"""Final delivery-message rendering (`build_envelope`).

Every enriched message embeds the raw alert verbatim in its detail (so
nothing is lost even if enrichment misleads). Every fallback carries the
mandatory [enrichment unavailable] marker so degradation is always visible
in-channel.
"""
from nuncio.render import build_envelope, RAW_FALLBACK_MARKER

RAW = "host host01 / infisical-postgres / CRIT / FATAL: all AuxiliaryProcs are in use"
ENRICH = "db is down on host01.\n\nLooks urgent, service unavailable."


def test_enriched_contains_analysis_and_raw_verbatim():
    env = build_envelope(ENRICH, RAW)
    assert ENRICH.strip() in env.detail
    assert RAW in env.detail  # raw embedded verbatim, byte-for-byte


def test_enriched_has_labeled_raw_section():
    env = build_envelope(ENRICH, RAW)
    assert "Raw alert" in env.detail


def test_enriched_summary_is_first_line_of_enrichment():
    env = build_envelope(ENRICH, RAW)
    assert env.summary == "db is down on host01."


def test_marker_true_prepends_mandatory_marker():
    env = build_envelope("", RAW, marker=True)
    assert env.detail.startswith(RAW_FALLBACK_MARKER)
    assert RAW in env.detail


def test_marker_true_never_omitted_even_for_empty_enrichment():
    env = build_envelope("", "", marker=True)
    assert env.detail.startswith(RAW_FALLBACK_MARKER)


def test_marker_false_omits_marker():
    env = build_envelope(ENRICH, RAW, marker=False)
    assert not env.detail.startswith(RAW_FALLBACK_MARKER)


def test_envelope_carries_severity_host_service():
    env = build_envelope(ENRICH, RAW, severity="critical", host="host01", service="db")
    assert env.severity == "critical"
    assert env.host == "host01"
    assert env.service == "db"
    assert env.notify_type == "5"


def test_envelope_headline_reflects_severity_and_entity():
    env = build_envelope(ENRICH, RAW, severity="critical", host="host01", service="db")
    assert env.headline.startswith("❗")
    assert "host01/db" in env.headline


def test_envelope_detail_html_is_populated_by_default():
    env = build_envelope(ENRICH, RAW, severity="warning", host="host01")
    assert env.detail_html is not None
    assert "<pre>" in env.detail_html


def test_envelope_detail_html_can_be_overridden():
    env = build_envelope(ENRICH, RAW, detail_html="<custom/>")
    assert env.detail_html == "<custom/>"
