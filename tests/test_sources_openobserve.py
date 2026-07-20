"""OpenObserve alert-destination webhook adapter."""
import json

import pytest

import nuncio.sources.openobserve as openobserve_mod
from nuncio import fingerprint as fp_mod
from nuncio.prompt import build_level_a_messages
from nuncio.sources.openobserve import OpenObserve


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(openobserve_mod, "_clock", lambda: 1_752_739_260.0)  # minute bucket stable
    yield

RECOMMENDED_TEMPLATE_PAYLOAD = {
    "alert_name": "syslog-flood",
    "stream": "syslog",
    "org_name": "default",
    "start_time": "1752739200000000",
    "end_time": "1752739260000000",
    "severity": "critical",
    "message": "16.8k msgs/hr from a single MAC",
}


def test_maps_recommended_template_fields():
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    assert len(out) == 1
    a = out[0].alert
    assert a["service"] == "syslog-flood"
    assert a["severity"] == "critical"
    assert "16.8k msgs" in a["output"]
    assert a["source"] == "openobserve"


def test_key_is_source_prefixed_and_stable_fields():
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    assert out[0].key == "openobserve:syslog-flood/syslog/1752739200000000"


def test_field_aliases_accepted():
    payload = {"alertName": "x", "streamName": "y", "alert_severity": "warning",
               "alert_desc": "something happened"}
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["service"] == "x"
    assert out[0].alert["severity"] == "warning"
    assert "something happened" in out[0].alert["output"]


def test_missing_fields_degrade_gracefully_not_raise():
    out = OpenObserve().parse({}, headers={})
    assert len(out) == 1
    assert out[0].alert["service"] == "-"


def test_non_dict_payload_raises_value_error():
    with pytest.raises(ValueError):
        OpenObserve().parse("not json", headers={})


# --- a destination template that omits start_time must NOT collapse every
# firing of the same alert+stream onto one key forever (true loss: after the
# first firing, store.persist's INSERT OR IGNORE silently drops every
# subsequent one). Degrade to an ingest-time minute-bucket instead (mirrors
# nuncio/sources/generic.py's documented parse()-may-use-a-clock exception). ---

def test_missing_start_time_does_not_collapse_distinct_firings_in_different_minutes(monkeypatch):
    payload = {"alert_name": "syslog-flood", "stream": "syslog", "message": "m"}
    k1 = OpenObserve().parse(payload, headers={})[0].key
    monkeypatch.setattr(openobserve_mod, "_clock", lambda: 1_752_739_400.0)  # next minute
    k2 = OpenObserve().parse(payload, headers={})[0].key
    assert k1 != k2


def test_missing_start_time_dedupes_tight_retries_in_same_minute():
    payload = {"alert_name": "syslog-flood", "stream": "syslog", "message": "m"}
    k1 = OpenObserve().parse(payload, headers={})[0].key
    k2 = OpenObserve().parse(payload, headers={})[0].key
    assert k1 == k2


def test_present_start_time_key_is_unchanged_by_the_fallback():
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    assert out[0].key == "openobserve:syslog-flood/syslog/1752739200000000"


# --- Phase 3: first-class extras (details/value/check_command) from
# optional rows/condition/query template keys -------------------------

def test_rows_string_populates_details_and_appears_in_prompt():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, rows="2026-07-19 10:00:01 boom x14")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["details"] == "2026-07-19 10:00:01 boom x14"
    messages = build_level_a_messages(out[0].alert)
    assert "details: 2026-07-19 10:00:01 boom x14" in messages[1]["content"]


def test_rows_json_list_of_dicts_renders_compact_deterministic_multiline():
    rows = [
        {"ts": "12:00:01", "msg": "boom", "count": 5},
        {"ts": "12:00:02", "msg": "boom", "count": 3},
    ]
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, rows=rows)
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["details"] == (
        '{"count": 5, "msg": "boom", "ts": "12:00:01"}\n'
        '{"count": 3, "msg": "boom", "ts": "12:00:02"}'
    )


def test_rows_json_list_of_strings_renders_one_per_line():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, rows=["line one", "line two"])
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["details"] == "line one\nline two"


def test_rows_single_dict_not_wrapped_in_list_renders_one_line():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, rows={"ts": "12:00:01", "msg": "boom"})
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["details"] == '{"msg": "boom", "ts": "12:00:01"}'


def test_condition_populates_value_and_query_populates_check_command():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD,
                    condition="count>=10 (got 14)",
                    query="SELECT count(*) FROM syslog WHERE ...")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["value"] == "count>=10 (got 14)"
    assert out[0].alert["check_command"] == "SELECT count(*) FROM syslog WHERE ..."
    messages = build_level_a_messages(out[0].alert)
    content = messages[1]["content"]
    assert "value: count>=10 (got 14)" in content
    assert "check: SELECT count(*) FROM syslog WHERE ..." in content


def test_alias_sql_maps_to_check_command():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, sql="SELECT 1")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["check_command"] == "SELECT 1"


def test_alias_threshold_maps_to_value():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, threshold="cpu>90")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["value"] == "cpu>90"


def test_alias_result_maps_to_details():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, result="raw result text")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["details"] == "raw result text"


def test_regression_alert_without_new_extras_is_byte_identical():
    # Phase 3.6: host no longer defaults to org/stream (org/stream-as-host
    # fabricated a shared "same host" identity among every O2 alert on the
    # same org) -- it's the "-" placeholder like every other adapter absent
    # a real host/instance field in the destination template.
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    a0 = out[0].alert
    assert a0 == {
        "host": "-", "service": "syslog-flood", "state": "firing",
        "severity": "critical", "output": "16.8k msgs/hr from a single MAC",
        "timestamp": "1752739200000000", "source": "openobserve",
    }
    assert out[0].key == "openobserve:syslog-flood/syslog/1752739200000000"
    assert out[0].raw_text == "[syslog] syslog-flood — 16.8k msgs/hr from a single MAC"


def test_regression_minute_bucket_path_unaffected_by_absent_new_extras():
    payload = {"alert_name": "syslog-flood", "stream": "syslog", "message": "m"}
    out = OpenObserve().parse(payload, headers={})
    assert out[0].key == "openobserve:syslog-flood/syslog/29212321"
    assert "details" not in out[0].alert
    assert "value" not in out[0].alert
    assert "check_command" not in out[0].alert


def test_fingerprint_identical_with_and_without_rows_query_condition():
    plain = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})[0].alert
    extra_payload = dict(
        RECOMMENDED_TEMPLATE_PAYLOAD,
        rows=[{"ts": "12:00:01", "msg": "boom"}],
        condition="count>=10 (got 14)",
        query="SELECT count(*) FROM syslog",
    )
    extra = OpenObserve().parse(extra_payload, headers={})[0].alert
    assert fp_mod.fingerprint(plain) == fp_mod.fingerprint(extra)


def test_secret_in_row_does_not_crash_and_key_is_set():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD,
                    rows=[{"msg": "auth failed", "password": "hunter2"}])
    out = OpenObserve().parse(payload, headers={})
    assert "details" in out[0].alert
    assert "hunter2" in out[0].alert["details"]


# --- Phase 3.6: host no longer defaults to org/stream -- two unrelated O2
# alerts on the same org must not fabricate a shared "same host" identity. ---

# --- Phase 4.1: optional unit/container template field -> alert["unit"],
# so resolve_unit (Phase 4.1) and resolve_unit_strict (Phase 3) can name the
# real docker container/log unit instead of falling back to the alert name.

def test_unit_field_mapped_to_alert_unit():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, unit="vector")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["unit"] == "vector"


def test_container_alias_mapped_to_alert_unit():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, container="vector")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["unit"] == "vector"


def test_container_name_alias_mapped_to_alert_unit():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, container_name="vector")
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["unit"] == "vector"


def test_unit_field_string_coerced():
    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, unit=12345)
    out = OpenObserve().parse(payload, headers={})
    assert out[0].alert["unit"] == "12345"


def test_unit_field_absent_when_template_omits_it():
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    assert "unit" not in out[0].alert


def test_regression_alert_without_new_extras_is_still_byte_identical_with_unit_absent():
    # pins the exact-dict regression test above: adding the optional `unit`
    # extra must not appear when the template doesn't supply it.
    out = OpenObserve().parse(RECOMMENDED_TEMPLATE_PAYLOAD, headers={})
    assert "unit" not in out[0].alert


def test_unit_feeds_resolve_unit_strict_for_the_causal_gate():
    from nuncio.resolver import resolve_unit_strict

    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, unit="Docker container vector")
    out = OpenObserve().parse(payload, headers={})
    assert resolve_unit_strict(out[0].alert) == "vector"


def test_two_unrelated_o2_alerts_same_org_share_no_host():
    from nuncio.correlate import rank_correlated

    a1 = OpenObserve().parse(dict(RECOMMENDED_TEMPLATE_PAYLOAD, alert_name="alert-one"),
                              headers={})[0]
    a2 = OpenObserve().parse(dict(RECOMMENDED_TEMPLATE_PAYLOAD, alert_name="alert-two",
                                   start_time="1752739300000000"), headers={})[0]
    assert a1.alert["host"] == a2.alert["host"] == "-"  # both placeholder, not "default"
    row = ("k", a1.raw_text, 1000.0, "openobserve", None, None, None,
           None, a1.alert["service"])  # host persists as NULL for a "-" placeholder
    ranked = rank_correlated([row], a2.alert, tokens=[], now=1000.0)
    assert ranked == []  # no shared identity -- no correlation between them


# --- Phase 4.4: severity:"info" from a destination template flows end-to-end
# through the disposition gate (Phase 2) -- an O2 alert declared `info` in
# the template must render without cause/next framing, same as any other
# source's `info` severity. ---

def test_template_severity_info_renders_without_cause_or_next_end_to_end():
    from nuncio.engine import Engine
    from nuncio.store import Store

    class _FakeClock:
        def __call__(self):
            return 1000.0

    class _FakeLLM:
        model = "local-model"

        def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
            return json.dumps({
                "summary": "watchtower updated 3 containers.",
                "likely_cause": "a stale image was pulled",
                "correlation": None,
                "checks": ["review the changelog"],
            })

    class _FakeDelivery:
        def __init__(self):
            self.sent = []

        def send(self, envelope):
            self.sent.append(envelope)
            return True

    payload = dict(RECOMMENDED_TEMPLATE_PAYLOAD, alert_name="watchtower-updates",
                    severity="info")
    parsed = OpenObserve().parse(payload, headers={})[0]
    assert parsed.alert["severity"] == "info"

    store = Store(":memory:")
    try:
        store.persist(parsed.key, parsed.raw_text)
        dlv = _FakeDelivery()
        engine = Engine(store=store, llm=_FakeLLM(), delivery=dlv, budget_s=45.0,
                        per_attempt_s=20.0, delivery_budget_s=3.0, clock=_FakeClock())
        outcome = engine.process(parsed.key, parsed.alert, parsed.raw_text)
        assert outcome == "enriched"
        detail = dlv.sent[0].detail
        assert "Likely caused by" not in detail
        assert "Next:" not in detail
        assert "watchtower updated 3 containers." in detail
    finally:
        store.close()
