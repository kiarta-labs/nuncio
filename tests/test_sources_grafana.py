"""Grafana unified-alerting webhook adapter."""
import pytest

from nuncio import fingerprint as fp_mod
from nuncio.prompt import build_level_a_messages
from nuncio.sources.grafana import Grafana

PAYLOAD = {
    "receiver": "nuncio",
    "status": "firing",
    "commonLabels": {"alertname": "HighCPU"},
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "HighCPU", "instance": "web-1", "severity": "critical"},
            "annotations": {"summary": "CPU above 90% for 5m"},
            "startsAt": "2026-07-17T09:00:00Z",
            "fingerprint": "abc123",
        },
        {
            "status": "resolved",
            "labels": {"alertname": "HighCPU", "instance": "web-2"},
            "annotations": {"description": "back to normal"},
            "startsAt": "2026-07-17T09:05:00Z",
            "fingerprint": "def456",
        },
    ],
}


def test_parses_one_entry_per_alert():
    out = Grafana().parse(PAYLOAD, headers={})
    assert len(out) == 2


def test_maps_fields_and_severity():
    out = Grafana().parse(PAYLOAD, headers={})
    a = out[0].alert
    assert a["host"] == "web-1"
    assert a["service"] == "HighCPU"
    assert a["severity"] == "critical"
    assert "CPU above 90%" in a["output"]
    assert a["source"] == "grafana"


def test_resolved_alert_without_severity_label_is_unknown_not_critical():
    out = Grafana().parse(PAYLOAD, headers={})
    assert out[1].alert["severity"] != "critical"


def test_key_is_source_prefixed_and_uses_fingerprint():
    out = Grafana().parse(PAYLOAD, headers={})
    assert out[0].key.startswith("grafana:abc123/")


def test_batched_alerts_get_distinct_keys():
    out = Grafana().parse(PAYLOAD, headers={})
    assert out[0].key != out[1].key


def test_missing_alerts_list_raises_value_error():
    with pytest.raises(ValueError):
        Grafana().parse({"status": "firing"}, headers={})


def test_non_dict_payload_raises_value_error():
    with pytest.raises(ValueError):
        Grafana().parse([1, 2], headers={})


def test_raw_text_is_meaningful_standalone():
    out = Grafana().parse(PAYLOAD, headers={})
    assert "web-1" in out[0].raw_text and "HighCPU" in out[0].raw_text


# --- Phase 2: value/links extras -----------------------------------------

def _alert_with(**overrides):
    a = {
        "status": "firing",
        "labels": {"alertname": "HighCPU", "instance": "web-1", "severity": "critical"},
        "annotations": {"summary": "CPU above 90% for 5m"},
        "startsAt": "2026-07-17T09:00:00Z",
        "fingerprint": "abc123",
    }
    a.update(overrides)
    return {"receiver": "nuncio", "status": "firing",
            "commonLabels": {"alertname": "HighCPU"}, "alerts": [a]}


def test_value_from_valueString():
    payload = _alert_with(valueString="[ var='A' labels={} value=95.3 ]")
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["value"] == "[ var='A' labels={} value=95.3 ]"


def test_value_line_appears_in_level_a_prompt():
    payload = _alert_with(valueString="[ var='A' value=95.3 ]")
    out = Grafana().parse(payload, headers={})
    messages = build_level_a_messages(out[0].alert)
    user_content = messages[1]["content"]
    assert "value: [ var='A' value=95.3 ]" in user_content


def test_value_falls_back_to_compact_values_dict():
    payload = _alert_with(values={"B": 0, "A": 95.3})
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["value"] == "A=95.3, B=0"


def test_value_omitted_when_neither_valuestring_nor_values_present():
    payload = _alert_with()
    out = Grafana().parse(payload, headers={})
    assert "value" not in out[0].alert


def test_value_omitted_when_valuestring_empty_and_values_empty_dict():
    payload = _alert_with(valueString="", values={})
    out = Grafana().parse(payload, headers={})
    assert "value" not in out[0].alert


def test_links_joins_runbook_panel_dashboard_in_order():
    payload = _alert_with(
        annotations={"summary": "CPU above 90% for 5m", "runbook_url": "https://runbook/cpu"},
        panelURL="https://grafana/d/panel1",
        dashboardURL="https://grafana/d/dash1",
    )
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["links"] == (
        "https://runbook/cpu · https://grafana/d/panel1 · https://grafana/d/dash1"
    )


def test_links_line_appears_in_level_a_prompt():
    payload = _alert_with(panelURL="https://grafana/d/panel1")
    out = Grafana().parse(payload, headers={})
    messages = build_level_a_messages(out[0].alert)
    user_content = messages[1]["content"]
    assert "links: https://grafana/d/panel1" in user_content


def test_links_only_panelurl_present():
    payload = _alert_with(panelURL="https://grafana/d/panel1")
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["links"] == "https://grafana/d/panel1"


def test_links_omitted_when_none_present():
    payload = _alert_with()
    out = Grafana().parse(payload, headers={})
    assert "links" not in out[0].alert


def test_batched_alerts_each_carry_own_value_no_cross_contamination():
    payload = {
        "receiver": "nuncio", "status": "firing",
        "commonLabels": {"alertname": "HighCPU"},
        "alerts": [
            {"status": "firing", "labels": {"alertname": "HighCPU", "instance": "web-1"},
             "annotations": {"summary": "a"}, "startsAt": "t1", "fingerprint": "f1",
             "valueString": "value-one"},
            {"status": "firing", "labels": {"alertname": "HighCPU", "instance": "web-2"},
             "annotations": {"summary": "b"}, "startsAt": "t2", "fingerprint": "f2",
             "valueString": "value-two"},
        ],
    }
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["value"] == "value-one"
    assert out[1].alert["value"] == "value-two"


def test_regression_alert_without_extras_is_byte_identical():
    out = Grafana().parse(PAYLOAD, headers={})
    a0 = out[0].alert
    assert a0 == {
        "host": "web-1", "service": "HighCPU", "state": "firing",
        "severity": "critical", "output": "CPU above 90% for 5m",
        "timestamp": "2026-07-17T09:00:00Z", "source": "grafana",
    }
    assert out[0].key == "grafana:abc123/firing/2026-07-17T09:00:00Z"
    assert out[0].raw_text == "[FIRING] web-1 / HighCPU — CPU above 90% for 5m"


# --- Phase 1: lifecycle-deterministic severity (resolved -> ok, unconditionally) --

def test_resolved_with_warning_label_is_ok_not_warning():
    payload = _alert_with(
        status="resolved",
        labels={"alertname": "HighCPU", "instance": "web-1", "severity": "warning"},
    )
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["severity"] == "ok"


def test_resolved_with_critical_label_is_ok_not_critical():
    payload = _alert_with(
        status="resolved",
        labels={"alertname": "HighCPU", "instance": "web-1", "severity": "critical"},
    )
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["severity"] == "ok"


def test_firing_with_warning_label_is_warning():
    payload = _alert_with(
        labels={"alertname": "HighCPU", "instance": "web-1", "severity": "warning"},
    )
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["severity"] == "warning"


def test_firing_with_no_severity_label_is_unknown():
    payload = _alert_with(labels={"alertname": "HighCPU", "instance": "web-1"})
    out = Grafana().parse(payload, headers={})
    assert out[0].alert["severity"] == "unknown"


def test_batch_one_firing_one_resolved_same_rule_gets_warning_and_ok():
    payload = {
        "receiver": "nuncio", "status": "firing",
        "commonLabels": {"alertname": "HighCPU"},
        "alerts": [
            {"status": "firing",
             "labels": {"alertname": "HighCPU", "instance": "web-1", "severity": "warning"},
             "annotations": {"summary": "CPU above 90%"}, "startsAt": "t1", "fingerprint": "f1"},
            {"status": "resolved",
             "labels": {"alertname": "HighCPU", "instance": "web-1", "severity": "warning"},
             "annotations": {"summary": "back to normal"}, "startsAt": "t2", "fingerprint": "f1"},
        ],
    }
    out = Grafana().parse(payload, headers={})
    assert len(out) == 2
    assert out[0].alert["severity"] == "warning"
    assert out[1].alert["severity"] == "ok"


def test_fingerprint_identical_with_and_without_value_links():
    payload_plain = _alert_with()
    payload_extra = _alert_with(
        valueString="[ var='A' value=95.3 ]",
        annotations={"summary": "CPU above 90% for 5m", "runbook_url": "https://runbook/cpu"},
        panelURL="https://grafana/d/panel1",
    )
    plain = Grafana().parse(payload_plain, headers={})[0].alert
    extra = Grafana().parse(payload_extra, headers={})[0].alert
    assert "value" not in plain and "value" in extra
    assert fp_mod.fingerprint(plain) == fp_mod.fingerprint(extra)
