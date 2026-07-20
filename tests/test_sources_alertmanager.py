"""Prometheus Alertmanager webhook adapter."""
import pytest

from nuncio.sources.alertmanager import Alertmanager, _labels_hash

PAYLOAD = {
    "receiver": "nuncio",
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "DiskFull", "instance": "10.0.0.5", "severity": "warning"},
            "annotations": {"summary": "disk 91% full"},
            "startsAt": "2026-07-17T09:00:00Z",
            "fingerprint": "f1",
        },
        {
            "status": "firing",
            # no fingerprint -> fallback to a labels hash
            "labels": {"alertname": "NoFingerprint", "instance": "10.0.0.6"},
            "annotations": {},
            "startsAt": "2026-07-17T09:01:00Z",
        },
    ],
}


def test_parses_one_entry_per_alert():
    out = Alertmanager().parse(PAYLOAD, headers={})
    assert len(out) == 2


def test_maps_fields():
    out = Alertmanager().parse(PAYLOAD, headers={})
    a = out[0].alert
    assert a["host"] == "10.0.0.5"
    assert a["service"] == "DiskFull"
    assert a["severity"] == "warning"
    assert "disk 91%" in a["output"]
    assert a["source"] == "alertmanager"


def test_missing_fingerprint_falls_back_to_labels_hash():
    out = Alertmanager().parse(PAYLOAD, headers={})
    expected = _labels_hash(PAYLOAD["alerts"][1]["labels"])
    assert expected in out[1].key


def test_key_is_source_prefixed():
    out = Alertmanager().parse(PAYLOAD, headers={})
    assert out[0].key.startswith("alertmanager:f1/")


def test_labels_hash_is_stable_regardless_of_key_order():
    a = {"z": "1", "a": "2"}
    b = {"a": "2", "z": "1"}
    assert _labels_hash(a) == _labels_hash(b)


def test_missing_alerts_list_raises_value_error():
    with pytest.raises(ValueError):
        Alertmanager().parse({"status": "firing"}, headers={})


def test_severity_defaults_to_status_when_label_absent():
    payload = {"alerts": [{"status": "firing", "labels": {"alertname": "X"}, "annotations": {}}]}
    out = Alertmanager().parse(payload, headers={})
    # "firing" isn't a recognized severity word -> normalizes to unknown, not
    # a fabricated critical/warning guess.
    assert out[0].alert["severity"] == "unknown"


# --- Phase 1: lifecycle-deterministic severity (resolved -> ok, unconditionally) --

def test_resolved_with_warning_label_is_ok_not_warning():
    payload = {"alerts": [{
        "status": "resolved",
        "labels": {"alertname": "DiskFull", "instance": "10.0.0.5", "severity": "warning"},
        "annotations": {}, "startsAt": "t1", "fingerprint": "f1",
    }]}
    out = Alertmanager().parse(payload, headers={})
    assert out[0].alert["severity"] == "ok"


def test_resolved_with_critical_label_is_ok_not_critical():
    payload = {"alerts": [{
        "status": "resolved",
        "labels": {"alertname": "DiskFull", "instance": "10.0.0.5", "severity": "critical"},
        "annotations": {}, "startsAt": "t1", "fingerprint": "f1",
    }]}
    out = Alertmanager().parse(payload, headers={})
    assert out[0].alert["severity"] == "ok"


def test_firing_with_warning_label_is_warning():
    out = Alertmanager().parse(PAYLOAD, headers={})
    assert out[0].alert["severity"] == "warning"


def test_firing_with_no_severity_label_is_unknown():
    payload = {"alerts": [{
        "status": "firing", "labels": {"alertname": "X", "instance": "h1"},
        "annotations": {}, "startsAt": "t1", "fingerprint": "f1",
    }]}
    out = Alertmanager().parse(payload, headers={})
    assert out[0].alert["severity"] == "unknown"


def test_batch_one_firing_one_resolved_same_rule_gets_warning_and_ok():
    payload = {"alerts": [
        {"status": "firing",
         "labels": {"alertname": "DiskFull", "instance": "10.0.0.5", "severity": "warning"},
         "annotations": {}, "startsAt": "t1", "fingerprint": "f1"},
        {"status": "resolved",
         "labels": {"alertname": "DiskFull", "instance": "10.0.0.5", "severity": "warning"},
         "annotations": {}, "startsAt": "t2", "fingerprint": "f1"},
    ]}
    out = Alertmanager().parse(payload, headers={})
    assert len(out) == 2
    assert out[0].alert["severity"] == "warning"
    assert out[1].alert["severity"] == "ok"
