"""Generic best-effort webhook adapter."""
import pytest

import nuncio.sources.generic as generic_mod
from nuncio.sources.generic import Generic


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(generic_mod, "_clock", lambda: 1_752_739_260.0)  # minute bucket stable
    yield


def test_sniffs_common_field_names():
    out = Generic().parse({"host": "web-1", "message": "disk 91% full"}, headers={})
    assert len(out) == 1
    a = out[0].alert
    assert a["host"] == "web-1"
    assert "disk 91% full" in a["output"]
    assert a["source"] == "generic"


def test_sniffs_alias_field_names():
    out = Generic().parse(
        {"hostname": "db-1", "alertname": "PgDown", "status": "critical", "output": "connection refused"},
        headers={},
    )
    a = out[0].alert
    assert a["host"] == "db-1"
    assert a["service"] == "PgDown"
    assert a["severity"] == "critical"


def test_unrecognized_payload_embeds_whole_body():
    payload = {"weird_field": "value", "another": 42}
    out = Generic().parse(payload, headers={})
    assert "weird_field" in out[0].alert["output"]
    assert "42" in out[0].alert["output"]


def test_key_dedupes_identical_body_in_same_minute():
    p = {"host": "x", "message": "same"}
    k1 = Generic().parse(p, headers={})[0].key
    k2 = Generic().parse(p, headers={})[0].key
    assert k1 == k2  # same body, same minute bucket -> tight-retry dedup


def test_key_does_not_dedupe_distinct_events():
    a = Generic().parse({"host": "x", "message": "one"}, headers={})[0].key
    b = Generic().parse({"host": "x", "message": "two"}, headers={})[0].key
    assert a != b


def test_key_changes_across_minute_buckets(monkeypatch):
    p = {"host": "x", "message": "same"}
    monkeypatch.setattr(generic_mod, "_clock", lambda: 1_752_739_260.0)
    k1 = Generic().parse(p, headers={})[0].key
    monkeypatch.setattr(generic_mod, "_clock", lambda: 1_752_739_400.0)  # next minute
    k2 = Generic().parse(p, headers={})[0].key
    assert k1 != k2  # a genuine retry outside the tight window is not deduped


def test_key_is_source_prefixed():
    out = Generic().parse({"host": "x"}, headers={})
    assert out[0].key.startswith("generic:")


def test_non_dict_payload_raises_value_error():
    with pytest.raises(ValueError):
        Generic().parse([1, 2, 3], headers={})


# --- non-string canonical fields bypassed the engine's
# `isinstance(v, str)` redaction check downstream. Defense in depth: the
# generic adapter already coerced `state` to str; host/service/output must be
# too, since arbitrary POSTed JSON can hand any of them a dict/list/int. ---

def test_non_string_host_and_output_are_coerced_to_str():
    out = Generic().parse(
        {"host": {"x": "y"}, "message": {"password": "hunter2"}, "severity": "crit"},
        headers={},
    )
    a = out[0].alert
    assert isinstance(a["host"], str)
    assert isinstance(a["output"], str)


def test_non_string_service_is_coerced_to_str():
    out = Generic().parse(
        {"host": "web1", "alertname": {"nested": True}, "message": "m"},
        headers={},
    )
    assert isinstance(out[0].alert["service"], str)


def test_ingest_to_engine_end_to_end_does_not_leak_nonstring_secret():
    """Full path: an arbitrary POST body whose `message` field is a dict
    containing a secret must not reach the LLM prompt unredacted, whether via
    the adapter's own coercion or the engine's redaction (belt and suspenders)."""
    from nuncio.engine import Engine
    from nuncio.store import Store

    class FakeLLM:
        def __init__(self):
            self.calls = []
        def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
            self.calls.append(messages)
            return "SUMMARY: x\nSEVERITY: y"

    class FakeDelivery:
        def __init__(self):
            self.sent = []
        def send(self, message, title="t"):
            self.sent.append(message)
            return True

    parsed = Generic().parse(
        {"host": "web1", "message": {"password": "hunter2"}, "severity": "crit"},
        headers={},
    )[0]
    store = Store(":memory:")
    store.persist(parsed.key, parsed.raw_text)
    llm = FakeLLM()
    dlv = FakeDelivery()
    Engine(store, llm, dlv, clock=lambda: 1000.0).process(parsed.key, parsed.alert, parsed.raw_text)
    combined = " ".join(m["content"] for m in llm.calls[0])
    assert "hunter2" not in combined
    store.close()
