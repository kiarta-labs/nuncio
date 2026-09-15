"""P1 trust-aware dual track: raw prompts/store-red split, hosted skip."""
import json

import pytest

from nuncio.assist import AssistClient
from nuncio.engine import Engine
from nuncio.router import Router
from nuncio.server import App, Metrics
from nuncio.store import Store

CANARY = "tok_canary_9f8e7d6c5b4a3c2d1e0f"
ALERT = {"host": "host01", "service": "db-primary", "state": "CRIT",
         "output": f"FATAL: password reset token {CANARY} rejected",
         "severity": "critical"}
RAW = f"host host01 / db-primary / CRIT / FATAL: password reset token {CANARY} rejected"
RAW_FULL = RAW  # server forks the adapter raw verbatim for trusted alerts
STRUCTURED_WITH_CANARY = json.dumps({
    "summary": "Primary database rejecting connections on host01.",
    "likely_cause": f"leaked reset token {CANARY} replayed against the login",
    "correlation": None,
    "checks": [f"rotate {CANARY} now", "inspect auth logs on host01"],
})


class FakeLLM:
    """Scripted LLM mirroring tests/test_engine.py's double: script entries
    are ("ok", text); enrich() returns the text (plus usage like the real
    LLMClient contract)."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []
        self._json_object_supported = None

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.calls.append(messages)
        kind, val = self.rows[len(self.calls) - 1]
        if kind == "err":
            raise val
        return val, {"prompt_tokens": 1, "completion_tokens": 1}


class FakeDelivery:
    def __init__(self):
        self.sent = []

    def send(self, envelope):
        self.sent.append(envelope)
        return True

    def send_brief(self, envelope):
        self.sent.append(envelope)
        return True

    def send_full(self, envelope):
        self.sent.append(envelope)
        return True

    def has_verbosity(self, verbosity):
        return False  # no assist deferral in these tests unless stated


class FakeGatherer:
    def __init__(self, sections):
        self.sections = dict(sections)
        self.timeout_s = 5.0
        self.max_bytes = 16000
        self.collectors = {}

    def gather(self, alert, key, now, timeout=None, return_sections=False, profile="low"):
        if return_sections:
            return "", dict(self.sections)
        return ""


def _engine(store, llm, dlv, **kw):
    params = dict(budget_s=45.0, per_attempt_s=20.0, clock=lambda: 1000.0, depth="low")
    params.update(kw)
    return Engine(store=store, llm=llm, delivery=dlv, **params)


def _sections():
    return {"recent_logs": f"## Recent logs\nlogin rejected, token {CANARY} already used"}


def test_trusted_prompt_carries_canary_verbatim():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()))
        assert eng.process("k1", dict(ALERT), RAW, trusted=True, raw_full=RAW_FULL) == "enriched"
        prompt = str(llm.calls[0])
        # alert fields + bundle sections unmasked (the canary survives
        # verbatim; the system prompt's own placeholder *instructions* may
        # still mention «REDACTED», which is not redaction of content)
        assert prompt.count(CANARY) >= 2
    finally:
        store.close()


def test_untrusted_prompt_redacts_canary():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()))
        assert eng.process("k1", dict(ALERT), RAW) == "enriched"
        prompt = str(llm.calls[0])
        assert CANARY not in prompt
        assert "«REDACTED" in prompt
    finally:
        store.close()


def test_trusted_delivery_raw_but_store_redacted():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()))
        assert eng.process("k1", dict(ALERT), RAW, trusted=True, raw_full=RAW_FULL) == "enriched"
        # delivered detail intentionally carries raw content...
        assert CANARY in dlv.sent[0].detail
        # ...while every at-rest surface stays redacted
        detail = store.get_alert_detail("k1")
        assert CANARY not in (detail["bundle"] or "")
        assert CANARY not in (detail["enrichment"] or "")
        assert detail["redaction_count"] == 0  # nothing stripped pre-LLM
    finally:
        store.close()


def test_trusted_without_raw_full_fails_closed_to_redacted():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()))
        assert eng.process("k1", dict(ALERT), RAW, trusted=True) == "enriched"
        assert CANARY not in dlv.sent[0].detail  # no raw_full -> redacted raw
    finally:
        store.close()


def _router():
    return Router(private_alias="m", knowledge_alias="km",
                  classification_table={"container": "generic container guidance"},
                  knowledge_enabled=True, knowledge_redundant_with_private=False)


class FakeKnowledgeLLM:
    def __init__(self):
        self.calls = []

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.calls.append(messages)
        return "Common cause: X. Standard fix: Y.", {}


def _alert_with_category(severity="critical"):
    return dict(ALERT, category="container", severity=severity)


def test_trusted_skips_untrusted_knowledge_plane():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        know = FakeKnowledgeLLM()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      router=_router(), knowledge_llm=know,
                      knowledge_trusted=False, depth="low")
        assert eng.process("k1", _alert_with_category(), RAW,
                           trusted=True, raw_full=RAW_FULL) == "enriched"
        assert know.calls == []
        assert "General guidance" not in dlv.sent[0].detail
    finally:
        store.close()


def test_trusted_uses_trusted_knowledge_plane():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        know = FakeKnowledgeLLM()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      router=_router(), knowledge_llm=know,
                      knowledge_trusted=True, depth="low")
        assert eng.process("k1", _alert_with_category(), RAW,
                           trusted=True, raw_full=RAW_FULL) == "enriched"
        assert len(know.calls) == 1
        # the knowledge call itself stays generic (never alert content)
        assert CANARY not in str(know.calls[0])
    finally:
        store.close()


class RecordingAssist:
    def __init__(self):
        self.submits = []

    def eligible(self, severity, mode):
        return True

    def submit(self, key, envelope, context_text, followup=False, trusted=False):
        self.submits.append((key, followup, trusted, context_text))
        return True


class FullVerbosityDelivery(FakeDelivery):
    def has_verbosity(self, verbosity):
        return True


def test_trusted_skips_untrusted_assist_plane():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FullVerbosityDelivery()
        assist = RecordingAssist()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      assist=assist, assist_trusted=False)
        assert eng.process("k1", _alert_with_category(), RAW,
                           trusted=True, raw_full=RAW_FULL) == "enriched"
        assert assist.submits == []  # rich leg shipped immediately, no deferral
        assert CANARY in dlv.sent[0].detail
    finally:
        store.close()


def test_trusted_defers_to_trusted_assist_with_raw_context():
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FullVerbosityDelivery()
        assist = RecordingAssist()
        assist.posture = "scrubbed-real"  # the content-carrying posture
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      assist=assist, assist_trusted=True)
        assert eng.process("k1", _alert_with_category(), RAW,
                           trusted=True, raw_full=RAW_FULL) == "enriched"
        assert len(assist.submits) == 1
        _key, _followup, trusted_flag, context_text = assist.submits[0]
        assert trusted_flag is True
        assert CANARY in context_text  # raw context for the trusted plane
    finally:
        store.close()


def test_insight_trusted_accepts_str_while_insight_still_rejects():
    client = AssistClient(FakeLLM([("ok", "an insight")]))
    assert client.insight_trusted("raw context") == "an insight"
    with pytest.raises(TypeError):
        client.insight("raw context")
    with pytest.raises(TypeError):
        client.insight_trusted({"not": "a str"})


def test_trusted_full_depth_threads_raw_through_triage_and_rca():
    # Full depth consumes two LLM calls (triage + RCA); both prompts must
    # carry raw content on the trusted leg.
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        llm = FakeLLM([("ok", "triage notes here"), ("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      depth="full", budget_s=90.0, full_budget_s=90.0)
        assert eng.process("k1", dict(ALERT), RAW, trusted=True, raw_full=RAW_FULL) == "enriched"
        assert len(llm.calls) == 2
        assert all(call and CANARY in str(call) for call in llm.calls)
    finally:
        store.close()


def test_queue_tuple_carries_trust_and_raw_fork(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    try:
        from nuncio.server import App, Metrics

        class Eng:
            mode = "enriched"

        app = App(Eng(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=10,
                  clock=lambda: 1000.0, maint_interval=3600.0, private_trusted=True)
        payload = {"host": "svr", "service": "s",
                   "message": f"boom {CANARY}", "severity": "critical"}
        assert app.ingest("generic", payload) == 200
        prio, _seq, _key, _alert, raw, raw_full, _dl, _mode, _depth, trusted, provider_at_ingest = app.q.get_nowait()
        assert trusted is True
        assert CANARY in (raw_full or "")
        assert CANARY not in raw  # queued raw is always the redacted form
        assert prio == 0
    finally:
        store.close()


def test_selector_flip_refreshes_trust_flags(tmp_path):
    from nuncio import config
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path),
           "NUNCIO_PROVIDERS_JSON": json.dumps(
               {"local": {"base_url": "http://127.0.0.1:11434/v1", "trusted": True}})}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        assert app.private_trusted is False
        assert app.engine.knowledge_trusted is False
        assert app.engine.assist_trusted is False
        result = config.apply_changes(app, {"NUNCIO_LLM_PROVIDER": "local"})
        assert result["applied"] == ["NUNCIO_LLM_PROVIDER"]
        assert app.private_trusted is True
        assert "127.0.0.1:11434" in app.engine.llm.base_url
        view = {row["id"]: row for row in config.providers_list_view(app.settings)}
        assert view["local"]["trusted"] is True
    finally:
        app.store.close()


def test_captured_trust_survives_a_live_flip(tmp_path):
    # Ingest while untrusted, flip the app flag, then process with the
    # QUEUED values: the alert must stay untrusted (capture-at-ingest).
    from nuncio.server import App, Metrics

    class Eng:
        mode = "enriched"

    store = Store(str(tmp_path / "t.db"))
    try:
        app = App(Eng(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=10,
                  clock=lambda: 1000.0, maint_interval=3600.0, private_trusted=False)
        payload = {"host": "svr", "service": "s",
                   "message": f"boom {CANARY}", "severity": "critical"}
        assert app.ingest("generic", payload) == 200
        item = app.q.get_nowait()
        assert item[9] is False and item[5] is None
        app.private_trusted = True  # live flip AFTER capture
        # replay the queued values through a real engine: still redacted.
        # (Full depth needs two scripted rows: triage + RCA.)
        llm = FakeLLM([("ok", "triage notes here"), ("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()))
        _prio, _seq, key, alert, raw, raw_full, dl, mode, depth, trusted, provider_at_ingest = item
        assert eng.process(key, alert, raw, deadline=dl, mode=mode, depth=depth,
                           trusted=trusted, raw_full=raw_full,
                           provider_at_ingest=provider_at_ingest) == "enriched"
        assert CANARY not in dlv.sent[0].detail
    finally:
        store.close()


def test_selector_flip_fails_closed_for_queued_trusted_alert():
    # Regression (review finding #1): an alert trusted under provider A must
    # NEVER be sent raw after a live selector flip re-points the wire client
    # to provider B. The captured provider id rides the queue tuple; process()
    # downgrades on mismatch (untrusted path, redacted everything).
    store = Store(":memory:")
    try:
        store.persist("k1", RAW)
        store.persist("k2", RAW)
        llm = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv = FakeDelivery()
        eng = _engine(store, llm, dlv, gatherer=FakeGatherer(_sections()),
                      provider_id="a", depth="low")
        assert eng.process("k1", dict(ALERT), RAW, trusted=True, raw_full=RAW_FULL,
                           provider_at_ingest="a") == "enriched"
        assert CANARY in dlv.sent[0].detail  # matching provider: raw flows

        llm2 = FakeLLM([("ok", STRUCTURED_WITH_CANARY)])
        dlv2 = FakeDelivery()
        eng2 = _engine(store, llm2, dlv2, gatherer=FakeGatherer(_sections()),
                       provider_id="b")  # selector flipped to an untrusted id
        assert eng2.process("k2", dict(ALERT), RAW, trusted=True, raw_full=RAW_FULL,
                            provider_at_ingest="a") == "enriched"
        assert CANARY not in dlv2.sent[0].detail  # downgraded: redacted
    finally:
        store.close()
