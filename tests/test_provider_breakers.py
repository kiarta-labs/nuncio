"""P2 per-provider breaker isolation + labelled metrics."""
import pytest

from nuncio.circuit import CircuitBreaker
from nuncio.deadline import Deadline
from nuncio.engine import Engine
from nuncio.llm import LLMError
from nuncio.server import Metrics
from nuncio.store import Store


class FakeLLM:
    def __init__(self, behavior):
        self.behavior = behavior
        self.calls = []
        self._json_object_supported = None

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.calls.append(messages)
        kind, val = self.behavior[len(self.calls) - 1]
        if kind == "err":
            raise val
        return val, {}


class FakeDelivery:
    def send(self, envelope):
        return True


def _engine(store, llm, **kw):
    params = dict(budget_s=45.0, per_attempt_s=20.0, clock=lambda: 1000.0)
    params.update(kw)
    return Engine(store=store, llm=llm, delivery=FakeDelivery(), **params)


def _retryable():
    return LLMError("boom", retryable=True, status=500)


def test_active_breaker_defaults_to_legacy_breaker():
    store = Store(":memory:")
    try:
        eng = _engine(store, FakeLLM([]))
        assert eng._active_breaker() is eng.breaker
        assert eng.provider_breakers == {}
    finally:
        store.close()


def test_active_breaker_resolves_selected_provider():
    store = Store(":memory:")
    try:
        ba = CircuitBreaker()
        bb = CircuitBreaker()
        eng = _engine(store, FakeLLM([]),
                      provider_breakers={"a": ba, "b": bb}, provider_id="a")
        assert eng._active_breaker() is ba
        eng.provider_id = "b"
        assert eng._active_breaker() is bb
        eng.provider_id = "ghost"  # unknown id fails closed to legacy
        assert eng._active_breaker() is eng.breaker
        eng.provider_id = None
        assert eng._active_breaker() is eng.breaker
    finally:
        store.close()


def test_funnel_failures_attribute_to_active_provider_only():
    store = Store(":memory:")
    try:
        llm = FakeLLM([("err", _retryable())])
        ba = CircuitBreaker(fails=10)
        bb = CircuitBreaker(fails=10)
        eng = _engine(store, llm, provider_breakers={"a": ba, "b": bb},
                      provider_id="a")
        dl = Deadline(45.0, clock=lambda: 1000.0)
        with pytest.raises(LLMError):
            eng._call_bounded([{"role": "user", "content": "hi"}], dl, None, bound=5.0)
        assert ba.failure_count == 1
        assert bb.failure_count == 0
        assert eng.breaker.failure_count == 0  # legacy object untouched
    finally:
        store.close()


def test_build_app_wires_provider_map_and_labelled_metrics(tmp_path):
    from nuncio import config
    import json
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path),
           "NUNCIO_PROVIDERS_JSON": json.dumps({
               "a": {"base_url": "http://a:11434/v1"},
               "b": {"base_url": "http://b:11434/v1"}})}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        assert set(app.engine.provider_breakers) == {"a", "b"}
        assert app.engine.provider_id is None
        assert app.engine._active_breaker() is app.engine.breaker
        assert set(app.metrics.breakers) == {"a", "b"}
        text = app.metrics.render()
        assert 'nuncio_llm_breaker_trips_total{provider="a"} 0' in text
        assert 'nuncio_llm_breaker_state{provider="b",state="closed"} 1' in text
        assert "nuncio_llm_breaker_trips_total 0" in text  # legacy series kept
    finally:
        app.store.close()


def test_selector_flip_repoints_funnel_and_legacy_series(tmp_path):
    from nuncio import config
    import json
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path),
           "NUNCIO_PROVIDERS_JSON": json.dumps({
               "a": {"base_url": "http://a:11434/v1"},
               "b": {"base_url": "http://b:11434/v1"}})}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        # trip provider a directly, then select it: funnel + legacy follow
        app.engine.provider_breakers["a"].record_failure()
        assert app.engine.provider_breakers["a"].failure_count == 1
        result = config.apply_changes(app, {"NUNCIO_LLM_PROVIDER": "a"})
        assert result["applied"] == ["NUNCIO_LLM_PROVIDER"]
        assert app.engine.provider_id == "a"
        assert app.engine._active_breaker() is app.engine.provider_breakers["a"]
        assert app.metrics.breaker is app.engine.provider_breakers["a"]
        # trips survive the flip (no reset on re-point)
        assert app.metrics.breaker.failure_count == 1
    finally:
        app.store.close()


def test_cb_knob_change_reconfigures_every_breaker(tmp_path):
    from nuncio import config
    import json
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path),
           "NUNCIO_PROVIDERS_JSON": json.dumps(
               {"a": {"base_url": "http://a:11434/v1"}})}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        app.engine.provider_breakers["a"].record_failure()
        config.apply_changes(app, {"NUNCIO_LLM_CB_FAILS": 5})
        assert app.engine.provider_breakers["a"].failure_count == 0  # reset, like legacy
        assert app.engine.provider_breakers["a"].fails == 5
        assert app.engine.breaker.fails == 5
    finally:
        app.store.close()


def test_metrics_without_breakers_omits_labelled_series():
    m = Metrics()
    assert "provider=" not in m.render()
