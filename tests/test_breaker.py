"""Engine-level circuit-breaker integration tests. The breaker sits in
`_call_bounded`, the single funnel every private-plane LLM call passes
through, so trips and recovery are observable through `process()` itself --
and the fail-safe invariant (raw + marker on any failure) must hold even
while the circuit is open."""
import pytest

from nuncio.engine import Engine
from nuncio.store import Store
from nuncio.llm import LLMError
from nuncio.render import RAW_FALLBACK_MARKER

VALID = ("db-primary is down on host01, all AuxiliaryProcs busy.\n\n"
         "Looks urgent: the service is fully down, likely capacity exhaustion.")
ALERT = {"host": "host01", "service": "db-primary", "state": "CRIT",
         "output": "FATAL: all AuxiliaryProcs are in use"}
RAW = "host host01 / db-primary / CRIT / FATAL: all AuxiliaryProcs are in use"


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeLLM:
    """Scripted LLM; mirrors tests/test_engine.py's double."""
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.model = "local-model"
        self._json_object_supported = None

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.calls.append(messages)
        kind, val = self.script[len(self.calls) - 1]
        if kind == "err":
            raise val
        return val


class FakeDelivery:
    def __init__(self):
        self.sent = []

    def send(self, envelope):
        self.sent.append(envelope)
        return True


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "a.db"))
    yield s
    s.close()


def make_engine(store, llm, dlv, clock, cb_fails=2):
    return Engine(store=store, llm=llm, delivery=dlv,
                  budget_s=45.0, per_attempt_s=20.0, delivery_budget_s=3.0, clock=clock,
                  cb_fails=cb_fails, cb_window_s=300, cb_cooldown_s=60)


def test_retryable_failures_trip_circuit_and_next_alert_fails_fast(store):
    store.persist("k1", RAW)
    clk = FakeClock()
    llm = FakeLLM([("err", LLMError("5xx", retryable=True)),
                   ("err", LLMError("5xx", retryable=True))])
    dlv = FakeDelivery()
    eng = make_engine(store, llm, dlv, clk)
    out = eng.process("k1", ALERT, RAW)
    assert out == "raw"
    assert eng.breaker.state == "open"
    # Next alert: the circuit is open -> zero LLM calls, and the fail-safe
    # invariant still holds (raw + marker, store marked delivered_raw).
    store.persist("k2", RAW)
    llm.calls.clear()
    out2 = eng.process("k2", ALERT, RAW)
    assert out2 == "raw"
    assert len(llm.calls) == 0
    assert store.get_status("k2") == "delivered_raw"
    assert dlv.sent[1].detail.startswith(RAW_FALLBACK_MARKER)


def test_circuit_recovers_via_half_open_probe(store):
    store.persist("k1", RAW)
    clk = FakeClock()
    llm = FakeLLM([("err", LLMError("5xx", retryable=True)),
                   ("err", LLMError("5xx", retryable=True)),
                   ("ok", VALID)])
    dlv = FakeDelivery()
    eng = make_engine(store, llm, dlv, clk)
    assert eng.process("k1", ALERT, RAW) == "raw"
    assert eng.breaker.state == "open"
    clk.advance(61)  # cooldown elapses -> next call is the half-open probe
    store.persist("k2", RAW)
    out = eng.process("k2", ALERT, RAW)
    assert out == "enriched"
    assert eng.breaker.state == "closed"


def test_success_resets_failure_count(store):
    store.persist("k1", RAW)
    clk = FakeClock()
    llm = FakeLLM([("err", LLMError("5xx", retryable=True)), ("ok", VALID)])
    dlv = FakeDelivery()
    eng = make_engine(store, llm, dlv, clk)
    assert eng.process("k1", ALERT, RAW) == "enriched"
    assert eng.breaker.state == "closed"
    assert eng.breaker.failure_count == 0  # the retryable hit was cleared by success


def test_non_retryable_failures_never_trip(store):
    clk = FakeClock()
    llm = FakeLLM([("err", LLMError("400", retryable=False))])
    dlv = FakeDelivery()
    eng = make_engine(store, llm, dlv, clk)
    for i in range(2, 9):
        store.persist(f"k{i}", RAW)
        assert eng.process(f"k{i}", ALERT, RAW) == "raw"
    assert eng.breaker.state == "closed"


def test_hard_timeout_never_trips(store):
    # Timeouts are ambiguous (the request may have succeeded server-side) and
    # are deliberately excluded from the breaker's failure accounting.
    clk = FakeClock()
    llm = FakeLLM([("err", TimeoutError())])
    dlv = FakeDelivery()
    eng = make_engine(store, llm, dlv, clk)
    for i in range(2, 7):
        store.persist(f"k{i}", RAW)
        assert eng.process(f"k{i}", ALERT, RAW) == "raw"
    assert eng.breaker.state == "closed"