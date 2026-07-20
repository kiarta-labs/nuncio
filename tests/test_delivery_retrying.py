"""Generic bounded-retry wrapper. Tests `Retrying` wrapping a fake
DeliveryAdapter, since retry behavior lives in this shared wrapper rather
than in any single adapter."""
from nuncio.delivery.retrying import Retrying


class FakeAdapter:
    """Returns queued outcomes in order; records calls. An outcome of
    'raise' simulates a channel/connection exception."""
    name = "fake"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def send(self, title, body, severity="unknown"):
        self.calls.append((title, body, severity))
        o = self.outcomes[len(self.calls) - 1]
        if o == "raise":
            raise ConnectionError("channel down")
        return o


def make(outcomes):
    slept = []
    a = FakeAdapter(outcomes)
    r = Retrying(a, retries=3, sleep=slept.append, backoff=0.5)
    return r, a, slept


def test_send_success_first_try():
    r, a, slept = make([True])
    assert r.send("title", "hello") is True
    assert len(a.calls) == 1
    assert slept == []  # no backoff needed


def test_send_succeeds_after_transient_failures():
    r, a, slept = make([False, False, True])
    assert r.send("title", "hello") is True
    assert len(a.calls) == 3
    assert len(slept) == 2  # slept between the 3 attempts


def test_send_retries_on_adapter_exception():
    r, a, slept = make(["raise", True])
    assert r.send("title", "hello") is True
    assert len(a.calls) == 2


def test_send_returns_false_after_exhausting_retries():
    r, a, slept = make([False, False, False, False])  # retries=3 -> 4 attempts, all fail
    assert r.send("title", "hello") is False
    assert len(a.calls) == 4


def test_send_passes_title_body_severity_through():
    r, a, slept = make([True])
    r.send("the title", "the body", "critical")
    title, body, severity = a.calls[0]
    assert title == "the title" and body == "the body" and severity == "critical"


def test_name_reflects_wrapped_adapter():
    r, a, slept = make([True])
    assert r.name == "fake"


def test_durable_reflects_wrapped_adapter():
    # Dispatch/Fanout read `.durable` off the Retrying wrapper (never the
    # wrapped adapter directly), so the wrapper must proxy it transparently
    # or a non-durable sink like stdout silently loses its guard.
    durable_adapter = FakeAdapter([True])
    durable_adapter.durable = True
    non_durable_adapter = FakeAdapter([True])
    non_durable_adapter.durable = False
    no_attr_adapter = FakeAdapter([True])

    assert Retrying(durable_adapter).durable is True
    assert Retrying(non_durable_adapter).durable is False
    assert Retrying(no_attr_adapter).durable is True  # default, same as getattr(..., True)
