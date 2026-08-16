"""Generic bounded-retry wrapper. Tests `Retrying` wrapping a fake
DeliveryAdapter, since retry behavior lives in this shared wrapper rather
than in any single adapter."""
import logging

from nuncio.delivery import SendTimeout
from nuncio.delivery.retrying import Retrying


class FakeAdapter:
    """Returns queued outcomes in order; records calls. An outcome of
    'raise' simulates a channel/connection exception; 'timeout' simulates
    a SendTimeout (the POST may have already reached the far end)."""
    name = "fake"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def send(self, title, body, severity="unknown"):
        self.calls.append((title, body, severity))
        o = self.outcomes[len(self.calls) - 1]
        if o == "raise":
            raise ConnectionError("channel down")
        if o == "timeout":
            raise SendTimeout("timed out")
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


def test_send_timeout_is_not_retried():
    # A timeout means the POST may have already succeeded on the far end
    # (non-idempotent) -- retrying it risks a duplicate push, so Retrying
    # must give up immediately rather than treat it like a transient
    # connection failure.
    r, a, slept = make(["timeout"])
    assert r.send("title", "hello") is False
    assert len(a.calls) == 1
    assert slept == []


def test_send_timeout_after_other_failures_still_stops_immediately():
    r, a, slept = make([False, "timeout", True])
    assert r.send("title", "hello") is False
    assert len(a.calls) == 2  # never reaches the 3rd (would-succeed) attempt


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


def test_each_failed_attempt_logs_debug_and_exhaustion_warns(caplog):
    # F1: delivery failures must be visible per-attempt (DEBUG) and at
    # exhaustion (WARNING) instead of the historical silent `except: pass`.
    r, a, slept = make([False, False, False, False])  # 4 attempts, all fail
    with caplog.at_level(logging.DEBUG, logger="nuncio.delivery.retrying"):
        assert r.send("title", "hello") is False
    records = [rec for rec in caplog.records if rec.name == "nuncio.delivery.retrying"]
    assert sum(1 for rec in records if rec.levelno == logging.DEBUG) == 4
    assert any(rec.levelno == logging.WARNING and "exhausted" in rec.getMessage()
               for rec in records)


def test_raised_channel_error_logs_debug_with_error_details(caplog):
    r, a, slept = make(["raise", True])
    with caplog.at_level(logging.DEBUG, logger="nuncio.delivery.retrying"):
        assert r.send("title", "hello") is True
    records = [rec for rec in caplog.records if rec.name == "nuncio.delivery.retrying"]
    debug = [rec for rec in records if rec.levelno == logging.DEBUG]
    assert len(debug) == 1
    assert "ConnectionError" in debug[0].getMessage()


def test_send_timeout_logs_warning_without_debug_attempts(caplog):
    r, a, slept = make(["timeout"])
    with caplog.at_level(logging.DEBUG, logger="nuncio.delivery.retrying"):
        assert r.send("title", "hello") is False
    records = [rec for rec in caplog.records if rec.name == "nuncio.delivery.retrying"]
    assert sum(1 for rec in records if rec.levelno == logging.DEBUG) == 0
    assert any(rec.levelno == logging.WARNING and "SendTimeout" in rec.getMessage()
               for rec in records)
