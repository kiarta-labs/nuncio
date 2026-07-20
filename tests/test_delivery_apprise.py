"""Apprise delivery adapter. Verifies the transport-shape contract (payload =
{"body", "title"}) and that a 204 response (Apprise's "no destination
configured" signal) is correctly treated as delivery failure, not success —
trusting it as success would silently black-hole every alert. Covers a
single delivery attempt; retry behavior lives in Retrying, tested
separately."""
from nuncio.delivery.apprise import Apprise


class Transport:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.calls = []

    def __call__(self, url, payload, timeout=10):
        self.calls.append((url, payload, timeout))
        return self.statuses[len(self.calls) - 1]


def make(statuses, url="http://apprise:8000/notify/alerts"):
    t = Transport(statuses)
    a = Apprise({"url": url}, transport=t)
    return a, t


def test_send_success():
    a, t = make([200])
    assert a.send("title", "hello") is True
    assert len(t.calls) == 1


def test_send_failure_on_5xx():
    a, t = make([500])
    assert a.send("title", "hello") is False


def test_204_no_destination_is_treated_as_failure():
    # Apprise returns 204 when the config key has no destination -> nothing
    # pushed. Trusting it as success would silently black-hole every alert.
    a, t = make([204])
    assert a.send("title", "hello") is False


def test_payload_carries_title_and_body():
    a, t = make([200])
    a.send("the title", "the message body")
    _, payload, _ = t.calls[0]
    assert payload == {"body": "the message body", "title": "the title"}


def test_no_url_configured_fails_closed_without_transport_call():
    a, t = make([200], url=None)
    assert a.send("title", "hello") is False
    assert t.calls == []


def test_transport_exception_propagates_for_retrying_to_catch():
    def boom(url, payload, timeout=10):
        raise ConnectionError("down")
    a = Apprise({"url": "http://x"}, transport=boom)
    import pytest
    with pytest.raises(ConnectionError):
        a.send("title", "hello")
