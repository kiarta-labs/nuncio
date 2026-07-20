"""Delivery-adapter registry + Fanout."""
import pytest

from nuncio import delivery
from nuncio.delivery import DeliveryAdapter
from nuncio.delivery.stdout import Stdout


def test_all_six_launch_adapters_registered():
    assert {"apprise", "ntfy", "telegram", "slack", "webhook", "stdout"} <= set(delivery.names())


def test_get_unknown_adapter_returns_none():
    assert delivery.get("totally-not-a-real-adapter") is None


def test_build_unknown_adapter_raises():
    with pytest.raises(KeyError):
        delivery.build("nonexistent", {})


def test_build_constructs_configured_instance():
    a = delivery.build("apprise", {"url": "http://x"})
    assert a.url == "http://x"


class _Chan:
    def __init__(self, name, result):
        self.name = name
        self.result = result
        self.sent = []

    def send(self, title, body, severity="unknown"):
        self.sent.append((title, body, severity))
        return self.result


def test_fanout_any_success_is_success():
    a = _Chan("a", False)
    b = _Chan("b", True)
    f = delivery.Fanout([("a", a), ("b", b)])
    assert f.send("t", "m") is True
    assert a.sent and b.sent


def test_fanout_all_fail_is_failure():
    a = _Chan("a", False)
    b = _Chan("b", False)
    f = delivery.Fanout([("a", a), ("b", b)])
    assert f.send("t", "m") is False


def test_fanout_reports_per_channel_failure():
    failed = []
    a = _Chan("a", False)
    b = _Chan("b", True)
    f = delivery.Fanout([("a", a), ("b", b)], on_failure=failed.append)
    f.send("t", "m")
    assert failed == ["a"]


def test_fanout_name_lists_channels():
    a = _Chan("a", True)
    b = _Chan("b", True)
    assert delivery.Fanout([("a", a), ("b", b)]).name == "fanout(a,b)"


def test_fanout_survives_a_channel_raising():
    class Boom:
        def send(self, *a, **k):
            raise RuntimeError("channel exploded")
    b = _Chan("b", True)
    f = delivery.Fanout([("boom", Boom()), ("b", b)])
    assert f.send("t", "m") is True  # the other channel still got it


def test_fanout_survives_on_failure_callback_raising():
    a = _Chan("a", False)

    def boom(_name):
        raise RuntimeError("callback broke")

    f = delivery.Fanout([("a", a)], on_failure=boom)
    assert f.send("t", "m") is False  # the callback's own failure doesn't mask the real result


# --- durable-channel-aware success (a non-durable diagnostic sink like
# stdout must never mask a real durable channel's failure) ---

def test_base_adapter_defaults_to_durable():
    assert DeliveryAdapter.durable is True


class _DurableChan:
    durable = True

    def __init__(self, name, result):
        self.name = name
        self.result = result

    def send(self, title, body, severity="unknown", **kw):
        return self.result


def test_fanout_stdout_plus_failing_durable_channel_is_not_delivered():
    # stdout (non-durable) "succeeds" but the real channel (apprise-like,
    # durable) fails -- overall must be False so the alert stays 'received'
    # for maintenance to retry the real channel, not silently marked
    # delivered.
    stdout = Stdout()
    apprise = _DurableChan("apprise", result=False)
    f = delivery.Fanout([("stdout", stdout), ("apprise", apprise)])
    assert f.send("t", "m") is False


def test_fanout_stdout_only_zero_config_default_still_delivers():
    stdout = Stdout()
    f = delivery.Fanout([("stdout", stdout)])
    assert f.send("t", "m") is True


def test_fanout_durable_channel_alone_success_is_delivered():
    apprise = _DurableChan("apprise", result=True)
    f = delivery.Fanout([("apprise", apprise)])
    assert f.send("t", "m") is True


def test_fanout_stdout_and_durable_channel_both_succeed_is_delivered():
    stdout = Stdout()
    apprise = _DurableChan("apprise", result=True)
    f = delivery.Fanout([("stdout", stdout), ("apprise", apprise)])
    assert f.send("t", "m") is True


def test_fanout_retrying_wrapped_adapters_preserve_durable_rule():
    # Same Retrying-must-proxy-durable gap as Dispatch, but for Fanout
    # (config.build_delivery wraps every adapter in Retrying regardless of
    # which composition path -- Dispatch or Fanout -- consumes it).
    from nuncio.delivery.retrying import Retrying

    stdout = Retrying(Stdout(), retries=0, sleep=lambda s: None)
    apprise = Retrying(_DurableChan("apprise", result=False), retries=0, sleep=lambda s: None)
    f = delivery.Fanout([("stdout", stdout), ("apprise", apprise)])
    assert f.send("t", "m") is False


# --- delivery-transport scheme allowlist (consistency with
# clients/http.py's require_http_url; see delivery/require_http_url) ------

def test_require_http_url_allows_http_and_https_only():
    delivery.require_http_url("http://x")
    delivery.require_http_url("https://x")
    with pytest.raises(ValueError):
        delivery.require_http_url("file:///tmp/x")
    with pytest.raises(ValueError):
        delivery.require_http_url("ftp://x")
    with pytest.raises(ValueError):
        delivery.require_http_url("")
    with pytest.raises(ValueError):
        delivery.require_http_url(None)
