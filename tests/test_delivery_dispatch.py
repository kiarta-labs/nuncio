"""`Dispatch`: per-channel brief/full rendering, any-success, per-channel
exception isolation, verbosity overrides, and **kw forwarding through
Retrying."""
from nuncio.delivery import Dispatch, BRIEF, FULL
from nuncio.delivery.retrying import Retrying
from nuncio.delivery.stdout import Stdout
from nuncio.envelope import Envelope
from nuncio.render import RAW_FALLBACK_MARKER


def make_envelope(marker=False, summary="short summary", detail=None, severity="critical",
                   host="host01", service="db"):
    if detail is None:
        detail = f"{summary}\n\n--- Raw alert:\nraw text here"
    if marker:
        detail = RAW_FALLBACK_MARKER + "\n" + detail
    return Envelope(
        severity=severity, host=host, service=service,
        headline=f"CRIT · {host}/{service} — {summary}",
        summary=summary, detail=detail, detail_html=None,
        notify_type="5", marker=marker,
    )


class RecordingAdapter:
    def __init__(self, name, result=True, raises=False):
        self.name = name
        self.result = result
        self.raises = raises
        self.calls = []

    def send(self, title, body, severity="unknown", **kw):
        self.calls.append({"title": title, "body": body, "severity": severity, **kw})
        if self.raises:
            raise RuntimeError("channel exploded")
        return self.result


def test_brief_renders_headline_title_and_truncated_summary():
    a = RecordingAdapter("ntfy")
    d = Dispatch([("ntfy", a, BRIEF)])
    env = make_envelope(summary="short summary")
    assert d.send(env) is True
    call = a.calls[0]
    assert call["title"] == env.headline
    assert call["body"] == "short summary"


def test_full_renders_headline_title_and_complete_detail():
    a = RecordingAdapter("email")
    d = Dispatch([("email", a, FULL)])
    env = make_envelope()
    assert d.send(env) is True
    call = a.calls[0]
    assert call["title"] == env.headline
    assert call["body"] == env.detail


def test_brief_body_truncated_to_120_chars():
    a = RecordingAdapter("ntfy")
    d = Dispatch([("ntfy", a, BRIEF)])
    env = make_envelope(summary="x" * 500)
    d.send(env)
    body = a.calls[0]["body"]
    assert len(body) <= 120
    assert body.endswith("…")


def test_any_success_across_channels():
    a = RecordingAdapter("a", result=False)
    b = RecordingAdapter("b", result=True)
    d = Dispatch([("a", a, FULL), ("b", b, FULL)])
    assert d.send(make_envelope()) is True


def test_all_fail_is_failure():
    a = RecordingAdapter("a", result=False)
    b = RecordingAdapter("b", result=False)
    d = Dispatch([("a", a, FULL), ("b", b, FULL)])
    assert d.send(make_envelope()) is False


def test_per_channel_exception_is_isolated():
    boom = RecordingAdapter("boom", raises=True)
    ok = RecordingAdapter("ok", result=True)
    d = Dispatch([("boom", boom, FULL), ("ok", ok, FULL)])
    assert d.send(make_envelope()) is True


def test_send_never_raises_even_on_totally_broken_envelope():
    a = RecordingAdapter("a", result=True)
    d = Dispatch([("a", a, FULL)])
    assert d.send(None) is False  # degrades to False, does not raise


def test_returns_bool_type():
    a = RecordingAdapter("a", result=True)
    d = Dispatch([("a", a, FULL)])
    assert isinstance(d.send(make_envelope()), bool)


def test_verbosity_filter_only_full():
    brief_chan = RecordingAdapter("brief")
    full_chan = RecordingAdapter("full")
    d = Dispatch([("brief", brief_chan, BRIEF), ("full", full_chan, FULL)])
    d.send_full(make_envelope())
    assert full_chan.calls and not brief_chan.calls


def test_verbosity_filter_only_brief():
    brief_chan = RecordingAdapter("brief")
    full_chan = RecordingAdapter("full")
    d = Dispatch([("brief", brief_chan, BRIEF), ("full", full_chan, FULL)])
    d.send_brief(make_envelope())
    assert brief_chan.calls and not full_chan.calls


def test_has_verbosity():
    a = RecordingAdapter("a")
    d = Dispatch([("a", a, BRIEF)])
    assert d.has_verbosity(BRIEF) is True
    assert d.has_verbosity(FULL) is False


def test_on_failure_callback_invoked_per_failed_channel():
    failed = []
    a = RecordingAdapter("a", result=False)
    b = RecordingAdapter("b", result=True)
    d = Dispatch([("a", a, FULL), ("b", b, FULL)], on_failure=failed.append)
    d.send(make_envelope())
    assert failed == ["a"]


def test_dispatch_survives_on_failure_callback_raising():
    a = RecordingAdapter("a", result=False)

    def boom(_name):
        raise RuntimeError("callback broke")

    d = Dispatch([("a", a, FULL)], on_failure=boom)
    assert d.send(make_envelope()) is False  # the callback's own failure doesn't mask the real result


def test_dispatch_send_survives_an_exception_iterating_channels():
    class ExplodingChannels:
        """`self.channels` normally a plain list -- something that raises
        mid-iteration (rather than a single adapter's .send()) exercises
        Dispatch.send()'s OUTER exception guard, not the per-channel one."""
        def __iter__(self):
            raise RuntimeError("channel list broke")

    d = Dispatch([("a", RecordingAdapter("a"), FULL)])
    d.channels = ExplodingChannels()
    assert d.send(make_envelope()) is False  # degrades to "nothing sent", never raises


# --- marker survives truncation (A-T9) ---

def test_marker_survives_truncation_brief_and_full():
    env = make_envelope(marker=True, summary="x" * 5000, detail="x" * 5000)
    brief_chan = RecordingAdapter("brief")
    full_chan = RecordingAdapter("full")
    d = Dispatch([("brief", brief_chan, BRIEF), ("full", full_chan, FULL)])
    d.send(env)
    assert brief_chan.calls[0]["body"].startswith(RAW_FALLBACK_MARKER)
    assert full_chan.calls[0]["body"].startswith(RAW_FALLBACK_MARKER)


# --- **kw forwarding through Retrying ---

def test_kw_forwarded_through_retrying():
    a = RecordingAdapter("a", result=True)
    r = Retrying(a, retries=0, sleep=lambda s: None)
    d = Dispatch([("a", r, FULL)])
    env = make_envelope()
    d.send(env)
    call = a.calls[0]
    assert call["headline"] == env.headline
    assert call["summary"] == env.summary
    assert call["host"] == env.host
    assert call["service"] == env.service


# --- durable-channel-aware success (Envelope dispatcher) ---

class DurableRecordingAdapter(RecordingAdapter):
    durable = True


def test_dispatch_stdout_plus_failing_durable_channel_is_not_delivered():
    stdout = Stdout()
    apprise = DurableRecordingAdapter("apprise", result=False)
    d = Dispatch([("stdout", stdout, FULL), ("apprise", apprise, FULL)])
    assert d.send(make_envelope()) is False


def test_dispatch_stdout_only_zero_config_default_still_delivers():
    stdout = Stdout()
    d = Dispatch([("stdout", stdout, FULL)])
    assert d.send(make_envelope()) is True


def test_dispatch_durable_channel_alone_success_is_delivered():
    apprise = DurableRecordingAdapter("apprise", result=True)
    d = Dispatch([("apprise", apprise, FULL)])
    assert d.send(make_envelope()) is True


def test_dispatch_stdout_and_durable_channel_both_succeed_is_delivered():
    stdout = Stdout()
    apprise = DurableRecordingAdapter("apprise", result=True)
    d = Dispatch([("stdout", stdout, FULL), ("apprise", apprise, FULL)])
    assert d.send(make_envelope()) is True


def test_dispatch_retrying_wrapped_stdout_does_not_mask_failing_durable_channel():
    # config.build_delivery wraps EVERY adapter (including non-durable
    # stdout) in Retrying before handing it to Dispatch. If Retrying doesn't
    # proxy .durable, the wrapped stdout reads back as durable=True (the
    # getattr default) and its "success" wrongly masks the real channel's
    # failure below.
    stdout = Retrying(Stdout(), retries=0, sleep=lambda s: None)
    slack = Retrying(DurableRecordingAdapter("slack", result=False), retries=0, sleep=lambda s: None)
    d = Dispatch([("stdout", stdout, FULL), ("slack", slack, FULL)])
    assert d.send(make_envelope()) is False
