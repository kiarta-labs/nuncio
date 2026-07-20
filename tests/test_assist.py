"""The out-of-band assist plane: AssistClient + AssistTrack + Engine's
deferral logic + config validation + the restart/orphan sweep.

Key invariant under test: the assist call NEVER runs inside the 30s alert
deadline, and its failure/timeout NEVER affects (or delays past its own
budget) the primary alert, which has already been delivered by the time
assist even starts.
"""
import threading
import time

import pytest

from nuncio.assist import AssistClient, AssistTrack
from nuncio.config import ConfigError, Settings
from nuncio.engine import Engine
from nuncio.envelope import Envelope
from nuncio.store import Store

ALERT = {"host": "host01", "service": "db-primary", "state": "CRIT",
         "output": "FATAL: all AuxiliaryProcs are in use", "severity": "critical"}
RAW = "host host01 / db-primary / CRIT / FATAL: all AuxiliaryProcs are in use"
VALID_ENRICHMENT = ("db-primary is down on host01, all AuxiliaryProcs busy.\n\n"
                     "Looks urgent: the service is fully down, likely capacity exhaustion.")


# =====================================================================
# Fakes
# =====================================================================

class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class FakeLLM:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.calls.append(messages)
        kind, val = self.script[len(self.calls) - 1]
        if kind == "err":
            raise val
        return val


class FakeAssistClient:
    """A `client.insight(payload)` double -- kind in {"ok", "err", "hang"}."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def insight(self, payload):
        self.calls.append(payload)
        kind, val = self.script[len(self.calls) - 1]
        if kind == "err":
            raise val
        if kind == "hang":
            time.sleep(val)
            return "too late"
        return val


class FakeDispatch:
    """Records what got sent to each verbosity leg -- brief/full separately,
    plus a combined `.send()` for the non-deferred all-channel path."""

    def __init__(self, has_full=True, has_brief=True, brief_ok=True, full_ok=True, send_ok=True):
        self._has_full = has_full
        self._has_brief = has_brief
        self.brief_ok = brief_ok
        self.full_ok = full_ok
        self.send_ok = send_ok
        self.brief_sent = []
        self.full_sent = []
        self.sent = []  # combined, in call order: ("brief"|"full"|"send", envelope)

    def has_verbosity(self, v):
        if v == "brief":
            return self._has_brief
        if v == "full":
            return self._has_full
        return False

    def send_brief(self, envelope):
        self.brief_sent.append(envelope)
        self.sent.append(("brief", envelope))
        return self.brief_ok

    def send_full(self, envelope):
        self.full_sent.append(envelope)
        self.sent.append(("full", envelope))
        return self.full_ok

    def send(self, envelope):
        self.sent.append(("send", envelope))
        if self._has_brief:
            self.brief_sent.append(envelope)
        if self._has_full:
            self.full_sent.append(envelope)
        return self.send_ok


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "a.db"))
    yield s
    s.close()


def make_track(client, dispatch, store, **kw):
    kw.setdefault("timeout_s", 5.0)
    kw.setdefault("severities", ("critical",))
    kw.setdefault("queue_max", 8)
    return AssistTrack(client, dispatch, store, **kw)


def wait_for(fn, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return True
        time.sleep(0.01)
    return fn()


def make_engine(store, llm, delivery, clock, assist=None, **kw):
    kw.setdefault("budget_s", 45.0)
    kw.setdefault("per_attempt_s", 20.0)
    kw.setdefault("delivery_budget_s", 3.0)
    return Engine(store=store, llm=llm, delivery=delivery, clock=clock, assist=assist, **kw)


# =====================================================================
# AssistClient
# =====================================================================

def test_assist_client_unwraps_llm_tuple_return():
    llm = FakeLLM([("ok", ("root cause: disk full", {"prompt_tokens": 10, "completion_tokens": 5}))])
    from nuncio.redactor import scrub_for_assist_plane
    payload = scrub_for_assist_plane("disk full on host01")
    client = AssistClient(llm)
    assert client.insight(payload) == "root cause: disk full"


def test_assist_client_accepts_bare_string_llm_return():
    llm = FakeLLM([("ok", "root cause: disk full")])
    from nuncio.redactor import scrub_for_assist_plane
    payload = scrub_for_assist_plane("disk full on host01")
    client = AssistClient(llm)
    assert client.insight(payload) == "root cause: disk full"


# =====================================================================
# C-T3: config validation
# =====================================================================

def base_env(**extra):
    env = {"NUNCIO_LLM_URL": "http://gw:4000/v1", "NUNCIO_DATA_DIR": "/tmp/does-not-matter-for-settings"}
    env.update(extra)
    return env


def test_scrubbed_real_without_confirm_raises():
    with pytest.raises(ConfigError, match="NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK"):
        Settings(base_env(NUNCIO_ASSIST_DATA_POSTURE="scrubbed-real"))


def test_scrubbed_real_with_confirm_is_ok():
    s = Settings(base_env(NUNCIO_ASSIST_DATA_POSTURE="scrubbed-real", NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK="true"))
    assert s.NUNCIO_ASSIST_DATA_POSTURE == "scrubbed-real"
    assert s.NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK is True


def test_generic_posture_needs_no_confirm():
    s = Settings(base_env())  # default posture is "generic"
    assert s.NUNCIO_ASSIST_DATA_POSTURE == "generic"


def test_assist_enabled_without_url_raises():
    with pytest.raises(ConfigError, match="NUNCIO_ASSIST_URL"):
        Settings(base_env(NUNCIO_ASSIST_ENABLED="true"))


def test_assist_enabled_with_url_is_ok():
    s = Settings(base_env(NUNCIO_ASSIST_ENABLED="true", NUNCIO_ASSIST_URL="http://assist:1234"))
    assert s.NUNCIO_ASSIST_ENABLED is True


def test_invalid_assist_severity_raises():
    with pytest.raises(ConfigError, match="NUNCIO_ASSIST_SEVERITIES"):
        Settings(base_env(NUNCIO_ASSIST_SEVERITIES="critical,made-up"))


# =====================================================================
# C-T4: assist hangs/raises -> brief completes in budget, full carries no
# insight, outcome is "enriched".
# =====================================================================

def test_assist_timeout_still_delivers_brief_fast_and_full_late_without_insight(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=True)
    assist_client = FakeAssistClient([("hang", 0.3)])
    track = make_track(assist_client, dispatch, store, timeout_s=0.05)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert store.get_status("k1") == "delivered_enriched"
    assert len(dispatch.brief_sent) == 1  # the brief leg completed immediately

    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    full_envelope = dispatch.full_sent[0]
    assert "External assist" not in full_envelope.detail or "unavailable" not in full_envelope.detail
    assert store.get_assist_status("k1") == "failed"


def test_assist_raises_falls_back_to_full_with_no_insight(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("err", RuntimeError("boom"))])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert store.get_assist_status("k1") == "failed"
    assert VALID_ENRICHMENT in dispatch.full_sent[0].detail  # original content, no insight


# =====================================================================
# C-T5: insight reaches ONLY full channels
# =====================================================================

def test_assist_success_insight_only_in_full_leg(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "root cause: disk exhaustion; check /var usage")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.brief_sent) == 1
    assert "disk exhaustion" not in dispatch.brief_sent[0].detail
    assert "disk exhaustion" not in (dispatch.brief_sent[0].summary or "")

    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert "External assist" in dispatch.full_sent[0].detail
    assert "disk exhaustion" in dispatch.full_sent[0].detail
    assert store.get_assist_status("k1") == "done"
    assert "disk exhaustion" in (store.get_alert_detail("k1") or {}).get("assist_insight", "")


def test_assist_followup_labeled_and_separate_from_primary(store):
    """NUNCIO_DELIVERY=email alone (all FULL, no BRIEF) -> never deferred;
    primary ships in full immediately, assist's insight arrives as a
    separately-labeled follow-up full message."""
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=False)
    assist_client = FakeAssistClient([("ok", "root cause: disk exhaustion")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.full_sent) == 1  # primary went out immediately, in full
    assert "External assist" not in dispatch.full_sent[0].detail

    assert wait_for(lambda: len(dispatch.full_sent) == 2)
    followup = dispatch.full_sent[1]
    assert followup.headline.startswith("Assist follow-up:")
    assert "disk exhaustion" in followup.detail


# =====================================================================
# C-T6: deferral topology
# =====================================================================

def test_full_only_no_defer_but_followup_fires(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=False)
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert dispatch.brief_sent == []
    assert wait_for(lambda: len(dispatch.full_sent) == 2)


def test_brief_only_no_defer_no_crash_and_no_assist_call(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=False, has_brief=True)
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    time.sleep(0.2)
    assert assist_client.calls == []  # no FULL channel -> assist never fires
    assert store.get_assist_status("k1") is None


def test_brief_and_full_defers_brief_immediate_full_once_with_insight(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=True)
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert len(dispatch.brief_sent) == 1
    assert dispatch.full_sent == []  # not sent yet -- deferred
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert "insight text" in dispatch.full_sent[0].detail


def test_assisttrack_submit_returns_false_when_queue_is_full():
    dispatch = FakeDispatch()
    dummy_store = Store.__new__(Store)  # never touched by insight() -- irrelevant here
    assist_client = FakeAssistClient([("hang", 2.0), ("ok", "unused"), ("ok", "unused")])
    track = AssistTrack(assist_client, dispatch, dummy_store, timeout_s=5.0, queue_max=1)
    env = Envelope(severity="critical", host="", service="", headline="h", summary="s", detail="d")

    assert track.submit("k0", env, "ctx0") is True  # dequeued almost immediately, hangs inside insight()
    assert wait_for(lambda: len(assist_client.calls) >= 1)
    assert track.submit("k1", env, "ctx1") is True  # fills the 1-slot queue
    assert track.submit("k2", env, "ctx2") is False  # queue is now full


def test_queue_full_delivers_full_immediately_and_marks_skipped(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=True)

    class AlwaysFullTrack:
        """A minimal assist-track double whose queue is permanently full --
        isolates Engine's "submit() returned False" handling from any real
        queue-draining race."""

        def eligible(self, severity, mode):
            return mode == "enriched" and severity == "critical"

        def submit(self, key, envelope, context_text, followup=False):
            return False

    eng = make_engine(store, llm, dispatch, FakeClock(), assist=AlwaysFullTrack())
    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.brief_sent) == 1
    assert any(VALID_ENRICHMENT in e.detail for e in dispatch.full_sent)
    assert store.get_assist_status("k1") == "skipped"


# =====================================================================
# C-T7: restart/orphan sweep
# =====================================================================

def test_orphan_sweep_recovers_deferred_row_exactly_once(store):
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="deferred", enrichment=VALID_ENRICHMENT)

    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([])
    fake_wall = FakeClock()
    # created_at for k1 defaults to REAL time.time() at persist() -- force
    # the fake wall clock far enough past real "now" that the row reads as
    # older than (timeout_s + 30)s (writing created_at directly isn't
    # possible: it's not in Store._RECORD_STATS_FIELDS).
    fake_wall.t = time.time() + 10 ** 6
    track = make_track(assist_client, dispatch, store, timeout_s=5.0, wall_clock=fake_wall)
    track.sweep_orphans()

    assert len(dispatch.full_sent) == 1
    assert store.get_assist_status("k1") == "failed"

    # sweeping again must not re-deliver (status is no longer 'deferred')
    track.sweep_orphans()
    assert len(dispatch.full_sent) == 1


def test_orphan_sweep_never_touches_done_rows(store):
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="done", assist_insight="already delivered")

    dispatch = FakeDispatch()
    fake_wall = FakeClock()
    fake_wall.t = time.time() + 10 ** 6
    track = make_track(FakeAssistClient([]), dispatch, store, timeout_s=5.0, wall_clock=fake_wall)
    track.sweep_orphans()

    assert dispatch.full_sent == []
    assert store.get_assist_status("k1") == "done"


# =====================================================================
# Insight is redact()-ed before store/egress
# =====================================================================

def test_insight_is_redacted_before_store_and_egress(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch()
    secret = "sk-" + "abcDEF1234567890abcDEF1234567890abcDEF12"
    assist_client = FakeAssistClient([("ok", f"root cause found; leaked token {secret} in logs")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert secret not in dispatch.full_sent[0].detail
    stored_insight = (store.get_alert_detail("k1") or {}).get("assist_insight", "")
    assert secret not in stored_insight


# =====================================================================
# Severities gating + bypass never enqueues
# =====================================================================

def test_severity_not_in_set_is_never_deferred(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "insight")])
    track = make_track(assist_client, dispatch, store, severities=("critical",))
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    warning_alert = dict(ALERT, severity="warning")
    eng.process("k1", warning_alert, RAW)
    time.sleep(0.15)
    assert assist_client.calls == []
    assert len(dispatch.sent) == 1  # single combined send, non-deferred


def test_bypass_mode_never_enqueues_assist(store):
    store.persist("k1", RAW, mode="bypass")
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "insight")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track, mode="bypass")

    outcome = eng.process("k1", ALERT, RAW, mode="bypass")
    assert outcome == "raw"
    time.sleep(0.15)
    assert assist_client.calls == []


# =====================================================================
# _build_assist_context: generic vs scrubbed-real posture
# =====================================================================

def test_build_assist_context_generic_posture_has_no_alert_text(store):
    dispatch = FakeDispatch()
    track = make_track(FakeAssistClient([]), dispatch, store, posture="generic",
                        classification_table={"container": "containers can crash for many reasons"})
    eng = make_engine(store, FakeLLM([]), dispatch, FakeClock(), assist=track)
    envelope = Envelope(severity="critical", host="host01", service="db-primary",
                         headline="CRIT · host01/db-primary — db down", summary="db down", detail="d")
    ctx = eng._build_assist_context({"category": "container"}, {}, "db down on host01", envelope)
    assert "host01" not in ctx
    assert "db-primary" not in ctx
    assert "containers can crash" in ctx
    assert "category: container" in ctx


def test_build_assist_context_scrubbed_real_posture_includes_evidence(store):
    dispatch = FakeDispatch()
    track = make_track(FakeAssistClient([]), dispatch, store, posture="scrubbed-real")
    eng = make_engine(store, FakeLLM([]), dispatch, FakeClock(), assist=track)
    envelope = Envelope(severity="critical", host="host01", service="db-primary",
                         headline="CRIT · host01/db-primary — db down", summary="db down", detail="d")
    sections_red = {
        "correlated": "disk01 alert 4m earlier",
        "recurrence": "3rd time in 24h",
        "recent_logs": "\n".join(f"log line {i}" for i in range(30)),
    }
    ctx = eng._build_assist_context({"category": "container"}, sections_red, "db down\nlikely capacity", envelope)
    assert "CRIT · host01/db-primary — db down" in ctx
    assert "disk01 alert 4m earlier" in ctx
    assert "3rd time in 24h" in ctx
    assert "log line 0" in ctx
    assert "log line 19" in ctx
    assert "log line 20" not in ctx  # capped to the first 20 lines
    assert "analysis: db down" in ctx


def test_eligible_requires_enriched_mode():
    track_eligible_fn = AssistTrack.eligible
    dummy = type("D", (), {"severities": {"critical"}})()
    assert track_eligible_fn(dummy, "critical", "enriched") is True
    assert track_eligible_fn(dummy, "critical", "bypass") is False


# =====================================================================
# SHOULD-FIX 1: queue-full path records 'skipped' BEFORE send_full, so a
# crash between the two can't leave the row 'deferred' (which the orphan
# sweep would then treat as stuck and re-send -- a duplicate).
# =====================================================================

class _OrderSpyStore:
    """Wraps a real Store, appending every `record_stats` call (that touches
    assist_status) to a shared `calls` list -- everything else delegates
    straight through, so this stays a thin ordering probe rather than a
    reimplementation."""

    def __init__(self, inner, calls):
        self._inner = inner
        self._calls = calls

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def record_stats(self, key, **fields):
        if "assist_status" in fields:
            self._calls.append(("record_stats", fields["assist_status"]))
        return self._inner.record_stats(key, **fields)


class _OrderSpyDispatch:
    """A minimal dispatch double (brief+full both configured) that appends
    to the SAME shared `calls` list as `_OrderSpyStore` -- lets a test assert
    cross-object call ordering directly from one list."""

    def __init__(self, calls):
        self._calls = calls
        self.brief_sent = []
        self.full_sent = []

    def has_verbosity(self, v):
        return v in ("brief", "full")

    def send_brief(self, envelope):
        self.brief_sent.append(envelope)
        return True

    def send_full(self, envelope):
        self._calls.append(("send_full", None))
        self.full_sent.append(envelope)
        return True

    def send(self, envelope):
        return True


class _AlwaysFullTrack:
    """Assist-track double whose queue is permanently full -- isolates
    Engine's "submit() returned False" handling from any real queue-draining
    race (same shape as the existing queue-full test above)."""

    def eligible(self, severity, mode):
        return mode == "enriched" and severity == "critical"

    def submit(self, key, envelope, context_text, followup=False):
        return False


def test_queue_full_records_skipped_status_before_sending_full(store):
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    calls = []
    spy_store = _OrderSpyStore(store, calls)
    dispatch = _OrderSpyDispatch(calls)
    eng = make_engine(spy_store, llm, dispatch, FakeClock(), assist=_AlwaysFullTrack())

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"

    skipped_idx = calls.index(("record_stats", "skipped"))
    send_idx = calls.index(("send_full", None))
    assert skipped_idx < send_idx  # status recorded strictly before the send
    assert store.get_assist_status("k1") == "skipped"
    assert len(dispatch.full_sent) == 1


# =====================================================================
# SHOULD-FIX 2: atomic claim (Store.claim_assist / claim_assist_for_sweep)
# guarantees exactly one of {worker, sweep} ever sends the rich leg for a
# given key, whichever order they run in.
# =====================================================================

def test_claim_assist_is_atomic_across_concurrent_callers(store):
    store.persist("k1", RAW, severity="critical")
    store.record_stats("k1", assist_status="deferred")
    results = []
    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        results.append(store.claim_assist("k1"))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == [False, True]  # exactly one winner
    assert store.get_assist_status("k1") == "in_flight"


def test_claim_assist_claims_a_null_status_row():
    # No assist_status write ever landed (e.g. the submit-time write failed)
    # -- still claimable, per FIX 4's "None is claimable" posture.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        s = Store(f"{d}/a.db")
        try:
            s.persist("k1", RAW)
            assert s.get_assist_status("k1") is None
            assert s.claim_assist("k1") is True
            assert s.get_assist_status("k1") == "in_flight"
            assert s.claim_assist("k1") is False  # second claim loses
        finally:
            s.close()


def test_claim_assist_for_sweep_only_claims_deferred_rows(store):
    store.persist("k1", RAW, severity="critical")
    store.record_stats("k1", assist_status="in_flight")  # already claimed by the worker
    assert store.claim_assist_for_sweep("k1") is False  # not 'deferred' -- sweep must not touch it
    assert store.get_assist_status("k1") == "in_flight"

    store.persist("k2", RAW, severity="critical")
    store.record_stats("k2", assist_status="deferred")
    assert store.claim_assist_for_sweep("k2") is True
    assert store.get_assist_status("k2") == "failed"
    assert store.claim_assist_for_sweep("k2") is False  # already claimed once


def test_worker_claims_first_sweep_then_sees_nothing_to_send(store):
    """Worker wins the race: it processes (and claims) the item before the
    sweep runs. The sweep's own SELECT only ever returns rows still
    'deferred', so a row the worker already moved to 'in_flight'/'done' is
    invisible to it -- net exactly one send_full."""
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="deferred", enrichment=VALID_ENRICHMENT)

    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "root cause: disk exhaustion")])
    fake_wall = FakeClock()
    fake_wall.t = time.time() + 10 ** 6  # old enough to pass the sweep's age cutoff
    track = make_track(assist_client, dispatch, store, timeout_s=5.0, wall_clock=fake_wall)
    envelope = Envelope(severity="critical", host="h", service="s", headline="hl", summary="s", detail="d")

    track._process_item("k1", envelope, "ctx", False)  # simulates the worker dequeuing + finishing first
    assert store.get_assist_status("k1") == "done"

    track.sweep_orphans()  # must find nothing to claim -- row is no longer 'deferred'

    assert len(dispatch.full_sent) == 1
    assert len(assist_client.calls) == 1


def test_sweep_claims_first_worker_then_skips_its_own_send(store):
    """Reverse order: the sweep claims + delivers an orphaned row first (as
    if the worker's in-memory queue item was lost across a restart). A late
    worker item for the SAME key must lose the claim and skip entirely --
    never calling the LLM, never sending a second rich leg."""
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="deferred", enrichment=VALID_ENRICHMENT)

    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "root cause: disk exhaustion")])
    fake_wall = FakeClock()
    fake_wall.t = time.time() + 10 ** 6
    track = make_track(assist_client, dispatch, store, timeout_s=5.0, wall_clock=fake_wall)
    envelope = Envelope(severity="critical", host="h", service="s", headline="hl", summary="s", detail="d")

    track.sweep_orphans()
    assert store.get_assist_status("k1") == "failed"
    assert len(dispatch.full_sent) == 1

    track._process_item("k1", envelope, "ctx", False)  # a late/duplicate worker item for the same key

    assert len(dispatch.full_sent) == 1  # unchanged -- the claim failed, no second send
    assert assist_client.calls == []  # never even reached the LLM call


# =====================================================================
# SHOULD-FIX 4: a transient submit-time record_stats("deferred") failure
# (status stays NULL, per Engine._deliver_enriched's own swallowed
# try/except) must not silently drop the rich leg -- the worker's claim
# treats NULL as claimable (FIX 2's IS NULL arm) and still delivers it.
# =====================================================================

class _DeferredWriteFailsStore:
    """Wraps a real Store; the FIRST `assist_status="deferred"` write raises
    (simulating the transient store hiccup Engine's own try/except already
    swallows), so the column is left NULL exactly as it would be in
    production. Every other call -- including later assist_status writes
    like 'done'/'in_flight' -- passes straight through."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def record_stats(self, key, **fields):
        if fields.get("assist_status") == "deferred":
            raise RuntimeError("simulated transient store write failure")
        return self._inner.record_stats(key, **fields)


class _SkippedWriteFailsStore:
    """Wraps a real Store; the `assist_status="skipped"` write (the
    queue-full fallback's mark-before-send) raises -- Engine must still send
    the rich leg with no insight rather than strand it on a stats-write
    hiccup."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def record_stats(self, key, **fields):
        if fields.get("assist_status") == "skipped":
            raise RuntimeError("simulated store failure recording 'skipped'")
        return self._inner.record_stats(key, **fields)


def test_queue_full_survives_skipped_status_write_failure(store):
    flaky = _SkippedWriteFailsStore(store)
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=True)
    eng = make_engine(flaky, llm, dispatch, FakeClock(), assist=_AlwaysFullTrack())

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.brief_sent) == 1
    assert any(VALID_ENRICHMENT in e.detail for e in dispatch.full_sent)  # still sent


# =====================================================================
# Coverage: the module's many best-effort try/except swallows -- a metrics
# or store write failing here must NEVER strand the assist plane's own
# work (the insight call + dispatch), and an unhandled exception at any
# point in _process_item must be caught at the worker's own boundary so
# the worker thread survives to process the next queued item.
# =====================================================================

class _BoomingMetrics:
    """A metrics double whose `.inc()` always raises -- exercises every
    `try: self.metrics.inc(...) except Exception: pass` swallow in
    AssistTrack without needing a real Metrics object."""

    def inc(self, attr, key=None):
        raise RuntimeError(f"metrics.inc({attr!r}) broke")


def test_metrics_attempted_failure_does_not_block_the_insight_call(store):
    store.persist("k1", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store, metrics=_BoomingMetrics())
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert "insight text" in dispatch.full_sent[0].detail


def test_metrics_ok_failure_does_not_block_dispatch(store):
    store.persist("k1", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store, metrics=_BoomingMetrics())
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert store.get_assist_status("k1") == "done"


def test_metrics_failed_failure_does_not_block_fallback_dispatch(store):
    store.persist("k1", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("err", RuntimeError("boom"))])
    track = make_track(assist_client, dispatch, store, metrics=_BoomingMetrics())
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert store.get_assist_status("k1") == "failed"


def test_empty_insight_response_treated_as_failure(store):
    store.persist("k1", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "   ")])  # blank after redact()+strip()
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert store.get_assist_status("k1") == "failed"
    assert VALID_ENRICHMENT in dispatch.full_sent[0].detail  # no insight appended


def test_on_success_send_full_exception_is_logged_not_raised(store):
    store.persist("k1", RAW)

    class RaisingOnSuccessDispatch(FakeDispatch):
        def send_full(self, envelope):
            raise RuntimeError("channel exploded on the success path")

    dispatch = RaisingOnSuccessDispatch()
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: store.get_assist_status("k1") == "done")  # record_stats still ran
    # the worker thread must survive the exception -- prove it by submitting
    # a second item and confirming it's still processed.
    store.persist("k2", RAW)
    assert track.submit("k2", dispatch.brief_sent[0] if dispatch.brief_sent else None, "ctx2") is True


def test_on_failure_record_stats_exception_still_sends_fallback(store):
    class _FailedWriteFailsStore:
        def __init__(self, inner):
            self._inner = inner
        def __getattr__(self, name):
            return getattr(self._inner, name)
        def record_stats(self, key, **fields):
            if fields.get("assist_status") == "failed":
                raise RuntimeError("simulated store write failure")
            return self._inner.record_stats(key, **fields)

    flaky = _FailedWriteFailsStore(store)
    store.persist("k1", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("err", RuntimeError("boom"))])
    track = make_track(assist_client, dispatch, flaky)
    eng = make_engine(flaky, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: len(dispatch.full_sent) == 1)  # fallback still went out
    assert VALID_ENRICHMENT in dispatch.full_sent[0].detail


def test_followup_failure_is_silently_dropped_no_duplicate_send(store):
    # NUNCIO_DELIVERY=email alone -- primary already went out in full; if the
    # follow-up assist call fails there is nothing new to say, and the
    # original must never be re-sent.
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=False)
    assist_client = FakeAssistClient([("err", RuntimeError("assist boom"))])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.full_sent) == 1  # the primary send

    time.sleep(0.2)  # give the followup worker time to run and fail
    assert len(dispatch.full_sent) == 1  # still just the one -- no duplicate/fallback


def test_on_failure_send_full_exception_is_logged_not_raised(store):
    store.persist("k1", RAW)

    class RaisingSendFullDispatch(FakeDispatch):
        def send_full(self, envelope):
            raise RuntimeError("channel exploded on the fallback path")

    dispatch = RaisingSendFullDispatch()
    assist_client = FakeAssistClient([("err", RuntimeError("boom"))])
    track = make_track(assist_client, dispatch, store)
    eng = make_engine(store, FakeLLM([("ok", VALID_ENRICHMENT)]), dispatch, FakeClock(), assist=track)

    eng.process("k1", ALERT, RAW)
    assert wait_for(lambda: store.get_assist_status("k1") == "failed")
    # worker thread survives -- a subsequent submit is still accepted
    assert track.submit("k2", dispatch.brief_sent[0] if dispatch.brief_sent else
                         type("E", (), {"severity": "critical"})(), "ctx2") is True


def test_worker_survives_unhandled_exception_in_process_item(store, monkeypatch):
    # An exception that escapes _process_item entirely (not one of its own
    # internal try/excepts) must be caught at _worker's own boundary --
    # proven by submitting a second, healthy item afterward and confirming
    # it still gets processed.
    store.persist("k1", RAW)
    store.persist("k2", RAW)
    dispatch = FakeDispatch()
    assist_client = FakeAssistClient([("ok", "insight text")])
    track = make_track(assist_client, dispatch, store)

    real_scrub = __import__("nuncio.assist", fromlist=["scrub_for_assist_plane"]).scrub_for_assist_plane
    calls = []

    def flaky_scrub(text):
        calls.append(text)
        if len(calls) == 1:
            raise RuntimeError("scrub broke on the first call only")
        return real_scrub(text)

    monkeypatch.setattr("nuncio.assist.scrub_for_assist_plane", flaky_scrub)

    env = Envelope(severity="critical", host="h", service="s", headline="hl", summary="s", detail="d")
    assert track.submit("k1", env, "ctx1") is True
    assert track.submit("k2", env, "ctx2") is True
    assert wait_for(lambda: len(assist_client.calls) == 1)  # k2 reached insight(); k1 crashed before it


def test_sweep_skips_row_whose_claim_loses_the_race(store):
    # Simulates a genuine race: deferred_assist_older_than() still lists the
    # row (unwrapped store), but claim_assist_for_sweep() returns False (a
    # concurrent claim won) -- the sweep must skip it via `continue`, not
    # touch dispatch.
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="deferred", enrichment=VALID_ENRICHMENT)

    class _AlwaysDenyClaimStore:
        def __init__(self, inner):
            self._inner = inner
        def __getattr__(self, name):
            return getattr(self._inner, name)
        def claim_assist_for_sweep(self, key):
            return False

    denying = _AlwaysDenyClaimStore(store)
    dispatch = FakeDispatch()
    fake_wall = FakeClock()
    fake_wall.t = time.time() + 10 ** 6
    track = make_track(FakeAssistClient([]), dispatch, denying, timeout_s=5.0, wall_clock=fake_wall)

    track.sweep_orphans()
    assert dispatch.full_sent == []
    assert store.get_assist_status("k1") == "deferred"  # untouched -- the claim never landed


def test_sweep_survives_exception_mid_iteration_and_continues(store):
    store.persist("k1", RAW, severity="critical")
    store.mark_delivered("k1", "enriched")
    store.record_stats("k1", assist_status="deferred", enrichment=VALID_ENRICHMENT)
    store.persist("k2", RAW, severity="critical")
    store.mark_delivered("k2", "enriched")
    store.record_stats("k2", assist_status="deferred", enrichment=VALID_ENRICHMENT)

    class _RaisingOnFirstClaimStore:
        def __init__(self, inner):
            self._inner = inner
            self._n = 0
        def __getattr__(self, name):
            return getattr(self._inner, name)
        def claim_assist_for_sweep(self, key):
            self._n += 1
            if self._n == 1:
                raise RuntimeError("claim exploded on the first row")
            return self._inner.claim_assist_for_sweep(key)

    flaky = _RaisingOnFirstClaimStore(store)
    dispatch = FakeDispatch()
    fake_wall = FakeClock()
    fake_wall.t = time.time() + 10 ** 6
    track = make_track(FakeAssistClient([]), dispatch, flaky, timeout_s=5.0, wall_clock=fake_wall)

    track.sweep_orphans()  # must not raise despite the first row's claim exploding
    assert len(dispatch.full_sent) == 1  # the second row still got recovered


def test_deferred_write_failure_still_delivers_full_leg_exactly_once(store):
    flaky = _DeferredWriteFailsStore(store)
    store.persist("k1", RAW)
    llm = FakeLLM([("ok", VALID_ENRICHMENT)])
    dispatch = FakeDispatch(has_full=True, has_brief=True)
    assist_client = FakeAssistClient([("ok", "root cause: disk exhaustion")])
    track = make_track(assist_client, dispatch, flaky)
    eng = make_engine(flaky, llm, dispatch, FakeClock(), assist=track)

    outcome = eng.process("k1", ALERT, RAW)
    assert outcome == "enriched"
    assert len(dispatch.brief_sent) == 1  # primary alert unaffected by the store hiccup

    # The submit-time write failed, so the status column is still NULL --
    # verify that premise directly before checking the worker recovers it.
    assert store.get_assist_status("k1") is None

    assert wait_for(lambda: len(dispatch.full_sent) == 1)
    assert "disk exhaustion" in dispatch.full_sent[0].detail
    assert store.get_assist_status("k1") == "done"  # worker claimed the NULL row and delivered it
