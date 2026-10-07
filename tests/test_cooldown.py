"""Delivery-side repeat cooldown (NUNCIO_COOLDOWN_S): the identity-keyed gate
that collapses repeats of ONE alert episode which the per-event idempotency key
cannot (OpenObserve recomputes its query-window start on every evaluation, so
`key` changes by construction -- see nuncio/sources/openobserve.py).

Tested with 0 workers so the queue is inspectable and there are no thread races,
and with an injected wall clock shared by the Store's created_at and
App.wall_clock so every window boundary is deterministic (never a real sleep).
"""
import pytest

from nuncio.model import ParsedAlert
from nuncio.server import App, Metrics
from nuncio.sources import openobserve as o2_adapter
from nuncio.store import Store

IDENTITY = "unifi-inform-failures/syslog"
KEY1 = "openobserve:unifi-inform-failures/syslog/2026-10-07T09:05:08"
KEY2 = "openobserve:unifi-inform-failures/syslog/2026-10-07T09:10:08"
KEY3 = "openobserve:unifi-inform-failures/syslog/2026-10-07T09:15:08"
CKEY = f"openobserve:{IDENTITY}"


def k(window):
    """The adapter's key for a given O2 start_time/window value."""
    return f"openobserve:unifi-inform-failures/syslog/{window}"


class FakeEngine:
    def __init__(self):
        self.raw_delivered = []
        self.mode = "enriched"

    def _deliver_raw(self, key, raw):
        self.raw_delivered.append(key)
        return "raw"

    def process(self, *a, **k):
        return "enriched"

    def drain_raw(self):
        return 0


def o2_payload(start_time, alert_name="unifi-inform-failures", stream="syslog"):
    """The recommended O2 destination template (see the adapter docstring)."""
    return {
        "alert_name": alert_name, "stream": stream,
        "start_time": start_time, "severity": "warning",
        "message": ">= threshold 10, matched 15 in 60",
    }


def notify(pid, host="host01", service="sonarr"):
    """A checkmk-shaped payload -- a source that declares NO identity."""
    return {
        "NOTIFY_WHAT": "SERVICE", "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
        "NOTIFY_HOSTNAME": host, "NOTIFY_SERVICEDESC": service,
        "NOTIFY_SERVICESTATE": "CRIT", "NOTIFY_SERVICEOUTPUT": "boom",
        "NOTIFY_SERVICEPROBLEMID": str(pid),
    }


def build_app(tmp_path, cooldown_s=1800.0, name="c.db"):
    """An App whose Store created_at and App.wall_clock share one mutable
    clock, returned alongside the clock so a test can advance time."""
    now = [1000.0]
    clock = lambda: now[0]  # noqa: E731
    store = Store(str(tmp_path / name), clock=clock)
    eng = FakeEngine()
    app = App(eng, store, Metrics(), budget_s=45.0, concurrency=0, queue_max=8,
              clock=lambda: 500.0, wall_clock=clock, maint_interval=3600.0,
              cooldown_s=cooldown_s)
    app._engine = eng
    return app, now


# --- the adapter's identity contract -------------------------------------

def test_openobserve_declares_a_bucket_free_identity():
    parsed = o2_adapter.OpenObserve().parse(o2_payload("2026-10-07T09:05:08"), {})
    assert len(parsed) == 1
    assert parsed[0].identity == IDENTITY
    assert parsed[0].key == KEY1  # the idempotency/display key is unchanged


def test_identity_is_stable_while_the_window_start_moves():
    a = o2_adapter.OpenObserve().parse(o2_payload("2026-10-07T09:05:08"), {})[0]
    b = o2_adapter.OpenObserve().parse(o2_payload("2026-10-07T09:10:08"), {})[0]
    assert a.key != b.key            # by construction -- the whole defect
    assert a.identity == b.identity  # ...and this is what makes it fixable
    assert "09:05:08" not in a.identity


def test_identity_is_present_when_the_template_omits_start_time():
    parsed = o2_adapter.OpenObserve().parse(o2_payload(""), {})
    assert parsed[0].identity == IDENTITY


def test_parsed_alert_identity_defaults_to_empty():
    pa = ParsedAlert(key="k", alert={}, raw_text="r")
    assert pa.identity == ""


# --- the gate: first pages, repeat does not ------------------------------

def test_first_pages_and_the_repeat_of_one_episode_is_suppressed(tmp_path):
    app, now = build_app(tmp_path)
    try:
        assert app.ingest("openobserve", o2_payload("2026-10-07T09:05:08")) == 200
        assert app.q.qsize() == 1
        assert app.store.get_status(KEY1) == "received"
        assert app.store.get_alert_detail(KEY1)["cooldown_key"] == CKEY

        now[0] += 300.0  # 5 min later: same unresolved episode, new key
        assert app.ingest("openobserve", o2_payload("2026-10-07T09:10:08")) == 200

        assert app.store.get_status(KEY2) == "delivered_suppressed_cooldown"
        assert app.store.get_alert_detail(KEY2)["outcome"] == "suppressed_cooldown"
        assert app.q.qsize() == 1                      # never queued -> no LLM spend
        assert app.metrics.suppressed_cooldown == 1
        assert app.metrics.ingested == 2               # persisted + countable
    finally:
        app.store.close()


def test_suppression_is_a_rate_bound_not_a_mute(tmp_path):
    app, now = build_app(tmp_path)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 300.0
        app.ingest("openobserve", o2_payload("W2"))    # suppressed
        now[0] += 1801.0                               # past the 1800 s window
        app.ingest("openobserve", o2_payload("W3"))
        assert app.store.get_status("openobserve:unifi-inform-failures/syslog/W2") == \
            "delivered_suppressed_cooldown"
        assert app.store.get_status("openobserve:unifi-inform-failures/syslog/W3") == "received"
        assert app.q.qsize() == 2                      # W1 + W3, one per window
        assert app.metrics.suppressed_cooldown == 1
    finally:
        app.store.close()


def test_the_clock_is_anchored_at_ingest_not_delivery(tmp_path):
    """A repeat arriving while the first is still queued (never delivered, so
    `outcome` is NULL) must still be suppressed -- otherwise the bound leaks
    for exactly as long as enrichment takes."""
    app, now = build_app(tmp_path)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        assert app.store.get_alert_detail(k("W1"))["outcome"] is None  # still queued
        now[0] += 10.0
        app.ingest("openobserve", o2_payload("W2"))
        assert app.store.get_status(k("W2")) == "delivered_suppressed_cooldown"
        assert app.q.qsize() == 1
    finally:
        app.store.close()


def test_two_alerts_of_one_identity_in_the_same_batch(tmp_path, monkeypatch):
    from nuncio import sources
    first = ParsedAlert(key=KEY1, alert={"host": "-", "service": "x"}, raw_text="r1",
                        identity=IDENTITY)
    second = ParsedAlert(key=KEY2, alert={"host": "-", "service": "x"}, raw_text="r2",
                         identity=IDENTITY)
    # patch the REGISTERED adapter instance (the registry instantiates one at
    # import) -- a fresh OpenObserve() would not be the one the App looks up.
    monkeypatch.setattr(sources.get("openobserve"), "parse",
                        lambda payload, headers: [first, second])
    app, _now = build_app(tmp_path)
    try:
        assert app.ingest("openobserve", {}) == 200
        assert app.q.qsize() == 1
        assert app.store.get_status(KEY2) == "delivered_suppressed_cooldown"
    finally:
        app.store.close()


def test_a_different_identity_is_never_collapsed(tmp_path):
    app, now = build_app(tmp_path)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 10.0
        app.ingest("openobserve", o2_payload("W1", alert_name="other-alert"))
        now[0] += 10.0
        app.ingest("openobserve", o2_payload("W1", stream="docker"))
        assert app.q.qsize() == 3          # three distinct identities
        assert app.metrics.suppressed_cooldown == 0
    finally:
        app.store.close()


# --- escape hatches and fail-open ---------------------------------------

def test_zero_disables_the_cooldown(tmp_path):
    app, now = build_app(tmp_path, cooldown_s=0.0)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 1.0
        app.ingest("openobserve", o2_payload("W2"))
        assert app.q.qsize() == 2
        assert app.metrics.suppressed_cooldown == 0
    finally:
        app.store.close()


def test_a_source_without_an_identity_is_never_suppressed(tmp_path):
    app, now = build_app(tmp_path)
    try:
        app.ingest("checkmk", notify(1))
        now[0] += 1.0
        app.ingest("checkmk", notify(2))
        assert app.q.qsize() == 2
        assert app.metrics.suppressed_cooldown == 0
        # ...and no cooldown_key is written at all for such a source
        assert app.store.get_alert_detail("checkmk:host01/sonarr/2/PROBLEM/1")["cooldown_key"] is None
    finally:
        app.store.close()


def test_the_gate_fails_open_when_the_clock_lookup_explodes(tmp_path, monkeypatch):
    app, now = build_app(tmp_path)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 10.0

        def boom(*a, **k):
            raise RuntimeError("store gone")

        monkeypatch.setattr(app.store, "cooldown_last", boom)
        assert app.ingest("openobserve", o2_payload("W2")) == 200
        assert app.q.qsize() == 2          # delivered, never dropped
        assert app.metrics.suppressed_cooldown == 0
    finally:
        app.store.close()


def test_the_gate_fails_open_when_the_cas_is_lost(tmp_path, monkeypatch):
    app, now = build_app(tmp_path)
    try:
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 10.0
        monkeypatch.setattr(app.store, "mark_suppressed_cooldown", lambda key: False)
        app.ingest("openobserve", o2_payload("W2"))
        assert app.q.qsize() == 2          # the row moved on -> normal path
        assert app.metrics.suppressed_cooldown == 0
    finally:
        app.store.close()


# --- telemetry ----------------------------------------------------------

def test_metrics_render_includes_the_suppressed_counter(tmp_path):
    app, now = build_app(tmp_path)
    try:
        assert "nuncio_suppressed_cooldown_total 0" in app.metrics.render()
        app.ingest("openobserve", o2_payload("W1"))
        now[0] += 10.0
        app.ingest("openobserve", o2_payload("W2"))
        assert "nuncio_suppressed_cooldown_total 1" in app.metrics.render()
    finally:
        app.store.close()


# --- store primitives ---------------------------------------------------

def test_cooldown_last_is_none_without_a_row(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    try:
        assert s.cooldown_last(CKEY) is None
    finally:
        s.close()


def test_cooldown_last_returns_the_newest_non_suppressed_cell(tmp_path):
    now = [1000.0]
    s = Store(str(tmp_path / "s.db"), clock=lambda: now[0])
    try:
        s.persist("k1", "p", cooldown_key=CKEY)
        now[0] += 10.0
        s.persist("k2", "p", cooldown_key=CKEY)
        assert s.cooldown_last(CKEY) == 1010.0
        # excluding the newest (it is the row being decided) falls back to k1
        assert s.cooldown_last(CKEY, exclude_key="k2") == 1000.0
    finally:
        s.close()


def test_cooldown_last_ignores_suppressed_rows(tmp_path):
    """Anti-self-extension: a suppressed repeat must NOT refresh the clock, or
    a steady stream of repeats would suppress itself forever."""
    now = [1000.0]
    s = Store(str(tmp_path / "s.db"), clock=lambda: now[0])
    try:
        s.persist("k1", "p", cooldown_key=CKEY)
        now[0] += 10.0
        s.persist("k2", "p", cooldown_key=CKEY)
        assert s.mark_suppressed_cooldown("k2") is True
        s.record_stats("k2", outcome="suppressed_cooldown")
        assert s.cooldown_last(CKEY) == 1000.0     # k2 did not move the clock
        now[0] += 10.0
        s.persist("k3", "p", cooldown_key=CKEY)    # a third repeat
        assert s.cooldown_last(CKEY, exclude_key="k3") == 1000.0
    finally:
        s.close()


def test_cooldown_last_is_scoped_to_one_identity(tmp_path):
    s = Store(str(tmp_path / "s.db"), clock=lambda: 1000.0)
    try:
        s.persist("k1", "p", cooldown_key="openobserve:a/syslog")
        assert s.cooldown_last("openobserve:b/syslog") is None
    finally:
        s.close()


def test_mark_suppressed_cooldown_is_a_cas_from_received(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    try:
        s.persist("k1", "p")
        assert s.mark_suppressed_cooldown("k1") is True
        assert s.get_status("k1") == "delivered_suppressed_cooldown"
        assert s.mark_suppressed_cooldown("k1") is False   # already terminal
    finally:
        s.close()


def test_suppressed_row_is_terminal_and_reaped(tmp_path):
    now = [1000.0]
    s = Store(str(tmp_path / "s.db"), clock=lambda: now[0])
    try:
        s.persist("k1", "p")
        s.mark_suppressed_cooldown("k1")
        assert s.undelivered() == []                       # invisible to the drain
        assert s.undelivered_older_than(2000.0) == []      # ...to the safety net
        now[0] = 5000.0
        assert s.purge_delivered(4000.0) == 1              # 'delivered_%' -> reaped
    finally:
        s.close()


def test_cooldown_key_is_persist_only_not_record_stats_writable():
    assert "cooldown_key" not in Store._RECORD_STATS_FIELDS
    assert "cooldown_key" in Store._STATS_COLUMNS


def test_cooldown_key_column_migrates_additively_on_a_legacy_db(tmp_path):
    """A DB file written by 0.5.0: the new column AND its index must appear
    without touching existing rows (the index is created after the ALTER loop,
    so a legacy file cannot raise 'no such column')."""
    import sqlite3
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE alerts (key TEXT PRIMARY KEY, payload TEXT NOT NULL, "
        "status TEXT NOT NULL, seq INTEGER, created_at REAL, bundle TEXT)"
    )
    conn.execute(
        "INSERT INTO alerts (key, payload, status, seq, created_at) VALUES (?, ?, ?, ?, ?)",
        ("legacy-key", "legacy payload", "delivered_enriched", 1, 1000.0),
    )
    conn.commit()
    conn.close()

    s = Store(path)
    try:
        row = s.get_alert_detail("legacy-key")
        assert row["payload"] == "legacy payload"   # existing data untouched
        assert row["cooldown_key"] is None          # additive, nullable
        idx = {r[0] for r in s._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_alerts_cooldown" in idx
        assert s.cooldown_last("anything") is None
    finally:
        s.close()
