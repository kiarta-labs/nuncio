"""Q2 burst resilience: severity-priority queue, ok cheap path, digest."""
import time

from nuncio.server import App, Metrics
from nuncio.store import Store


class FakeEngine:
    def __init__(self, mode="enriched"):
        self.mode = mode

    def process(self, *a, **k):
        return "enriched"

    def _deliver_raw(self, *a, **k):
        return "raw"


def _app(tmp_path, **kw):
    store = Store(str(tmp_path / "d.db"))
    now = [1000.0]
    params = dict(budget_s=45.0, concurrency=0, queue_max=20,
                  clock=lambda: 1000.0, wall_clock=lambda: now[0],
                  maint_interval=3600.0, digest_window_s=600.0)
    mode = kw.pop("mode", "enriched")
    params.update(kw)
    a = App(FakeEngine(mode), store, Metrics(), **params)
    return a, store, now


def _info(host, service, message):
    return {"host": host, "service": service, "message": message, "severity": "info"}


def test_priority_queue_orders_critical_first(tmp_path):
    a, store, _now = _app(tmp_path, digest_window_s=0.0)
    try:
        a.ingest("generic", {"host": "svr", "service": "s-ok", "message": "m", "severity": "ok"})
        a.ingest("generic", {"host": "svr", "service": "s-info", "message": "m", "severity": "info"})
        a.ingest("generic", {"host": "svr", "service": "s-crit", "message": "m", "severity": "critical"})
        got = []
        while True:
            try:
                prio, _seq, _key, alert, _raw, _raw_full, _dl, _mode, _depth, _trusted, _prov = a.q.get_nowait()
            except Exception:
                break
            got.append((prio, alert["service"]))
        assert [s for _, s in got] == ["s-crit", "s-info", "s-ok"]
        assert [p for p, _ in got] == [0, 2, 3]
    finally:
        store.close()


def test_ok_severity_forces_low_depth(tmp_path):
    a, store, _now = _app(tmp_path, digest_window_s=0.0)
    try:
        a.ingest("generic", {"host": "svr", "service": "s-ok", "message": "m", "severity": "ok"})
        item = a.q.get_nowait()
        assert item[8] == "low"
    finally:
        store.close()


def test_digest_holds_repeats_and_emits_one_digest(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        assert a.ingest("generic", _info("svr", "svc-a", "Updated alpha to 1")) == 200
        assert a.ingest("generic", _info("svr", "svc-b", "Updated beta to 2")) == 200
        assert a.ingest("generic", _info("svr", "svc-c", "Updated gamma to 3")) == 200
        assert a.q.qsize() == 1  # only the first notice queued
        assert a.metrics.digested == 2
        statuses = [r["status"] for r in a.store.rows_since(0)]
        assert statuses.count("delivered_digested") == 2
        # held rows are invisible to the maintenance safety net
        assert a.store.undelivered_older_than(now[0] + 99999) == []
        # expire the window -> exactly one digest alert ingested
        now[0] += 601.0
        a._sweep_digests()
        assert a.q.qsize() == 2
        assert "nuncio_digested_total 2" in a.metrics.render()
        digests = [r for r in a.store.rows_since(0) if "coalesced" in (r["payload"] or "")]
        assert len(digests) == 1
        assert digests[0]["severity"] == "info"
        assert "svc-b" in digests[0]["payload"] or "beta" in digests[0]["payload"]
    finally:
        store.close()


def test_digest_never_holds_critical_or_warning(tmp_path):
    a, store, _now = _app(tmp_path)
    try:
        a.ingest("generic", {"host": "svr", "service": "s", "message": "m1", "severity": "critical"})
        a.ingest("generic", {"host": "svr", "service": "s", "message": "m2", "severity": "critical"})
        a.ingest("generic", {"host": "svr", "service": "s", "message": "m3", "severity": "warning"})
        assert a.q.qsize() == 3
        assert a.metrics.digested == 0
    finally:
        store.close()


def test_digest_disabled_window_passes_everything_through(tmp_path):
    a, store, _now = _app(tmp_path, digest_window_s=0.0)
    try:
        a.ingest("generic", _info("svr", "svc-a", "Updated alpha to 1"))
        a.ingest("generic", _info("svr", "svc-b", "Updated beta to 2"))
        assert a.q.qsize() == 2
        assert a.metrics.digested == 0
    finally:
        store.close()


def test_digest_restart_fails_open_with_fresh_window(tmp_path):
    a, store, _now = _app(tmp_path)
    try:
        a.ingest("generic", _info("svr", "svc-a", "Updated alpha to 1"))
        a.ingest("generic", _info("svr", "svc-b", "Updated beta to 2"))
        assert a.q.qsize() == 1
        # simulate a restart: in-memory windows are gone, held rows stay terminal
        a._digest.clear()
        assert a.ingest("generic", _info("svr", "svc-c", "Updated gamma to 3")) == 200
        assert a.q.qsize() == 2  # fresh window -> delivered immediately, never held
    finally:
        store.close()


def test_digest_skips_bypass_mode(tmp_path):
    a, store, _now = _app(tmp_path, mode="bypass")
    try:
        a.ingest("generic", _info("svr", "svc-a", "Updated alpha to 1"))
        a.ingest("generic", _info("svr", "svc-b", "Updated beta to 2"))
        assert a.q.qsize() == 2
        assert a.metrics.digested == 0
    finally:
        store.close()


def test_mark_digested_is_cas_and_terminal(tmp_path):
    store = Store(str(tmp_path / "d.db"))
    try:
        assert store.persist("k1", "payload") is True
        assert store.mark_digested("k1") is True
        assert store.get_status("k1") == "delivered_digested"
        assert store.mark_digested("k1") is False  # already moved on
        assert store.undelivered_older_than(time.time() + 99999) == []
        assert store.purge_delivered(time.time() + 99999) == 1  # retention covers it
    finally:
        store.close()


def test_digest_window_live_swaps_via_apply_changes(tmp_path):
    from nuncio import config
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path)}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        assert app.digest_window_s == 0.0  # digest OFF by default (opt-in)
        result = config.apply_changes(app, {"NUNCIO_DIGEST_WINDOW_S": 60})
        assert result["applied"] == ["NUNCIO_DIGEST_WINDOW_S"]
        assert app.digest_window_s == 60.0
    finally:
        app.store.close()
