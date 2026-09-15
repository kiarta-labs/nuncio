"""C4 ingest-storm mode: rate trip, cheap-path downgrade, metrics, decay."""
from nuncio.server import App, Metrics
from nuncio.store import Store


class FakeEngine:
    def __init__(self, mode="enriched"):
        self.mode = mode
        self.depth = "full"

    def process(self, *a, **k):
        return "enriched"

    def _deliver_raw(self, *a, **k):
        return "raw"


def _app(tmp_path, **kw):
    store = Store(str(tmp_path / "d.db"))
    now = [1000.0]
    params = dict(budget_s=45.0, full_budget_s=90.0, concurrency=0, queue_max=50,
                  clock=lambda: now[0], wall_clock=lambda: now[0],
                  maint_interval=3600.0, digest_window_s=0.0)
    params.update(kw)
    a = App(FakeEngine(), store, Metrics(), **params)
    return a, store, now


def _payload(service, severity, i):
    return {"host": "svr", "service": service, "message": f"ms {i}",
            "severity": severity}


def _drain_depths(a):
    depths = []
    while True:
        try:
            item = a.q.get_nowait()
        except Exception:
            return depths
        depths.append((item[3].get("severity"), item[8]))
        a.q.task_done()


def test_storm_trips_on_rate_burst(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        assert not a.in_storm()
        for i in range(App._STORM_RATE):
            a.ingest("generic", _payload("s", "warning", i))
        assert a.in_storm() is True
        assert a.storm_state["entered"] == 1
        assert "nuncio_storm_entered_total 1" in a.metrics.render()
        assert "nuncio_storm_active 1" in a.metrics.render()
    finally:
        store.close()


def test_storm_downgrades_non_critical_only(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        for i in range(App._STORM_RATE):
            a.ingest("generic", _payload("s", "warning", i))
        assert a.in_storm()
        a.ingest("generic", _payload("c", "critical", 99))
        a.ingest("generic", _payload("w", "warning", 100))
        a.ingest("generic", _payload("o", "ok", 101))
        a.ingest("generic", _payload("u", "info", 102))
        depths = dict(_drain_depths(a))
        assert depths["critical"] == "full"  # criticals never downgraded
        assert depths["warning"] == "low"
        assert depths["ok"] == "low"
        assert depths["info"] == "low"
    finally:
        store.close()


def test_storm_decays_after_active_window(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        for i in range(App._STORM_RATE):
            a.ingest("generic", _payload("s", "warning", i))
        assert a.in_storm()
        now[0] += App._STORM_ACTIVE_S + 1.0
        assert a.in_storm() is False
        assert a.storm_state["active"] is False
        assert "nuncio_storm_active 0" in a.metrics.render()
        a.ingest("generic", _payload("w", "warning", 999))
        # cheap path no longer forced -> warning back to full depth
        depths = dict(_drain_depths(a))
        assert depths["warning"] == "full"
    finally:
        store.close()


def test_storm_rate_window_is_rolling(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        # 70% of threshold within the 60s window is not a storm (drop older)
        for i in range(App._STORM_RATE - 1):
            a.ingest("generic", _payload("s", "warning", i))
        assert not a.in_storm()
        now[0] += 120.0  # let the 60s window roll
        a.ingest("generic", _payload("s", "warning", 88))
        assert not a.in_storm()  # only 1 remained in-window
        for i in range(100, 100 + App._STORM_RATE):
            a.ingest("generic", _payload("s", "warning", i))
        assert a.in_storm() is True
    finally:
        store.close()