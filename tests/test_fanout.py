"""Fan-out digest: one rule alarming across many objects collapses to the
first K delivered individually plus one summary per window."""
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
    store = Store(str(tmp_path / "f.db"))
    now = [1000.0]
    params = dict(budget_s=45.0, concurrency=0, queue_max=200,
                  clock=lambda: 1000.0, wall_clock=lambda: now[0],
                  maint_interval=3600.0,
                  fanout_window_s=120.0, fanout_k=3)
    mode = kw.pop("mode", "enriched")
    params.update(kw)
    a = App(FakeEngine(mode), store, Metrics(), **params)
    return a, store, now


def _grafana(rule, status, instances, severity="warning"):
    alerts = []
    for inst in instances:
        labels = {"alertname": rule, "instance": inst}
        if severity is not None:
            labels["severity"] = severity
        alerts.append({"status": status, "labels": labels,
                       "annotations": {"summary": f"{rule} on {inst}"},
                       "startsAt": "2026-10-18T10:52:53Z",
                       "fingerprint": f"{rule}-{status}-{inst}",
                       "values": {}})
    return {"status": status, "commonLabels": {"alertname": rule},
            "alerts": alerts, "groupLabels": {}, "truncatedAlerts": 0,
            "title": f"[{status.upper()}] {rule}"}


def _instances(prefix, n):
    return [f"{prefix}-{i:03d}" for i in range(n)]


def _summaries(store):
    return [r for r in store.rows_since(0) if "coalesced" in (r["payload"] or "")]


def test_103_alerts_three_webhooks_collapse(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        names = _instances("ctr", 103)
        assert a.ingest("grafana", _grafana("Container restart loop", "firing", names[:40])) == 200
        assert a.ingest("grafana", _grafana("Container restart loop", "firing", names[40:80])) == 200
        assert a.ingest("grafana", _grafana("Container restart loop", "firing", names[80:])) == 200
        # the first K went out individually; the other 100 are folded
        assert a.q.qsize() == 3
        assert a.metrics.digested == 100
        statuses = [r["status"] for r in store.rows_since(0)]
        assert statuses.count("delivered_digested") == 100
        # held rows stay invisible to the maintenance safety net
        assert store.undelivered_older_than(now[0] + 99999) == []
        # window closes -> exactly one summary queued on top of the K
        now[0] += 121.0
        a._sweep_fanouts()
        assert a.q.qsize() == 4
        assert a.metrics.fanout_summaries == 1
        sums = _summaries(store)
        assert len(sums) == 1
        assert "Container restart loop" in sums[0]["payload"]
        assert "x103" in sums[0]["payload"]
        assert "FIRING" in sums[0]["payload"]
        assert sums[0]["severity"] == "warning"
        assert "nuncio_fanout_summaries_total 1" in a.metrics.render()
    finally:
        store.close()


def test_mixed_rules_form_separate_groups(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        for rule in ("rule-A", "rule-B"):
            assert a.ingest("grafana", _grafana(rule, "firing", _instances(rule, 5))) == 200
        assert a.q.qsize() == 6          # K from each group, none shared
        assert a.metrics.digested == 4   # 2 folded per group
        now[0] += 121.0
        a._sweep_fanouts()
        assert a.metrics.fanout_summaries == 2
        assert a.q.qsize() == 8
    finally:
        store.close()


def test_firing_and_resolved_do_not_share_a_group(tmp_path):
    a, store, _now = _app(tmp_path)
    try:
        assert a.ingest("grafana", _grafana("rule-X", "firing", _instances("x", 5))) == 200
        assert a.ingest("grafana", _grafana("rule-X", "resolved", _instances("x", 5), severity=None)) == 200
        assert a.q.qsize() == 6   # K from EACH state group
        assert a.metrics.digested == 4
    finally:
        store.close()


def test_critical_never_held(tmp_path):
    a, store, _now = _app(tmp_path)
    try:
        assert a.ingest("grafana", _grafana("rule-C", "firing", _instances("c", 10), severity="critical")) == 200
        assert a.q.qsize() == 10
        assert a.metrics.digested == 0
        assert a.metrics.fanout_summaries == 0
    finally:
        store.close()


def test_resolved_storm_collapses(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        assert a.ingest("grafana", _grafana("rule-R", "resolved", _instances("r", 10), severity=None)) == 200
        # resolved alerts parse as severity ok and are eligible
        assert a.q.qsize() == 3
        assert a.metrics.digested == 7
        now[0] += 121.0
        a._sweep_fanouts()
        assert a.metrics.fanout_summaries == 1
        sums = _summaries(store)
        assert sums and sums[0]["severity"] == "ok"
        assert "RESOLVED" in sums[0]["payload"]
    finally:
        store.close()


def test_restart_mid_window_fails_open(tmp_path):
    a, store, now = _app(tmp_path)
    try:
        assert a.ingest("grafana", _grafana("rule-M", "firing", _instances("m", 10))) == 200
        assert a.q.qsize() == 3
        assert a.metrics.digested == 7
        # simulate a restart: open windows are gone, held rows stay terminal
        a._fanout.clear()
        assert a.ingest("grafana", _grafana("rule-M", "firing", _instances("n", 4))) == 200
        assert a.q.qsize() == 6          # fresh window -> its first K delivered
        assert a.metrics.digested == 8   # its 4th arrival folds into the fresh window
        now[0] += 121.0
        a._sweep_fanouts()
        # only the FRESH window closes and summarises; the pre-restart window
        # is gone and emits nothing (the held rows were already announced by
        # its first K -- nothing is lost beyond the summary itself)
        assert a.metrics.fanout_summaries == 1
        sums = _summaries(store)
        assert len(sums) == 1 and "x4" in sums[0]["payload"]
        statuses = [r["status"] for r in store.rows_since(0)]
        assert statuses.count("delivered_digested") == 8  # still auditable
    finally:
        store.close()


def test_disabled_window_passes_everything_through(tmp_path):
    a, store, _now = _app(tmp_path, fanout_window_s=0.0)
    try:
        assert a.ingest("grafana", _grafana("rule-D", "firing", _instances("d", 10))) == 200
        assert a.q.qsize() == 10
        assert a.metrics.digested == 0
    finally:
        store.close()


def test_bypass_mode_skips_fanout(tmp_path):
    a, store, _now = _app(tmp_path, mode="bypass")
    try:
        assert a.ingest("grafana", _grafana("rule-B", "firing", _instances("b", 10))) == 200
        assert a.q.qsize() == 10
        assert a.metrics.digested == 0
    finally:
        store.close()


def test_fanout_settings_live_swap_via_apply_changes(tmp_path):
    from nuncio import config
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path)}
    app, _settings = config.build_app(config.load_settings(env))
    try:
        assert app.fanout_window_s == 0.0   # fan-out OFF by default (opt-in)
        assert app.fanout_k == 3
        result = config.apply_changes(app, {"NUNCIO_FANOUT_WINDOW_S": 120,
                                            "NUNCIO_FANOUT_K": 5})
        assert sorted(result["applied"]) == ["NUNCIO_FANOUT_K", "NUNCIO_FANOUT_WINDOW_S"]
        assert app.fanout_window_s == 120.0
        assert app.fanout_k == 5
    finally:
        app.store.close()
