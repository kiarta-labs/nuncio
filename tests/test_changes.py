"""C2 recent-changes section + wiring."""
from nuncio.bundle import _ORDER, _TRUNCATE_ORDER, assemble_bundle
from nuncio.collectors import collect_changes
from nuncio.gatherer import Gatherer, _CATEGORY_COLLECTORS
from nuncio.prompt import build_full_triage_messages
from nuncio.store import Store


def _seed(store, now):
    store.persist("k1", "[FIRING] host01 / web -- disk latency high",
                  source="checkmk", category="container", severity="warning",
                  host="host01", service="web")
    store.persist("k2", "[INFO] host01 / web -- deployed web build 1.2.3",
                  source="generic", category="container", severity="info",
                  host="host01", service="web")
    store.persist("k3", "[INFO] host01 / worker -- worker restarted after OOM",
                  source="generic", category="container", severity="info",
                  host="host01", service="worker")


def test_collect_changes_same_service_and_hints():
    import time
    store = Store(":memory:")
    try:
        _seed(store, None)
        now = time.time()
        alert = {"host": "host01", "service": "db", "output": "down", "severity": "critical"}
        out = collect_changes(store, alert, "k0", now)
        assert out.startswith("## Recent changes (last 60m)")
        # no same-service rows for db; two keyword hints from other services
        assert "change hint" in out
        assert "deployed web build" in out
        assert "restarted after OOM" in out
    finally:
        store.close()


def test_collect_changes_same_service_count():
    import time
    store = Store(":memory:")
    try:
        _seed(store, None)
        now = time.time()
        alert = {"host": "host01", "service": "web", "output": "x", "severity": "warning"}
        out = collect_changes(store, alert, "k0", now)
        assert "2 same-service event(s)" in out
    finally:
        store.close()


def test_collect_changes_empty_marker():
    store = Store(":memory:")
    try:
        out = collect_changes(store, {"service": "nothing-here"}, "k0", 200000.0)
        assert "(no recent changes)" in out
    finally:
        store.close()


def test_collect_changes_never_raises():
    class BoomStore:
        def recent(self, *a, **k):
            raise RuntimeError("db gone")

    out = collect_changes(BoomStore(), {"service": "web"}, "k0", 200000.0)
    assert "context unavailable: changes" in out


def test_changes_selected_in_every_profile():
    stub = {n: (lambda a, k, t: "x") for n in
            ("recent_logs", "container_state", "metrics", "kernel",
             "correlated", "recurrence", "history", "changes")}
    g = Gatherer(stub)
    for cat, svc in (("container", "web"), ("network", "eth0"),
                     ("generic", "thing"), ("storage", "disk"),
                     ("hardware", "cpu")):
        assert "changes" in g.select({"service": svc, "output": "x", "category": cat}), cat
    assert "changes" in _CATEGORY_COLLECTORS["container"]


def test_bundle_orders_and_drops_changes_first():
    sections = {
        "container_state": "## Container state\nup",
        "recent_logs": "## Recent logs\nline",
        "metrics": "## Related metrics\nup",
        "kernel": "## Kernel\nok",
        "correlated": "## Correlated alerts\n- x [same service]",
        "history": "## Alert history\ny",
        "changes": "## Recent changes\n- z",
        "recurrence": "## Recurrence\nfirst occurrence",
    }
    full = assemble_bundle(sections, 10 ** 6)
    order = [full.index("## " + h) for h in
             ("Container state", "Recent logs", "Related metrics", "Kernel",
              "Correlated alerts", "Alert history", "Recent changes", "Recurrence")]
    assert order == sorted(order)
    assert _ORDER.index("changes") > _ORDER.index("history")
    # C5 addition dropped before changes under pressure
    assert _TRUNCATE_ORDER[0] == "past_incidents"
    assert _TRUNCATE_ORDER.index("changes") > _TRUNCATE_ORDER.index("past_incidents")
    tiny = assemble_bundle(sections, 120)
    assert "Recent changes" not in tiny or "Similar past incidents" not in tiny
    assert "Recurrence" in tiny  # single line survives


def test_triage_builder_includes_changes_section():
    msgs = build_full_triage_messages(
        {"host": "h", "service": "s", "state": "x", "output": "y"},
        {"history": "## Alert history\nnone",
         "changes": "## Recent changes (last 60m)\n- 1 same-service event(s)"})
    assert "Recent changes" in msgs[1]["content"]
