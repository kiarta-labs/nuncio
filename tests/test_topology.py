"""C3 learned co-occurrence edges (rank-only) + store input + rank hook."""
from nuncio import topology
from nuncio.correlate import rank_correlated
from nuncio.fingerprint import fingerprint
from nuncio.store import Store


class FakeClock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def _fire(store, service, severity="warning", day=0, tag=""):
    key = f"{service}-d{day}-{tag or severity}"
    store.persist(key, f"[{severity}] {service} event {tag}", source="checkmk",
                  category="container", severity=severity,
                  fingerprint=f"fp-{service}-{day}", host="host01", service=service)


def _store_with_cofire(daysABC=3):
    clock = FakeClock()
    store = Store(":memory:", clock=clock)
    base = clock.t
    for day in range(daysABC):
        clock.t = base + day * 86400
        _fire(store, "web", day=day)
        _fire(store, "db", day=day)
        if day == 0:
            _fire(store, "oneoff", day=day)
        _fire(store, "noisy-info", severity="info", day=day)
    clock.t = base + daysABC * 86400
    return store, clock


def test_learned_edges_from_repeated_cofire():
    store, clock = _store_with_cofire()
    try:
        edges = topology.learn_edges(store, {"at": 0.0, "edges": {}}, now=clock.t)
        assert "db" in edges.get("web", [])
        assert "web" in edges.get("db", [])
        assert "oneoff" not in edges.get("web", [])  # single shared day: no edge
        assert "noisy-info" not in edges  # info severity never enters
        assert "web" not in edges.get("noisy-info", [])
    finally:
        store.close()


def test_learned_edges_respect_day_threshold():
    store, clock = _store_with_cofire(daysABC=2)
    try:
        edges = topology.learn_edges(store, {"at": 0.0, "edges": {}}, now=clock.t)
        assert edges.get("web", []) == [] or "db" not in edges.get("web", [])
    finally:
        store.close()


def test_learned_edges_cap_per_service():
    clock = FakeClock()
    store = Store(":memory:", clock=clock)
    try:
        base = clock.t
        partners = [f"svc{i}" for i in range(7)]
        for day in range(3):
            clock.t = base + day * 86400
            _fire(store, "hub", day=day)
            for p in partners:
                _fire(store, p, day=day)
        clock.t = base + 3 * 86400
        edges = topology.learn_edges(store, {"at": 0.0, "edges": {}}, now=clock.t)
        assert len(edges["hub"]) == 5
    finally:
        store.close()


def test_learned_edges_ttl_cache_and_recompute():
    store, clock = _store_with_cofire()
    try:
        state = {"at": 0.0, "edges": {}}
        first = topology.learn_edges(store, state, now=clock.t)
        base = clock.t
        # new co-firing pair lands 3 days later (store clock advanced so
        # their created_at fall on distinct days)
        for d in range(3):
            clock.t = base + (d + 1) * 86400
            _fire(store, "newa", day=99 + d)
            _fire(store, "newb", day=99 + d)
        # inside the TTL: cache wins, no recompute
        assert topology.learn_edges(store, state, now=base + 10) is first
        assert "newb" not in first.get("newa", [])
        # now past the TTL (now = the store's advanced clock): recompute
        # picks the new edge up (its window [now-30d, now] covers them)
        second = topology.learn_edges(store, state, now=clock.t)
        assert "newb" in second.get("newa", [])
    finally:
        store.close()


def test_learned_edges_never_raises():
    class BoomStore:
        def service_day_rows(self, *a, **k):
            raise RuntimeError("db gone")

    assert topology.learn_edges(BoomStore(), {"at": 0.0, "edges": {}}, now=1.0) == {}


def test_service_day_rows_bounded_newest():
    clock = FakeClock()
    store = Store(":memory:", clock=clock)
    try:
        for i in range(5):
            _fire(store, f"s{i}", day=0, tag=str(i))
        rows = store.service_day_rows(since=0.0, limit=3)
        assert len(rows) == 3
        assert all(len(r) == 4 for r in rows)
    finally:
        store.close()


def _nine(key, payload, created_at, fp, host="host01", service="web"):
    return (key, payload, created_at, "checkmk", "container", "warning", fp, host, service)


def test_learned_edge_reorders_but_never_admits():
    alert = {"host": "host01", "service": "web",
             "output": "disk latency high on web", "severity": "warning"}
    fp = fingerprint(alert)
    # gated by fingerprint but carrying a DIFFERENT service -> the learned
    # boost can apply (the row is admitted by the gate, not by the map).
    gated = _nine("k1", "disk latency high on web again", 1500.0, fp, service="web")
    learned_row = _nine("k2", "disk latency high on db", 1500.0, fp, service="db")
    stranger = _nine("k3", "unrelated snmp flap", 1500.0, "nope-fp",
                     host="other", service="zzz")
    learned = {"web": ["db"], "db": ["web"]}
    lines = rank_correlated([gated, learned_row, stranger], alert, now=2000.0,
                            learned=learned)
    texts = "\n".join(lines)
    assert "often seen together with db" in texts  # learned boost on a gated row
    assert "zzz" not in texts  # learned map can't admit an ungated row
    plain = rank_correlated([gated, learned_row, stranger], alert, now=2000.0)
    assert "often seen together" not in "\n".join(plain)
