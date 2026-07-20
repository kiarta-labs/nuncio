"""Idempotency + persistence store.

The store is the backbone of "never lose an alert": persist-before-ACK, at-least-
once with best-effort dedup, and a restart-drain that finds anything not yet
delivered. On-disk (SQLite) so a crash/restart is safe.
"""
import pytest
from nuncio.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "alerts.db"))
    yield s
    s.close()


def test_persist_new_key_returns_true_status_received(store):
    assert store.persist("host01/infisical-postgres/42", "raw payload") is True
    assert store.get_status("host01/infisical-postgres/42") == "received"


def test_persist_duplicate_key_returns_false_and_preserves_original(store):
    store.persist("k1", "original")
    assert store.persist("k1", "SECOND ATTEMPT") is False
    # original payload/status untouched
    assert store.get_payload("k1") == "original"
    assert store.get_status("k1") == "received"


def test_mark_delivered_enriched_updates_status(store):
    store.persist("k1", "p")
    store.mark_delivered("k1", "enriched")
    assert store.get_status("k1") == "delivered_enriched"


def test_mark_delivered_raw_updates_status(store):
    store.persist("k1", "p")
    store.mark_delivered("k1", "raw")
    assert store.get_status("k1") == "delivered_raw"


def test_undelivered_returns_received_not_yet_delivered(store):
    store.persist("k1", "p1")
    store.persist("k2", "p2")
    store.mark_delivered("k1", "enriched")
    undelivered = store.undelivered()
    keys = [k for k, _ in undelivered]
    assert keys == ["k2"]  # k1 delivered, only k2 remains
    assert undelivered[0] == ("k2", "p2")


def test_undelivered_ordered_oldest_first(store):
    for i in range(3):
        store.persist(f"k{i}", f"p{i}")
    assert [k for k, _ in store.undelivered()] == ["k0", "k1", "k2"]


def test_persistence_survives_reopen(tmp_path):
    path = str(tmp_path / "alerts.db")
    s1 = Store(path)
    s1.persist("k1", "durable")
    s1.close()  # simulate crash/restart
    s2 = Store(path)
    assert s2.get_status("k1") == "received"
    assert s2.get_payload("k1") == "durable"
    assert [k for k, _ in s2.undelivered()] == ["k1"]  # drain finds it
    s2.close()


def test_get_status_unknown_key_returns_none(store):
    assert store.get_status("nope") is None


# --- host/service (subject) columns ---

def test_fresh_store_has_host_and_service_columns(store):
    cols = {row[1] for row in store._conn.execute("PRAGMA table_info(alerts)").fetchall()}
    assert "host" in cols
    assert "service" in cols


def test_reopening_pre_existing_db_gets_host_and_service_columns(tmp_path):
    path = str(tmp_path / "alerts.db")
    s1 = Store(path)
    # simulate a DB file created before host/service existed: drop the columns
    # by rebuilding the table without them (sqlite has no DROP COLUMN in old
    # versions, so this recreates the pre-migration shape from scratch).
    s1.close()
    import sqlite3
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE alerts")
    conn.execute(
        "CREATE TABLE alerts (key TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL, "
        "seq INTEGER, created_at REAL, bundle TEXT, delivery_mode TEXT, raw_first_fired INTEGER DEFAULT 0)"
    )
    conn.commit()
    conn.close()
    s2 = Store(path)
    cols = {row[1] for row in s2._conn.execute("PRAGMA table_info(alerts)").fetchall()}
    assert "host" in cols
    assert "service" in cols
    s2.close()


def test_persist_stores_host_and_service(store):
    store.persist("k1", "p", host="svr", service="disk-root")
    detail = store.get_alert_detail("k1")
    assert detail["host"] == "svr"
    assert detail["service"] == "disk-root"


def test_persist_without_host_service_defaults_to_none(store):
    store.persist("k1", "p")
    detail = store.get_alert_detail("k1")
    assert detail["host"] is None
    assert detail["service"] is None


def test_rows_since_includes_host_and_service(store):
    store.persist("k1", "p", host="kprintr", service="cpu")
    rows = store.rows_since(0)
    assert rows[0]["host"] == "kprintr"
    assert rows[0]["service"] == "cpu"


def test_record_stats_cannot_touch_host_or_service(store):
    store.persist("k1", "p", host="svr", service="disk")
    with pytest.raises(ValueError):
        store.record_stats("k1", host="other")
    with pytest.raises(ValueError):
        store.record_stats("k1", service="other")


# --- C1: age-based recovery of stuck/undelivered rows ---

class FakeWall:
    def __init__(self, t=1000.0): self.t = t
    def __call__(self): return self.t


def test_undelivered_older_than_filters_by_age():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    s.persist("old", "p1")
    wall.t = 1100.0
    s.persist("new", "p2")
    # cutoff 1050: only 'old' (created at 1000) is older
    stale = s.undelivered_older_than(1050.0)
    assert [k for k, _ in stale] == ["old"]
    s.close()


def test_undelivered_older_than_excludes_delivered():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    s.persist("k1", "p1")
    s.mark_delivered("k1", "raw")
    wall.t = 2000.0
    assert s.undelivered_older_than(1999.0) == []
    s.close()


def test_purge_delivered_removes_old_delivered_only():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    s.persist("old_done", "p"); s.mark_delivered("old_done", "raw")
    wall.t = 5000.0
    s.persist("new_done", "p"); s.mark_delivered("new_done", "enriched")
    s.persist("old_undelivered", "p")  # created at 5000 too... make it old:
    removed = s.purge_delivered(cutoff=2000.0)
    assert removed == 1  # only old_done (delivered + old)
    assert s.get_status("old_done") is None
    assert s.get_status("new_done") == "delivered_enriched"  # too new, kept
    s.close()


# --- Phase 2: recent() for cross-alert correlation (backward window) ---

def test_recent_returns_alerts_in_backward_window_excluding_self():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 100.0; s.persist("a", "alert a")
    wall.t = 500.0; s.persist("b", "alert b")
    wall.t = 950.0; s.persist("c", "alert c")
    wall.t = 1000.0; s.persist("self", "the current alert")
    # window: 600s before now(1000) = [400,1000); exclude self -> b(500), c(950)
    got = s.recent(before=1000.0, window_s=600.0, exclude_key="self")
    assert [row[0] for row in got] == ["b", "c"]  # 'a'(100) too old, 'self' excluded


def test_recent_respects_limit_newest_kept():
    wall = FakeWall(0.0)
    s = Store(":memory:", clock=wall)
    for i in range(30):
        wall.t = float(i)
        s.persist(f"k{i}", f"p{i}")
    got = s.recent(before=100.0, window_s=100.0, exclude_key=None, limit=5)
    assert len(got) == 5


def test_recent_returns_9_tuple_with_source_category_severity_fingerprint_host_service():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0
    s.persist("a", "alert a", source="checkmk", category="hardware", severity="critical",
              fingerprint="fp123", host="svr", service="disk-root")
    got = s.recent(before=1000.0, window_s=600.0, exclude_key="self")
    assert len(got) == 1
    key, payload, created_at, source, category, severity, fp, host, service = got[0]
    assert key == "a" and payload == "alert a"
    assert source == "checkmk" and category == "hardware" and severity == "critical"
    assert fp == "fp123"
    assert host == "svr" and service == "disk-root"
    s.close()


# --- Phase 2: canary exclusion (F4), bundle audit column (F3) ---

def test_recent_excludes_canary_alerts():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0; s.persist("canary:heartbeat", "synthetic canary")
    wall.t = 960.0; s.persist("real", "[PROBLEM] host01 real alert")
    got = s.recent(before=1000.0, window_s=600.0, exclude_key="self")
    keys = [row[0] for row in got]
    assert "real" in keys
    assert "canary:heartbeat" not in keys  # canary never appears as correlated
    s.close()


def test_set_and_get_redacted_bundle():
    s = Store(":memory:", clock=FakeWall(1.0))
    s.persist("k1", "raw")
    assert s.get_bundle("k1") is None
    s.set_bundle("k1", "## Logs\n«REDACTED:env» line")
    assert "REDACTED" in s.get_bundle("k1")
    s.close()


# --- NUNCIO_MODE bookkeeping (delivery_mode) ---

def test_persist_records_delivery_mode(store):
    store.persist("k1", "p", mode="bypass")
    assert store.get_delivery_mode("k1") == "bypass"


def test_persist_mode_defaults_to_none_for_back_compat(store):
    store.persist("k1", "p")  # old 2-arg call style, still works
    assert store.get_delivery_mode("k1") is None


def test_mark_delivered_rejects_unknown_mode(store):
    store.persist("k1", "p")
    with pytest.raises(ValueError):
        store.mark_delivered("k1", "bogus")


def test_migration_promotes_legacy_pending_enrich_status_to_delivered_raw(tmp_path):
    # A DB file from before the delivery-mode collapse (see nuncio/store.py's
    # migration comment) can have rows stuck in the old interim
    # 'delivered_raw_pending_enrich' status -- opening the Store must
    # promote them straight to the terminal 'delivered_raw' rather than
    # leaving an unrecognized status behind, and the row must be gone from
    # undelivered() (it was never 'received').
    path = str(tmp_path / "legacy.db")
    s1 = Store(path)
    s1.persist("k1", "p")
    # Hand-write the legacy status directly -- no code path in this build
    # produces it anymore.
    s1._conn.execute("UPDATE alerts SET status = 'delivered_raw_pending_enrich' WHERE key = 'k1'")
    s1._conn.commit()
    s1.close()

    s2 = Store(path)
    assert s2.get_status("k1") == "delivered_raw"
    assert s2.undelivered() == []
    s2.close()


# --- dashboard columns ---

def test_persist_records_source_category_severity(store):
    store.persist("k1", "p", source="checkmk", category="container", severity="critical")
    row = store.get_alert_detail("k1")
    assert row["source"] == "checkmk"
    assert row["category"] == "container"
    assert row["severity"] == "critical"


def test_persist_stats_fields_default_to_none_for_back_compat(store):
    store.persist("k1", "p")  # old call style, no source/category/severity
    row = store.get_alert_detail("k1")
    assert row["source"] is None
    assert row["category"] is None
    assert row["severity"] is None


def test_record_stats_updates_only_given_fields(store):
    store.persist("k1", "p")
    store.record_stats("k1", outcome="enriched", latency_ms=1234, tokens_in=50, tokens_out=20)
    row = store.get_alert_detail("k1")
    assert row["outcome"] == "enriched"
    assert row["latency_ms"] == 1234
    assert row["tokens_in"] == 50
    assert row["tokens_out"] == 20
    assert row["fail_stage"] is None  # untouched


def test_record_stats_rejects_unknown_field(store):
    store.persist("k1", "p")
    with pytest.raises(ValueError):
        store.record_stats("k1", not_a_real_column="x")


def test_record_stats_noop_with_no_fields(store):
    store.persist("k1", "p")
    store.record_stats("k1")  # must not raise, must not touch the row
    row = store.get_alert_detail("k1")
    assert row["outcome"] is None


def test_record_stats_cannot_write_source_category_severity(store):
    # Those are persist()'s job only (single writer, no race between the two
    # write paths over the same columns).
    store.persist("k1", "p")
    with pytest.raises(ValueError):
        store.record_stats("k1", source="hacked")


# --- Phase A: enrich_format stats column (additive migration) ---

def test_enrich_format_column_defaults_to_none(store):
    store.persist("k1", "p")
    row = store.get_alert_detail("k1")
    assert row["enrich_format"] is None


def test_record_stats_can_write_enrich_format(store):
    store.persist("k1", "p")
    store.record_stats("k1", outcome="enriched", enrich_format="structured")
    row = store.get_alert_detail("k1")
    assert row["enrich_format"] == "structured"


def test_enrich_format_is_a_row_col_visible_in_recent_rows(store):
    store.persist("k1", "p")
    store.record_stats("k1", enrich_format="text")
    rows = store.recent_rows()
    assert rows[0]["enrich_format"] == "text"


def test_enrich_format_column_migrates_additively_on_legacy_db(tmp_path):
    # Simulate a DB file created before enrich_format existed: build a bare
    # `alerts` table missing the column, then open it via Store() and
    # confirm the ALTER TABLE migration runs without touching existing data.
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
        assert row["payload"] == "legacy payload"  # existing data untouched
        assert row["enrich_format"] is None  # new column, additive, nullable
        s.record_stats("legacy-key", enrich_format="structured")
        assert s.get_alert_detail("legacy-key")["enrich_format"] == "structured"
    finally:
        s.close()


def test_get_created_at_returns_persist_time():
    wall = FakeWall(1234.5)
    s = Store(":memory:", clock=wall)
    s.persist("k1", "p")
    assert s.get_created_at("k1") == 1234.5
    s.close()


def test_get_created_at_unknown_key_returns_none(store):
    assert store.get_created_at("nope") is None


def test_status_counts_reflects_all_time_history(store):
    store.persist("k1", "p")
    store.persist("k2", "p")
    store.persist("k3", "p")
    store.mark_delivered("k1", "enriched")
    store.mark_delivered("k2", "raw")
    counts = store.status_counts()
    assert counts["delivered_enriched"] == 1
    assert counts["delivered_raw"] == 1
    assert counts["received"] == 1


def test_count_all(store):
    store.persist("k1", "p")
    store.persist("k2", "p")
    assert store.count_all() == 2


def test_rows_since_filters_by_created_at_and_returns_stats_columns():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    s.persist("old", "p")
    wall.t = 2000.0
    s.persist("new", "p", source="checkmk", severity="critical")
    s.record_stats("new", outcome="enriched", latency_ms=500, tokens_in=10, tokens_out=5)
    rows = s.rows_since(1500.0)
    assert [r["key"] for r in rows] == ["new"]
    assert rows[0]["source"] == "checkmk"
    assert rows[0]["latency_ms"] == 500
    s.close()


def test_recent_rows_newest_first_and_excludes_canaries():
    wall = FakeWall(1.0)
    s = Store(":memory:", clock=wall)
    wall.t = 1.0; s.persist("canary:hb", "synthetic")
    wall.t = 2.0; s.persist("a", "alert a", source="checkmk")
    wall.t = 3.0; s.persist("b", "alert b", source="grafana")
    rows = s.recent_rows(limit=10)
    assert [r["key"] for r in rows] == ["b", "a"]
    s.close()


def test_recent_rows_filters_by_source_and_outcome():
    s = Store(":memory:", clock=FakeWall(1.0))
    s.persist("a", "p", source="checkmk")
    s.persist("b", "p", source="grafana")
    s.record_stats("a", outcome="enriched")
    s.record_stats("b", outcome="raw")
    assert [r["key"] for r in s.recent_rows(source="checkmk")] == ["a"]
    assert [r["key"] for r in s.recent_rows(outcome="raw")] == ["b"]
    s.close()


def test_recent_rows_respects_limit(store):
    for i in range(5):
        store.persist(f"k{i}", "p")
    assert len(store.recent_rows(limit=2)) == 2


def test_get_alert_detail_includes_bundle_and_enrichment(store):
    store.persist("k1", "raw payload", source="checkmk", category="hardware", severity="warning")
    store.set_bundle("k1", "## Logs\n«REDACTED:env» line")
    store.record_stats("k1", outcome="enriched", enrichment="SUMMARY: ok")
    row = store.get_alert_detail("k1")
    assert row["payload"] == "raw payload"
    assert row["bundle"] == "## Logs\n«REDACTED:env» line"
    assert row["enrichment"] == "SUMMARY: ok"
    assert row["category"] == "hardware"


def test_get_alert_detail_unknown_key_returns_none(store):
    assert store.get_alert_detail("nope") is None


# --- B1: fingerprint column + fingerprint_stats ---

def test_persist_stores_fingerprint(store):
    store.persist("k1", "p", fingerprint="abc123")
    row = store.get_alert_detail("k1")
    assert row["fingerprint"] == "abc123"


def test_fingerprint_stats_counts_within_window():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 900.0; s.persist("a", "p", fingerprint="fp1")
    wall.t = 950.0; s.persist("b", "p", fingerprint="fp1")
    wall.t = 960.0; s.persist("c", "p", fingerprint="fp2")
    count, first_seen = s.fingerprint_stats("fp1", window_s=200, now=1000.0)
    assert count == 2
    assert first_seen == 900.0
    s.close()


def test_fingerprint_stats_excludes_canaries():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0; s.persist("canary:hb", "p", fingerprint="fp1")
    count, first_seen = s.fingerprint_stats("fp1", window_s=200, now=1000.0)
    assert count == 0
    assert first_seen is None
    s.close()


def test_fingerprint_stats_no_match_returns_zero_none(store):
    count, first_seen = store.fingerprint_stats("nope", window_s=200)
    assert count == 0
    assert first_seen is None


def test_legacy_delivered_raw_pending_enrich_row_is_purged_like_other_delivered_rows(tmp_path):
    # LIKE 'delivered_%' already matches the historical interim status, so a
    # leftover row from a pre-collapse DB (see the migration test above)
    # still ages out via the normal retention purge rather than
    # accumulating forever, even before the migration ever runs.
    path = str(tmp_path / "legacy2.db")
    wall = FakeWall(1000.0)
    s = Store(path, clock=wall)
    s.persist("k1", "p")
    s._conn.execute("UPDATE alerts SET status = 'delivered_raw_pending_enrich' WHERE key = 'k1'")
    s._conn.commit()
    wall.t = 5000.0
    removed = s.purge_delivered(cutoff=2000.0)
    assert removed == 1
    assert s.get_status("k1") is None
    s.close()
