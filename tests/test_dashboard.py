"""The web dashboard — pure aggregation helpers and the
JSON/HTML rendering functions. HTTP-route-level tests (real socket, full
ingest->process->fetch, no-secret-leak) live in tests/test_app.py alongside
the rest of the server-layer tests.
"""
import json
import time
import types

import pytest

from nuncio.store import Store
from nuncio.web import dashboard


# --- percentile() ---

def test_percentile_empty_list_returns_none():
    assert dashboard.percentile([], 0.5) is None


def test_percentile_single_value():
    assert dashboard.percentile([42], 0.95) == 42


def test_percentile_p50_of_sorted_list():
    vals = [1, 2, 3, 4, 5]
    assert dashboard.percentile(vals, 0.5) == 3


def test_percentile_p95_interpolates():
    vals = list(range(1, 101))  # 1..100
    p95 = dashboard.percentile(vals, 0.95)
    assert 94 <= p95 <= 96


def test_percentile_p0_and_p100_are_min_and_max():
    vals = [10, 20, 30]
    assert dashboard.percentile(vals, 0.0) == 10
    assert dashboard.percentile(vals, 1.0) == 30


# --- _top_signatures() ---

def test_top_signatures_empty_input_returns_empty():
    assert dashboard._top_signatures([]) == []


def test_top_signatures_skips_falsy_fingerprint():
    rows = [{"fingerprint": None, "created_at": 1}, {"fingerprint": "", "created_at": 2}]
    assert dashboard._top_signatures(rows) == []


def test_top_signatures_requires_count_of_at_least_two():
    rows = [{"fingerprint": "fp-a", "created_at": 1, "source": "s", "severity": "warning", "payload": "x"}]
    assert dashboard._top_signatures(rows) == []


def test_top_signatures_counts_and_uses_most_recent_row_for_metadata():
    rows = [
        {"fingerprint": "fp-a", "created_at": 1, "source": "checkmk", "severity": "warning",
         "payload": "old summary line"},
        {"fingerprint": "fp-a", "created_at": 5, "source": "checkmk", "severity": "critical",
         "payload": "new summary line\nsecond line"},
    ]
    top = dashboard._top_signatures(rows)
    assert len(top) == 1
    g = top[0]
    assert g["fingerprint"] == "fp-a"
    assert g["count"] == 2
    assert g["last_seen"] == 5
    assert g["severity"] == "critical"  # from the most-recent row, not the first
    assert g["summary"] == "new summary line"  # first line only, of the latest payload


def test_top_signatures_sorted_by_count_desc_then_recency_desc():
    rows = [
        {"fingerprint": "fp-low", "created_at": 1, "payload": "a"},
        {"fingerprint": "fp-low", "created_at": 2, "payload": "a"},
        {"fingerprint": "fp-high", "created_at": 3, "payload": "b"},
        {"fingerprint": "fp-high", "created_at": 4, "payload": "b"},
        {"fingerprint": "fp-high", "created_at": 5, "payload": "b"},
    ]
    top = dashboard._top_signatures(rows)
    assert [g["fingerprint"] for g in top] == ["fp-high", "fp-low"]


def test_top_signatures_respects_limit():
    rows = []
    for fp in "abcdef":
        rows.append({"fingerprint": fp, "created_at": 1, "payload": "x"})
        rows.append({"fingerprint": fp, "created_at": 2, "payload": "x"})
    top = dashboard._top_signatures(rows, limit=3)
    assert len(top) == 3


def test_top_signatures_summary_truncated_to_120_chars():
    long_line = "x" * 200
    rows = [
        {"fingerprint": "fp-a", "created_at": 1, "payload": long_line},
        {"fingerprint": "fp-a", "created_at": 2, "payload": long_line},
    ]
    top = dashboard._top_signatures(rows)
    assert len(top[0]["summary"]) == 120


# --- _subject() ---

def test_subject_host_and_service_joined():
    assert dashboard._subject({"host": "svr", "service": "disk-root"}) == "svr/disk-root"


def test_subject_host_only():
    assert dashboard._subject({"host": "svr", "service": None}) == "svr"


def test_subject_service_only():
    assert dashboard._subject({"host": None, "service": "disk-root"}) == "disk-root"


def test_subject_neither_is_em_dash():
    assert dashboard._subject({"host": None, "service": None}) == "—"


def test_subject_falls_back_to_payload_when_columns_and_key_are_empty():
    row = {"host": None, "service": None, "payload": "[FIRING] - / HighCPU — msg"}
    assert dashboard._subject(row) == "HighCPU"


# --- _derive_host_service() ---

def test_derive_host_service_columns_win_when_host_present():
    row = {"host": "svr", "service": "disk-root", "key": "checkmk:other/other/1/PROBLEM/1",
           "payload": "[FIRING] ignored / ignored — x"}
    assert dashboard._derive_host_service(row) == ("svr", "disk-root")


def test_derive_host_service_host_level_column_never_invents_a_service():
    # A CheckMK host-level notification legitimately has service=NULL --
    # the helper must not try to parse one out of the key/payload.
    row = {"host": "svr", "service": None, "key": "checkmk:svr/-/1/PROBLEM/1"}
    assert dashboard._derive_host_service(row) == ("svr", None)


def test_derive_host_service_column_dash_normalizes_to_none_host_and_service():
    # Non-CheckMK adapters (grafana/alertmanager/generic) default a missing
    # host to the literal "-" and persist it -- untreated that would key the
    # hosts ledger on a phantom "-" host.
    row = {"host": "-", "service": "-"}
    assert dashboard._derive_host_service(row) == (None, None)


def test_derive_host_service_empty_string_columns_normalize_to_none():
    row = {"host": "", "service": ""}
    assert dashboard._derive_host_service(row) == (None, None)


def test_derive_host_service_grafana_shaped_row_keeps_service_when_host_is_dash():
    # host column is the adapter-default "-" (-> None) but service IS a real
    # column value -- must still surface it, not drop it on the floor.
    row = {"host": "-", "service": "HighCPU"}
    assert dashboard._derive_host_service(row) == (None, "HighCPU")


def test_derive_host_service_parses_checkmk_key_when_columns_missing():
    row = {"host": None, "service": None, "key": "checkmk:svr/PostgreSQL infisical/77001/PROBLEM/1"}
    assert dashboard._derive_host_service(row) == ("svr", "PostgreSQL infisical")


def test_derive_host_service_checkmk_key_host_level_dash_service_is_none():
    row = {"host": None, "service": None, "key": "checkmk:svr/-/1/PROBLEM/1"}
    assert dashboard._derive_host_service(row) == ("svr", None)


def test_derive_host_service_checkmk_key_with_slash_in_service_falls_through_to_payload():
    # "Filesystem /var" contains a "/" -- splitting the key on "/" yields 6
    # parts instead of 5, so the key-parse branch must be skipped (not
    # mis-split) and fall through to the payload parse, which handles it fine.
    row = {"host": None, "service": None,
           "key": "checkmk:svr/Filesystem /var/1/PROBLEM/1",
           "payload": "[RECOVERY] svr / Filesystem /var — ok"}
    assert dashboard._derive_host_service(row) == ("svr", "Filesystem /var")


def test_derive_host_service_payload_bracket_tag_strips_spaces_around_slash():
    # Old CheckMK rows (and ALL grafana/alertmanager/generic raw text) put
    # spaces around the slash -- without stripping, "svr " != "svr" and one
    # real host would split into two ledger buckets.
    row = {"host": None, "service": None, "payload": "[RECOVERY] svr / Filesystem /var — ok"}
    assert dashboard._derive_host_service(row) == ("svr", "Filesystem /var")


def test_derive_host_service_payload_grafana_dash_host_yields_none_service_kept():
    row = {"host": None, "service": None, "payload": "[FIRING] - / HighCPU — msg"}
    assert dashboard._derive_host_service(row) == (None, "HighCPU")


def test_derive_host_service_payload_emoji_prefix_no_spaces_around_slash():
    row = {"host": None, "service": None, "payload": "❗ h/s — out"}
    assert dashboard._derive_host_service(row) == ("h", "s")


def test_derive_host_service_payload_host_only_no_slash():
    row = {"host": None, "service": None, "payload": "[CRIT] web-1 — disk full"}
    assert dashboard._derive_host_service(row) == ("web-1", None)


def test_derive_host_service_payload_without_em_dash_returns_none_none():
    row = {"host": None, "service": None, "payload": "just some unstructured text, no dash here"}
    assert dashboard._derive_host_service(row) == (None, None)


def test_derive_host_service_non_checkmk_key_is_never_parsed_as_a_checkmk_key():
    row = {"host": None, "service": None, "key": "generic:6eb1fecb9cf6fc76/29738556",
           "payload": "[CRIT] verify-1784313389 / selfcheck — enriched-mode single-delivery verification"}
    assert dashboard._derive_host_service(row) == ("verify-1784313389", "selfcheck")


def test_derive_host_service_none_guards_missing_key_and_payload_do_not_crash():
    row = {"host": None, "service": "x"}
    assert dashboard._derive_host_service(row) == (None, "x")


def test_derive_host_service_bare_dict_lacking_everything_does_not_crash():
    assert dashboard._derive_host_service({}) == (None, None)


# --- _hourly_counts() ---

def test_hourly_counts_empty_rows():
    assert dashboard._hourly_counts([], now=100000.0, hours=24) == [0] * 24


def test_hourly_counts_buckets_by_hour_oldest_first():
    now = 100000.0
    rows = [{"created_at": now - 24 * 3600 + 1}, {"created_at": now - 0.5 * 3600}]
    buckets = dashboard._hourly_counts(rows, now=now, hours=24)
    assert buckets[0] == 1
    assert buckets[23] == 1
    assert sum(buckets) == 2


def test_hourly_counts_all_same_time_single_bucket():
    now = 100000.0
    rows = [{"created_at": now - 10} for _ in range(5)]
    buckets = dashboard._hourly_counts(rows, now=now, hours=24)
    assert buckets[23] == 5


# --- _storm_bucket_indices() ---

def test_storm_bucket_indices_empty_totals():
    assert dashboard._storm_bucket_indices([]) == []


def test_storm_bucket_indices_all_zero():
    assert dashboard._storm_bucket_indices([0, 0, 0]) == []


def test_storm_bucket_indices_flags_min_absolute_floor():
    # median of nonzero cols is 1, so 3*median=3 < floor of 5 -- only a col
    # hitting the 5-alert floor counts as a storm.
    totals = [1, 1, 5, 0, 0]
    assert dashboard._storm_bucket_indices(totals) == [2]


def test_storm_bucket_indices_flags_relative_spike():
    # median of nonzero (2,2,2,20) = 2 -> 3*median=6, so the 20-col storms.
    totals = [2, 2, 2, 20]
    assert dashboard._storm_bucket_indices(totals) == [3]


def test_storm_bucket_indices_single_nonzero_bucket_never_self_storms():
    # with only one nonzero column, the median *is* that column -- 3x itself
    # always exceeds itself, so a single spike can never flag against its own
    # baseline (this is expected: "storm" is a relative-to-peers concept).
    assert dashboard._storm_bucket_indices([0, 7, 0]) == []


# --- _flap_cycles() ---

def test_flap_cycles_empty_is_zero():
    assert dashboard._flap_cycles([]) == 0


def test_flap_cycles_single_problem_is_zero():
    assert dashboard._flap_cycles(["P"]) == 0


def test_flap_cycles_one_full_cycle():
    assert dashboard._flap_cycles(["P", "R", "P"]) == 1


def test_flap_cycles_two_full_cycles():
    assert dashboard._flap_cycles(["P", "R", "P", "R", "P"]) == 2


def test_flap_cycles_recovery_without_prior_problem_does_not_count():
    # leading R is a no-op (nothing to recover FROM); P->R with no return to
    # P is not yet a completed cycle.
    assert dashboard._flap_cycles(["R", "P", "R"]) == 0


def test_flap_cycles_dedupes_consecutive_repeats():
    # two problem alerts in a row (no recovery between) is still one "P"
    # state -- must not be double-counted as two half-cycles.
    assert dashboard._flap_cycles(["P", "P", "R", "R", "P"]) == 1


# --- _by_host_24h() ---

def test_by_host_24h_empty_rows_returns_empty_list():
    assert dashboard._by_host_24h([], [], now=100000.0) == []


def test_by_host_24h_skips_rows_without_host():
    rows = [{"host": None, "service": "x", "created_at": 100000.0, "severity": "critical"}]
    assert dashboard._by_host_24h(rows, [], now=100000.0) == []


def test_by_host_24h_counts_and_severity_mix():
    now = 100000.0
    rows = [
        {"host": "svr", "created_at": now, "severity": "critical", "outcome": "enriched"},
        {"host": "svr", "created_at": now, "severity": "warning", "outcome": "raw"},
        {"host": "svr", "created_at": now, "severity": "info", "outcome": "enriched"},
    ]
    out = dashboard._by_host_24h(rows, [], now=now)
    assert len(out) == 1
    g = out[0]
    assert g["host"] == "svr"
    assert g["count"] == 3
    assert g["crit"] == 1 and g["warn"] == 1 and g["info"] == 1
    assert g["enriched_count"] == 2
    assert g["total_for_enrich"] == 3


def test_by_host_24h_trend_new_when_no_prior():
    now = 100000.0
    rows = [{"host": "svr", "created_at": now, "severity": "info", "outcome": "enriched"}]
    out = dashboard._by_host_24h(rows, [], now=now)
    assert out[0]["prior_count"] == 0
    assert out[0]["trend_pct"] == "new"


def test_by_host_24h_trend_flat_when_equal():
    now = 100000.0
    rows = [{"host": "svr", "created_at": now, "severity": "info"} for _ in range(3)]
    prior = [{"host": "svr", "created_at": now - 30 * 3600, "severity": "info"} for _ in range(3)]
    out = dashboard._by_host_24h(rows, prior, now=now)
    assert out[0]["trend_pct"] == 0


def test_by_host_24h_trend_signed_percent():
    now = 100000.0
    rows = [{"host": "svr", "created_at": now, "severity": "info"} for _ in range(4)]
    prior = [{"host": "svr", "created_at": now - 30 * 3600, "severity": "info"} for _ in range(2)]
    out = dashboard._by_host_24h(rows, prior, now=now)
    assert out[0]["trend_pct"] == 100  # doubled


def test_by_host_24h_sorted_desc_and_capped_to_six():
    now = 100000.0
    rows = []
    for i in range(8):
        n = 8 - i  # host0 has most alerts, host7 fewest
        for _ in range(n):
            rows.append({"host": f"host{i}", "created_at": now, "severity": "info"})
    out = dashboard._by_host_24h(rows, [], now=now)
    assert len(out) == 6
    assert out[0]["host"] == "host0"
    counts = [g["count"] for g in out]
    assert counts == sorted(counts, reverse=True)


def test_by_host_24h_spark_has_24_hourly_buckets():
    now = 100000.0
    rows = [{"host": "svr", "created_at": now, "severity": "info"}]
    out = dashboard._by_host_24h(rows, [], now=now)
    assert len(out[0]["spark"]) == 24
    assert sum(out[0]["spark"]) == 1


def test_by_host_24h_derives_host_from_checkmk_key_when_columns_missing():
    # Old rows persisted before host/service columns existed have NULL
    # host/service -- the ledger must still populate from the key.
    now = 100000.0
    rows = [{"host": None, "service": None, "created_at": now, "severity": "warning",
             "key": "checkmk:router.kirits.net/Interface 5/0/PROBLEM/1"}]
    out = dashboard._by_host_24h(rows, [], now=now)
    assert len(out) == 1
    assert out[0]["host"] == "router.kirits.net"


def test_by_host_24h_derives_host_from_payload_when_key_and_columns_missing():
    now = 100000.0
    rows = [{"host": None, "service": None, "created_at": now, "severity": "warning",
             "payload": "[RECOVERY] svr / Interface 5 — up"}]
    out = dashboard._by_host_24h(rows, [], now=now)
    assert len(out) == 1
    assert out[0]["host"] == "svr"


# --- _noisiest_subjects_24h() ---

def test_noisiest_subjects_empty_rows():
    assert dashboard._noisiest_subjects_24h([]) == []


def test_noisiest_subjects_has_critical_flag():
    rows = [
        {"host": "svr", "service": "x", "created_at": 1, "severity": "critical", "fingerprint": "a"},
        {"host": "svr", "service": "x", "created_at": 2, "severity": "warning", "fingerprint": "a"},
    ]
    out = dashboard._noisiest_subjects_24h(rows)
    assert out[0]["subject"] == "svr/x"
    assert out[0]["count"] == 2
    assert out[0]["has_critical"] is True


def test_noisiest_subjects_recur_is_max_fingerprint_group():
    rows = [
        {"host": "svr", "service": "x", "created_at": i, "severity": "warning", "fingerprint": "a"}
        for i in range(3)
    ] + [{"host": "svr", "service": "x", "created_at": 9, "severity": "warning", "fingerprint": "b"}]
    out = dashboard._noisiest_subjects_24h(rows)
    assert out[0]["recur"] == 3


def test_noisiest_subjects_flapping_true_when_two_cycles():
    rows = []
    for i, sev in enumerate(["warning", "ok", "warning", "ok", "warning"]):
        rows.append({"host": "svr", "service": "x", "created_at": i, "severity": sev, "fingerprint": None})
    out = dashboard._noisiest_subjects_24h(rows)
    assert out[0]["flap_cycles"] == 2
    assert out[0]["flapping"] is True


def test_noisiest_subjects_not_flapping_single_cycle():
    rows = [
        {"host": "svr", "service": "x", "created_at": 1, "severity": "warning", "fingerprint": None},
        {"host": "svr", "service": "x", "created_at": 2, "severity": "ok", "fingerprint": None},
        {"host": "svr", "service": "x", "created_at": 3, "severity": "warning", "fingerprint": None},
    ]
    out = dashboard._noisiest_subjects_24h(rows)
    assert out[0]["flap_cycles"] == 1
    assert out[0]["flapping"] is False


def test_noisiest_subjects_derives_subject_from_payload_when_columns_missing():
    rows = [{"host": None, "service": None, "created_at": 1, "severity": "warning",
             "payload": "[RECOVERY] svr / Interface 5 — up"}]
    out = dashboard._noisiest_subjects_24h(rows)
    assert out[0]["subject"] == "svr/Interface 5"


def test_noisiest_subjects_sorted_desc_and_capped():
    rows = []
    for i in range(8):
        n = 8 - i
        for _ in range(n):
            rows.append({"host": f"h{i}", "service": "x", "created_at": 1, "severity": "warning"})
    out = dashboard._noisiest_subjects_24h(rows, limit=6)
    assert len(out) == 6
    assert out[0]["subject"] == "h0/x"


# --- _source_time_48h() ---

def test_source_time_48h_empty_rows():
    out = dashboard._source_time_48h([], now=172800.0)
    assert out["sources"] == []
    assert out["buckets"] == 24
    assert out["grid"] == {}
    assert out["storm_cols"] == []


def test_source_time_48h_grid_shape_and_top_sources():
    now = 172800.0
    rows = []
    for i in range(3):
        rows.append({"source": "checkmk", "created_at": now, "outcome": "enriched"})
    rows.append({"source": "grafana", "created_at": now, "outcome": "enriched"})
    out = dashboard._source_time_48h(rows, now=now)
    assert out["sources"][0] == "checkmk"  # most alerts first
    assert len(out["grid"]["checkmk"]) == 24
    assert sum(out["grid"]["checkmk"]) == 3


def test_source_time_48h_raw_grid_tracks_raw_outcomes():
    now = 172800.0
    rows = [
        {"source": "checkmk", "created_at": now, "outcome": "raw"},
        {"source": "checkmk", "created_at": now, "outcome": "enriched"},
    ]
    out = dashboard._source_time_48h(rows, now=now)
    assert sum(out["raw_grid"]["checkmk"]) == 1


def test_source_time_48h_limits_to_five_sources():
    now = 172800.0
    rows = [{"source": f"s{i}", "created_at": now} for i in range(7)]
    out = dashboard._source_time_48h(rows, now=now)
    assert len(out["sources"]) == 5


def test_source_time_48h_storm_cols_from_combined_totals():
    now = 200000.0
    start = now - 24 * 7200
    rows = (
        [{"source": "checkmk", "created_at": start + 3600, "outcome": "enriched"} for _ in range(2)]
        + [{"source": "checkmk", "created_at": start + 7200 + 3600, "outcome": "enriched"} for _ in range(2)]
        + [{"source": "checkmk", "created_at": now, "outcome": "enriched"} for _ in range(20)]
    )
    out = dashboard._source_time_48h(rows, now=now)
    assert out["storm_cols"] == [23]  # the 20-alert bucket, not the two 2-alert baseline buckets


# --- _efficacy_24h() ---

def test_efficacy_24h_counts_problems_and_recoveries():
    rows = [
        {"severity": "warning"}, {"severity": "critical"}, {"severity": "ok"},
    ]
    app = make_app_stub_metrics(duplicates=7)
    out = dashboard._efficacy_24h(app, rows, [])
    assert out["problems"] == 2
    assert out["recovered_problems"] == 1
    assert out["deduped"] == 7


def test_efficacy_24h_flapping_subjects_counts_flag():
    noisiest = [{"flapping": True}, {"flapping": False}, {"flapping": True}]
    app = make_app_stub_metrics()
    out = dashboard._efficacy_24h(app, [], noisiest)
    assert out["flapping_subjects"] == 2


def make_app_stub_metrics(duplicates=0):
    return types.SimpleNamespace(metrics=types.SimpleNamespace(duplicates=duplicates))


# --- FakeApp harness for build_stats / render_* ---

class FakeMetrics:
    def __init__(self, duplicates=0, recovered=0, queue_depth=0, failures=None):
        self.duplicates = duplicates
        self.recovered = recovered
        self.queue_depth = queue_depth
        self.failures = failures or {}


class FakeWall:
    def __init__(self, t=100000.0):
        self.t = t
    def __call__(self):
        return self.t


def make_app(store, metrics=None, wall=None, **overrides):
    wall = wall or FakeWall()
    defaults = dict(
        store=store, metrics=metrics or FakeMetrics(), wall_clock=wall,
        start_wall=wall.t - 3600, version="0.1.0-test", queue_max=20, concurrency=1,
        collector_impls={"logs": "null", "containers": "null", "metrics": "null"},
        collector_health=None,
        plane_info={"private": {"model": "local-model"}, "knowledge": {"enabled": False}},
        delivery_adapters=["stdout"],
        logo_bytes=b"\x89PNG", favicon_data_uri="data:image/png;base64,AAAA",
    )
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


# --- build_stats() contract shape ---

def test_build_stats_top_level_keys(store):
    app = make_app(store)
    s = dashboard.build_stats(app)
    for key in ("uptime_s", "version", "totals", "window_24h", "fail_stages_24h",
                "by_source_24h", "by_category_24h", "by_severity_24h", "planes",
                "queue", "collectors", "delivery", "spark_48h"):
        assert key in s, key


def test_build_stats_totals_keys(store):
    app = make_app(store)
    totals = dashboard.build_stats(app)["totals"]
    for key in ("ingested", "delivered_enriched", "delivered_raw", "duplicates",
                "recovered", "shed", "undelivered_now"):
        assert key in totals, key


def test_build_stats_window_24h_keys(store):
    app = make_app(store)
    w = dashboard.build_stats(app)["window_24h"]
    for key in ("ingested", "enriched_rate", "raw_rate", "p50_latency_ms",
                "p95_latency_ms", "max_latency_ms", "deadline_breaches",
                "tokens_in", "tokens_out", "redactions"):
        assert key in w, key


def test_build_stats_empty_store_has_zeroed_totals(store):
    app = make_app(store)
    s = dashboard.build_stats(app)
    assert s["totals"] == {
        "ingested": 0, "delivered_enriched": 0, "delivered_raw": 0,
        "duplicates": 0, "recovered": 0, "shed": 0, "undelivered_now": 0,
    }
    assert s["window_24h"]["ingested"] == 0
    assert s["window_24h"]["enriched_rate"] == 0.0
    assert s["window_24h"]["p50_latency_ms"] is None  # no data -- not a fabricated 0


def test_build_stats_undelivered_now_reflects_received_rows(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    store.persist("k2", "p")
    store.mark_delivered("k1", "enriched")
    app = make_app(store, wall=wall)
    s = dashboard.build_stats(app)
    assert s["totals"]["undelivered_now"] == 1  # k2 only
    assert s["totals"]["delivered_enriched"] == 1


def test_build_stats_undelivered_now_survives_restart_semantics(store):
    # The whole point of SQLite-backed totals: a fresh
    # Store handle over the SAME file still reports the right undelivered
    # count -- it comes from a live SQL count, not an in-memory counter that
    # would reset.
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    app = make_app(store, wall=wall, metrics=FakeMetrics())  # fresh Metrics() == "restarted"
    s = dashboard.build_stats(app)
    assert s["totals"]["undelivered_now"] == 1


def test_build_stats_delivered_raw_includes_raw_and_enriched(store):
    # "raw_and_enriched" is a historical status from the retired raw_first
    # delivery mode -- no code path writes it anymore, so it's set directly
    # via SQL here (store.mark_delivered() only accepts the modes it still
    # writes) to prove old DB rows still count correctly.
    wall = FakeWall(1000.0)
    store.persist("k1", "p", mode="bypass")
    store._conn.execute("UPDATE alerts SET status = 'delivered_raw_and_enriched' WHERE key = 'k1'")
    store._conn.commit()
    app = make_app(store, wall=wall)
    s = dashboard.build_stats(app)
    assert s["totals"]["delivered_raw"] == 1


def test_build_stats_window_24h_excludes_rows_older_than_24h():
    # A dedicated Store clocked by the SAME FakeWall as `app.wall_clock` --
    # the fixture's default Store uses real time.time(), which would make
    # "now" (a small FakeWall value) meaningless against real created_at
    # timestamps.
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    s.persist("old", "p")
    s.record_stats("old", outcome="enriched")
    wall.t = 1000.0 + 100000  # far more than 24h later
    s.persist("new", "p")
    s.record_stats("new", outcome="enriched")
    app = make_app(s, wall=wall)
    stats = dashboard.build_stats(app)
    assert stats["window_24h"]["ingested"] == 1  # only "new"
    s.close()


def test_build_stats_enriched_rate_and_raw_rate(store):
    wall = FakeWall(1000.0)
    for i in range(3):
        store.persist(f"e{i}", "p")
        store.record_stats(f"e{i}", outcome="enriched")
    store.persist("r0", "p")
    store.record_stats("r0", outcome="raw")
    app = make_app(store, wall=wall)
    w = dashboard.build_stats(app)["window_24h"]
    assert w["enriched_rate"] == pytest.approx(0.75)
    assert w["raw_rate"] == pytest.approx(0.25)


def test_build_stats_latency_percentiles_from_recorded_rows(store):
    wall = FakeWall(1000.0)
    for i, lat in enumerate([100, 200, 300, 400, 500]):
        store.persist(f"k{i}", "p")
        store.record_stats(f"k{i}", outcome="enriched", latency_ms=lat)
    app = make_app(store, wall=wall)
    w = dashboard.build_stats(app)["window_24h"]
    assert w["p50_latency_ms"] == 300
    assert w["max_latency_ms"] == 500


def test_build_stats_deadline_breaches_counts_fail_stage(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    store.record_stats("k1", outcome="raw", fail_stage="deadline")
    store.persist("k2", "p")
    store.record_stats("k2", outcome="raw", fail_stage="llm")
    app = make_app(store, wall=wall)
    w = dashboard.build_stats(app)["window_24h"]
    assert w["deadline_breaches"] == 1
    assert dashboard.build_stats(app)["fail_stages_24h"] == {"deadline": 1, "llm": 1}


def test_build_stats_tokens_and_redactions_summed(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    store.record_stats("k1", outcome="enriched", tokens_in=100, tokens_out=40, redaction_count=2)
    store.persist("k2", "p")
    store.record_stats("k2", outcome="enriched", tokens_in=50, tokens_out=10, redaction_count=1)
    app = make_app(store, wall=wall)
    w = dashboard.build_stats(app)["window_24h"]
    assert w["tokens_in"] == 150
    assert w["tokens_out"] == 50
    assert w["redactions"] == 3


def test_build_stats_by_source_category_severity_breakdowns(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p", source="checkmk", category="container", severity="critical")
    store.persist("k2", "p", source="checkmk", category="hardware", severity="warning")
    store.persist("k3", "p", source="grafana", category="container", severity="critical")
    app = make_app(store, wall=wall)
    s = dashboard.build_stats(app)
    assert s["by_source_24h"] == {"checkmk": 2, "grafana": 1}
    assert s["by_category_24h"] == {"container": 2, "hardware": 1}
    assert s["by_severity_24h"] == {"critical": 2, "warning": 1}


def test_build_stats_window_24h_exact_enriched_and_raw_counts(store):
    wall = FakeWall(1000.0)
    for i in range(3):
        store.persist(f"e{i}", "p")
        store.record_stats(f"e{i}", outcome="enriched")
    store.persist("r0", "p")
    store.record_stats("r0", outcome="raw")
    app = make_app(store, wall=wall)
    w = dashboard.build_stats(app)["window_24h"]
    assert w["enriched"] == 3
    assert w["raw"] == 1


def test_build_stats_assist_24h_counts_attempted_ok_failed(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    store.record_stats("k1", outcome="enriched", assist_status="done")
    store.persist("k2", "p")
    store.record_stats("k2", outcome="enriched", assist_status="failed")
    store.persist("k3", "p")
    store.record_stats("k3", outcome="enriched", assist_status="deferred")
    store.persist("k4", "p")  # never touched assist -- not "attempted"
    app = make_app(store, wall=wall)
    assist = dashboard.build_stats(app)["assist_24h"]
    assert assist == {"attempted": 3, "ok": 1, "failed": 1}


def test_build_stats_assist_24h_empty_store_is_zeroed(store):
    app = make_app(store)
    assert dashboard.build_stats(app)["assist_24h"] == {"attempted": 0, "ok": 0, "failed": 0}


def test_build_stats_top_signatures_24h_present_in_shape(store):
    wall = FakeWall(1000.0)
    for i in range(3):
        store.persist(f"k{i}", f"host / vector / crit {i}", fingerprint="fp-a")
    app = make_app(store, wall=wall)
    top = dashboard.build_stats(app)["top_signatures_24h"]
    assert top and top[0]["fingerprint"] == "fp-a"
    assert top[0]["count"] == 3


def test_build_stats_planes_private_model_and_call_stats(store):
    wall = FakeWall(1000.0)
    store.persist("k1", "p")
    store.record_stats("k1", outcome="enriched", llm_ms=250)
    store.persist("k2", "p")
    store.record_stats("k2", outcome="raw", fail_stage="llm")
    app = make_app(store, wall=wall)
    planes = dashboard.build_stats(app)["planes"]
    assert planes["private"]["model"] == "local-model"
    assert planes["private"]["calls_24h"] == 1  # only k1 has llm_ms
    assert planes["private"]["errors_24h"] == 1  # k2's fail_stage == "llm"
    assert planes["knowledge"]["enabled"] is False


def test_build_stats_collectors_reports_null_pill_for_unwired_client(store):
    app = make_app(store)  # default collector_impls all "null"
    collectors = dashboard.build_stats(app)["collectors"]
    assert collectors["logs"]["impl"] == "null"
    assert collectors["logs"]["ok"] is True


def test_build_stats_collectors_reflects_health_tracker(store):
    from nuncio.clients import CollectorHealth
    health = CollectorHealth()
    with pytest.raises(RuntimeError):
        health.wrap("logs", lambda: (_ for _ in ()).throw(RuntimeError("boom")))()
    app = make_app(store, collector_health=health,
                    collector_impls={"logs": "loki", "containers": "null", "metrics": "null"})
    collectors = dashboard.build_stats(app)["collectors"]
    assert collectors["logs"]["impl"] == "loki"
    assert collectors["logs"]["ok"] is False
    assert collectors["logs"]["fail_24h"] == 1


# --- _impl_label() / collectors "off" display (never print the literal
# "null" sentinel or a bare None in the dashboard, P2) ---

def test_impl_label_maps_null_sentinel_to_off():
    assert dashboard._impl_label("null") == "off"


def test_impl_label_maps_none_to_off():
    assert dashboard._impl_label(None) == "off"


def test_impl_label_maps_empty_string_to_off():
    assert dashboard._impl_label("") == "off"


def test_impl_label_passes_through_a_real_impl_name():
    assert dashboard._impl_label("loki") == "loki"


def test_build_stats_collectors_unwired_client_has_off_label_and_not_configured(store):
    app = make_app(store)  # default collector_impls all "null"
    collectors = dashboard.build_stats(app)["collectors"]
    assert collectors["logs"]["label"] == "off"
    assert collectors["logs"]["configured"] is False
    # the raw sentinel stays available too, for callers that still want it
    assert collectors["logs"]["impl"] == "null"


def test_build_stats_collectors_wired_client_has_impl_as_label_and_configured(store):
    app = make_app(store, collector_impls={"logs": "loki", "containers": "null", "metrics": "null"})
    collectors = dashboard.build_stats(app)["collectors"]
    assert collectors["logs"]["label"] == "loki"
    assert collectors["logs"]["configured"] is True


def test_build_stats_queue_and_delivery_blocks(store):
    app = make_app(store, metrics=FakeMetrics(queue_depth=3, failures={"delivery": 2}))
    s = dashboard.build_stats(app)
    assert s["queue"] == {"depth": 3, "max": 20, "concurrency": 1}
    assert s["delivery"] == {"adapters": ["stdout"], "fail_24h": 2}


def test_build_stats_spark_48h_shape(store):
    app = make_app(store)
    spark = dashboard.build_stats(app)["spark_48h"]
    assert len(spark["ingested"]) == 48
    assert len(spark["raw_fallback"]) == 48
    assert len(spark["p95_ms"]) == 48


def test_build_stats_spark_48h_buckets_by_hour():
    wall = FakeWall(0.0)
    s = Store(":memory:", clock=wall)
    s.persist("k1", "p")  # created_at = 0 -> bucket 0 (oldest)
    wall.t = 48 * 3600.0 - 1  # just before "now" -> last bucket
    s.persist("k2", "p")
    app = make_app(s, wall=FakeWall(48 * 3600.0))
    spark = dashboard.build_stats(app)["spark_48h"]
    assert spark["ingested"][0] == 1
    assert spark["ingested"][-1] == 1
    s.close()


def test_build_stats_uptime_s_from_start_wall(store):
    wall = FakeWall(2000.0)
    app = make_app(store, wall=wall, start_wall=1000.0)
    s = dashboard.build_stats(app)
    assert s["uptime_s"] == 1000


def test_build_stats_version_passthrough(store):
    app = make_app(store, version="9.9.9")
    assert dashboard.build_stats(app)["version"] == "9.9.9"


def test_render_stats_json_is_valid_json(store):
    app = make_app(store)
    body = dashboard.render_stats_json(app)
    parsed = json.loads(body)
    assert "totals" in parsed


# --- render_alerts_json() ---

def test_render_alerts_json_shape(store):
    store.persist("k1", "host01 / vector / CRIT", source="checkmk", category="container",
                   severity="critical")
    store.record_stats("k1", outcome="enriched", latency_ms=500, tokens_in=10, tokens_out=5)
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app))
    assert len(body["alerts"]) == 1
    a = body["alerts"][0]
    for key in ("key", "created_at", "source", "category", "severity", "outcome",
                "fail_stage", "latency_ms", "tokens_in", "tokens_out", "summary"):
        assert key in a
    assert a["summary"] == "host01 / vector / CRIT"


def test_render_alerts_json_filters_by_source(store):
    store.persist("a", "p", source="checkmk")
    store.persist("b", "p", source="grafana")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app, source="checkmk"))
    assert [a["key"] for a in body["alerts"]] == ["a"]


def test_render_alerts_json_filters_by_outcome(store):
    store.persist("a", "p")
    store.record_stats("a", outcome="enriched")
    store.persist("b", "p")
    store.record_stats("b", outcome="raw")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app, outcome="raw"))
    assert [a["key"] for a in body["alerts"]] == ["b"]


def test_render_alerts_json_limit_clamped_to_sane_bounds(store):
    for i in range(5):
        store.persist(f"k{i}", "p")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app, limit="not-a-number"))
    assert len(body["alerts"]) <= 50  # falls back to the default, not a crash


def test_render_alerts_json_derives_host_service_from_key_when_columns_null(store):
    # Old rows persisted before host/service columns existed -- host/service
    # must still populate on the wire from the idempotency key.
    store.persist("checkmk:router.kirits.net/Interface 5/0/PROBLEM/1",
                   "[PROBLEM] router.kirits.net / Interface 5 — WARNING", source="checkmk")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app))
    a = body["alerts"][0]
    assert a["host"] == "router.kirits.net"
    assert a["service"] == "Interface 5"


def test_render_alerts_json_sends_subject_fallback_only_when_host_and_service_both_none(store):
    store.persist("k1", "just some unstructured text, no dash here")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app))
    a = body["alerts"][0]
    assert a["host"] is None and a["service"] is None
    assert a["subject"]  # non-empty fallback string present


def test_render_alerts_json_omits_subject_fallback_when_host_present(store):
    store.persist("checkmk:svr/PostgreSQL infisical/1/PROBLEM/1", "p", source="checkmk", host="svr")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app))
    a = body["alerts"][0]
    assert a["host"] == "svr"
    assert a.get("subject") is None


def test_render_alerts_json_drops_fingerprint_field(store):
    store.persist("k1", "p", fingerprint="fp-a")
    app = make_app(store)
    body = json.loads(dashboard.render_alerts_json(app))
    assert "fingerprint" not in body["alerts"][0]


def test_render_alerts_json_never_includes_bundle_or_enrichment_text(store):
    store.persist("k1", "safe payload")
    store.set_bundle("k1", "## Logs\nsome bundle content that should not appear here")
    store.record_stats("k1", outcome="enriched", enrichment="the delivered analysis text")
    app = make_app(store)
    body = dashboard.render_alerts_json(app)
    assert b"bundle content" not in body
    assert b"delivered analysis" not in body


# --- render_alert_detail_html() ---

def test_render_alert_detail_html_returns_none_for_missing_key(store):
    app = make_app(store)
    assert dashboard.render_alert_detail_html(app, "nope") is None


def test_render_alert_detail_html_contains_key_fields(store):
    store.persist("checkmk:host01/vector/1", "raw redacted text", source="checkmk",
                   category="container", severity="critical")
    store.set_bundle("checkmk:host01/vector/1", "## Correlated\n(none)")
    store.record_stats("checkmk:host01/vector/1", outcome="enriched", latency_ms=1200, llm_ms=800,
                        tokens_in=100, tokens_out=40, redaction_count=2, bundle_bytes=42,
                        enrichment="SUMMARY: ok\nSEVERITY: low")
    app = make_app(store)
    html = dashboard.render_alert_detail_html(app, "checkmk:host01/vector/1").decode()
    assert "checkmk:host01/vector/1" in html
    assert "checkmk" in html
    assert "container" in html
    assert "critical" in html
    assert "1200 ms" in html
    assert "800 ms" in html
    assert "raw redacted text" in html
    assert "Correlated" in html
    assert "SUMMARY: ok" in html
    assert "local-model" in html  # plane/model


def test_render_alert_detail_html_has_serif_headline_and_assist_stage(store):
    store.persist("k1", "host01 disk full\nmore detail", source="checkmk")
    store.record_stats("k1", outcome="enriched", assist_status="done", assist_insight="an assist insight")
    app = make_app(store)
    html = dashboard.render_alert_detail_html(app, "k1").decode()
    assert 'class="headline"' in html
    assert "host01 disk full" in html  # first line only
    assert "Assist status" in html  # new kv row
    assert "done" in html
    assert "an assist insight" in html
    assert '<span class="n">04</span>' in html  # numbered stage block


def test_render_alert_detail_html_assist_unused_shows_muted_line(store):
    store.persist("k1", "raw only, nothing else recorded yet")
    app = make_app(store)
    html = dashboard.render_alert_detail_html(app, "k1").decode()
    assert "assist plane not used for this alert" in html


def test_render_alert_detail_html_never_leaks_a_secret(store):
    from nuncio.redactor import redact
    secret_line = "connect failed password=Sup3rS3cret! to db"
    redacted_payload, _ = redact(secret_line)
    store.persist("k1", redacted_payload)
    store.set_bundle("k1", redact("VECTOR_O2_PASSWORD=Sup3rS3cretHunter2 rejected")[0])
    store.record_stats("k1", outcome="enriched",
                        enrichment=redact("token=ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 leaked")[0])
    app = make_app(store)
    html = dashboard.render_alert_detail_html(app, "k1")
    assert b"Sup3rS3cret!" not in html
    assert b"Sup3rS3cretHunter2" not in html
    assert b"ghp_" b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in html
    assert b"REDACTED" in html


def test_render_alert_detail_html_handles_missing_optional_fields_gracefully(store):
    store.persist("k1", "raw only, nothing else recorded yet")
    app = make_app(store)
    html = dashboard.render_alert_detail_html(app, "k1").decode()
    assert "k1" in html
    assert "(none)" in html  # no bundle/enrichment yet


# --- render_dashboard_html() ---

def test_render_dashboard_html_under_48kb(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app)
    assert len(html) < 48_000


def test_render_dashboard_html_is_self_contained_no_external_refs(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    for banned in ("cdn.", "googleapis.com", "fonts.google", "unpkg.com", "jsdelivr"):
        assert banned not in html


def test_render_dashboard_html_contains_title_and_nav(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert "Nuncio" in html
    assert "Overview" in html
    assert "Settings" in html
    assert 'class="active"' in html


def test_render_dashboard_html_includes_favicon_link_when_present(store):
    app = make_app(store, favicon_data_uri="data:image/png;base64,AAAA")
    html = dashboard.render_dashboard_html(app).decode()
    assert 'rel="icon"' in html
    assert "data:image/png;base64,AAAA" in html


def test_render_dashboard_html_omits_favicon_link_when_absent(store):
    app = make_app(store, favicon_data_uri="")
    html = dashboard.render_dashboard_html(app).decode()
    assert 'rel="icon"' not in html


def test_render_dashboard_html_never_inlines_raster_logo_bytes(store):
    # Nameplate: the brand bird is referenced by URL (GET /logo.png), and the
    # inline trace glyph remains as a hidden onerror fallback. Neither embeds
    # raster bytes -- the page must never balloon by inlining the logo asset.
    # The only base64 content allowed inline is the (tiny) favicon data-URI.
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'class="mark" src="/logo.png"' in html  # the bird, by URL
    assert "<svg class=\"mark\"" in html  # hidden onerror fallback
    assert html.count("base64") == 1  # exactly the favicon href, nothing bigger


def test_render_dashboard_html_polls_stats_and_alerts_json(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert "stats.json" in html
    assert "alerts.json" in html
    assert "10000" in html  # 10s poll interval


def test_render_dashboard_html_has_verdict_and_signal_path(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'id="verdict"' in html
    assert 'id="sigpath"' in html
    assert 'id="sp-ingested"' in html
    assert 'id="sp-enriched"' in html
    assert 'id="sp-raw"' in html
    assert 'id="sp-delivered"' in html


def test_render_dashboard_html_has_invariant_chips(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'class="chips"' in html
    assert 'id="chip-undelivered"' in html
    assert 'id="chip-enriched-rate"' in html
    assert 'id="chip-breaches"' in html
    assert 'id="chip-queue"' in html


def test_render_dashboard_html_has_bar_lists_and_signatures(store):
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'id="bars-source"' in html
    assert 'id="bars-category"' in html
    assert 'id="bars-severity"' in html
    assert 'id="bars-failstage"' in html
    assert 'id="signatures"' in html


def test_render_dashboard_html_has_volcost_counters_and_stripchart(store):
    # Pass-2: the 7 volume/cost cards collapsed into one meter rail (4 cells)
    # + a single ruled counters line -- assist now lives in that counters
    # line's text, not a standalone card/id.
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'id="vccnt"' in html
    assert 'id="stripchart"' in html
    assert 'class="rail"' in html


def test_render_dashboard_html_recent_alerts_table_scoped_wide(store):
    # the min-width:640px bug fix -- only the Recent Alerts wrapper gets the
    # "wide" class, not every .tablewrap on the page.
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'class="tablewrap wide"' in html
    assert html.count('class="tablewrap wide"') == 1


def test_render_dashboard_html_supports_dark_and_light_theme(store):
    # Dark is the hero/default (:root {} with no media query); light is the
    # explicit prefers-color-scheme override -- plus a manual `data-theme`
    # attribute override in both directions for an in-page theme toggle.
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert "prefers-color-scheme:light" in html.replace(" ", "")
    assert 'data-theme="dark"' in html
    assert 'data-theme="light"' in html


# =====================================================================
# REV 3 Phase C -- shell.py's header_html() grows a `tape_html=None`
# parameter so the settings page can swap the tape span for a lock widget
# (nuncio/web/settings.py) without touching shell.py's dashboard consumer.
# The dashboard NEVER passes tape_html, so its render must stay byte-for-
# byte identical to the pre-Phase-C (post-Phase-A/B) render. A hand-copied
# multi-KB HTML fixture would be unreviewable noise, so this pins a SHA-256
# of the exact `make_app`-built render captured immediately before Phase C's
# edits landed -- any future change to shared CSS/JS/markup that reaches the
# dashboard (intentional or not) will flip this hash and fail loudly.
# =====================================================================
#
# REV 3 Phase D update: `--glow` (root token, shared to every page including
# the dashboard) moved 18px -> 22px as part of the prominence bump -- same
# character count, so the LENGTH baseline is untouched, but the hash moves.
# dashboard.py itself is still untouched; only the shared root token did.

_DASHBOARD_BASELINE_LEN = 34386
_DASHBOARD_BASELINE_SHA256 = "044bc04c43d319d88825432145e1036c242968389c3ed35d6c084b9d5924fbc1"


def test_render_dashboard_html_byte_identical_to_pre_phase_c_baseline(store):
    import hashlib
    app = make_app(store)
    html = dashboard.render_dashboard_html(app)
    assert len(html) == _DASHBOARD_BASELINE_LEN
    assert hashlib.sha256(html).hexdigest() == _DASHBOARD_BASELINE_SHA256


def test_render_dashboard_html_still_has_the_tape_span(store):
    # header_html()'s default tape_html=None must still emit the exact
    # dashboard telemetry tape -- only settings.py opts into the lock widget.
    app = make_app(store)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'id="tape"' in html
    assert "reading" in html


def test_header_html_default_tape_html_is_byte_identical_to_the_shipped_span():
    from nuncio.web import shell
    assert shell.header_html("overview") == (
        '<div class="topbar"><div class="wrap row">'
        + shell._LOGO_IMG + shell._MARK_SVG +
        '<span class="wordmark">Nuncio</span>'
        '<span class="rule"></span>'
        '<span class="tape" id="tape">reading&hellip;</span>'
        + shell.nav_html("overview") +
        '</div></div>'
    )


def test_header_html_accepts_a_tape_html_override_for_the_lock_widget():
    from nuncio.web import shell
    out = shell.header_html("settings", tape_html='<span id="lockwrap">LOCK</span>')
    assert '<span id="lockwrap">LOCK</span>' in out
    assert 'id="tape"' not in out
