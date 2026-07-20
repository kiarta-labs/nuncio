"""Level-B context collectors. Each is read-only, bounded, and NEVER
raises — a failed/slow collector degrades to a «context unavailable» marker.
Data sources are injected callables so collectors are testable offline."""
from nuncio.collectors import (
    collect_correlated, collect_recent_logs, collect_container_state,
    collect_metrics, collect_kernel, collect_recurrence, collect_history, UNAVAIL,
)
from nuncio.fingerprint import fingerprint
from nuncio.store import Store


class FakeWall:
    def __init__(self, t=1000.0): self.t = t
    def __call__(self): return self.t


ALERT = {"host": "host01", "service": "infisical-postgres", "state": "CRIT",
         "output": "FATAL: all AuxiliaryProcs are in use"}


def test_correlated_lists_recent_other_alerts():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0; s.persist("gpf", "[PROBLEM] host01 GPF escalation")
    wall.t = 1000.0; s.persist("self", "the current one")
    section = collect_correlated(s, alert_key="self", now=1000.0)
    assert "GPF escalation" in section
    assert "the current one" not in section  # self excluded
    s.close()


def test_correlated_none_case():
    s = Store(":memory:", clock=FakeWall(1000.0))
    section = collect_correlated(s, alert_key="self", now=1000.0)
    assert "none" in section.lower()
    s.close()


def test_recent_logs_capped_and_labeled():
    lines = [f"line {i}" for i in range(500)]
    section = collect_recent_logs(lambda host, unit, w: lines, ALERT, max_lines=100)
    assert section.count("\n") <= 105  # capped near 100 lines + header
    assert "host01" in section and "infisical-postgres" in section


def test_recent_logs_degrades_on_exception():
    def boom(*a):
        raise RuntimeError("log store down")
    section = collect_recent_logs(boom, ALERT)
    assert section == UNAVAIL.format("recent_logs")


def test_container_state_summarizes():
    def inspect(name):
        return {"status": "restarting", "restart_count": 5, "exit_code": 1,
                "started_at": "2026-07-17", "logs": ["boot line", "crash line"]}
    section = collect_container_state(inspect, ALERT)
    assert "restarting" in section and "restart" in section.lower()
    assert "crash line" in section


def test_container_state_not_found():
    section = collect_container_state(lambda n: None, ALERT)
    assert "not found" in section.lower()


def test_metrics_degrades_on_exception():
    def boom(*a):
        raise RuntimeError("checkmk down")
    assert collect_metrics(boom, ALERT) == UNAVAIL.format("metrics")


def test_kernel_storm_is_summarized_not_dumped():
    flood = [f"GPF at addr {i}" for i in range(1000)]
    section = collect_kernel(lambda host, fac, w: flood, ALERT, max_lines=50)
    assert "more lines" in section  # sampled, not the full 1000
    assert section.count("\n") < 60


def test_kernel_degrades_on_exception():
    def boom(*a):
        raise RuntimeError("no journal")
    assert collect_kernel(boom, ALERT) == UNAVAIL.format("kernel")


# --- relevance-ranked recent logs (resolver + relevance integration) ---

def test_recent_logs_keeps_on_topic_old_line_over_noise():
    noise = [f"GET /health 200 {i}" for i in range(300)]
    lines = ["FATAL: all AuxiliaryProcs are in use"] + noise
    section = collect_recent_logs(lambda h, u, w: lines, ALERT, max_lines=50)
    assert "AuxiliaryProcs" in section  # naive tail-50 would have dropped it


def test_recent_logs_output_stays_chronological():
    lines = ["ERROR first", *[f"noise {i}" for i in range(150)], "ERROR last"]
    section = collect_recent_logs(lambda h, u, w: lines, ALERT, max_lines=10)
    assert section.index("ERROR first") < section.index("ERROR last")


def test_recent_logs_uses_resolved_unit_name():
    seen = {}
    def q(host, unit, w):
        seen["unit"] = unit
        return ["ok"]
    alert = {"host": "host01", "service": "Docker container grafana", "output": "down"}
    collect_recent_logs(q, alert)
    assert seen["unit"] == "grafana"  # normalized, not the raw CheckMK name


def test_container_state_uses_resolved_name():
    seen = {}
    def inspect(name):
        seen["name"] = name
        return {"status": "running", "restart_count": 0, "exit_code": 0,
                "started_at": "t", "logs": []}
    collect_container_state(inspect, {"service": "Docker container vector"})
    assert seen["name"] == "vector"


# --- annotated, scored correlation ---

def test_correlated_with_alert_annotates_why():
    # Ratified model: host-only co-location (via the legacy summary-regex
    # fallback -- these rows carry no `host` column) is a GROUPING label
    # ("also active on <host>"), never a causal "same host" reason -- but a
    # same-service row DOES gate causally.
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 940.0; s.persist("svc", "[PROBLEM] infisical-postgres FATAL wedge")
    wall.t = 950.0; s.persist("gpf", "[PROBLEM] host01 GPF escalation")
    wall.t = 960.0; s.persist("other", "[PROBLEM] workstation01 CPU high")
    wall.t = 1000.0; s.persist("self", "the current one")
    section = collect_correlated(s, alert_key="self", now=1000.0, alert=ALERT)
    assert "same service" in section       # infisical-postgres row gates causally
    assert "also active on host01" in section  # host01 GPF: grouping label only
    assert "workstation01" not in section  # unrelated, different host -- excluded
    svc_pos = section.index("infisical-postgres FATAL")
    gpf_pos = section.index("GPF")
    assert svc_pos < gpf_pos                # tier 0 (causal) sorts before tier 1 (grouping)
    s.close()


def test_correlated_without_alert_keeps_legacy_behavior():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0; s.persist("gpf", "[PROBLEM] host01 GPF escalation")
    section = collect_correlated(s, alert_key="self", now=1000.0)
    assert "GPF escalation" in section and "same host" not in section
    s.close()


def test_correlated_with_alert_and_empty_ranked_shows_none_not_raw_rows():
    # Regression (C1): an instance-less alert (host "-", so a_host is None
    # and no gate key can ever hit) plus only unrelated rows must render the
    # "(none related...)" placeholder -- NOT fall through to the legacy raw
    # listing, which would leak every unrelated row's summary to the LLM.
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 950.0
    s.persist("svr", "[PROBLEM] svr disk high", host="svr", service="disk")
    wall.t = 960.0
    s.persist("canary", "[PROBLEM] canary check failed", host="canary01", service="canary")
    wall.t = 970.0
    s.persist("grafana", "[PROBLEM] grafana alert fired", host="grafana01", service="grafana-alert")
    wall.t = 1000.0
    instanceless_alert = {"host": "-", "service": "GPU escalation", "state": "CRIT",
                           "output": "general-protection-fault storm"}
    section = collect_correlated(s, alert_key="self", now=1000.0, alert=instanceless_alert)
    assert "none related" in section.lower()
    assert "svr" not in section
    assert "canary" not in section
    assert "grafana" not in section
    s.close()


def test_correlated_with_alert_degrades_on_store_failure():
    class Boom:
        def recent(self, **kw):
            raise RuntimeError("db down")
    assert collect_correlated(Boom(), "k", 1000.0, alert=ALERT) == UNAVAIL.format("correlated")


# --- collect_recurrence ---

def test_recurrence_first_occurrence():
    s = Store(":memory:", clock=FakeWall(1000.0))
    section = collect_recurrence(s, ALERT, now=1000.0, window_s=7200)
    assert "first occurrence in 2h" in section
    s.close()


def test_recurrence_nth_occurrence():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    fp = fingerprint(ALERT)
    wall.t = 900.0; s.persist("k1", "p", fingerprint=fp)
    wall.t = 950.0; s.persist("k2", "p", fingerprint=fp)
    section = collect_recurrence(s, ALERT, now=1000.0, window_s=7200)
    assert "2nd occurrence" in section
    assert "ago" in section
    s.close()


def test_recurrence_degrades_on_store_failure():
    class Boom:
        def fingerprint_stats(self, *a, **kw):
            raise RuntimeError("db down")
    assert collect_recurrence(Boom(), ALERT, now=1000.0) == UNAVAIL.format("recurrence")


def test_recurrence_no_signature():
    s = Store(":memory:", clock=FakeWall(1000.0))
    section = collect_recurrence(s, {"host": "h"}, now=1000.0)
    assert "no stable signature" in section
    s.close()


# --- Phase B: collect_history (store-only, wider backward window) ---

def test_history_empty_case():
    s = Store(":memory:", clock=FakeWall(1000.0))
    section = collect_history(s, "self", 1000.0, ALERT)
    assert section == "## Alert history (24h)\n(no related alerts)"
    s.close()


def test_history_lists_older_row_beyond_the_correlation_window():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    # 2h old -- outside the default back_edge_s=600 correlation window, but
    # inside the 24h history window.
    wall.t = 1000.0 - 7200.0
    s.persist("gpf", "[PROBLEM] host01 GPF escalation")
    wall.t = 1000.0
    s.persist("self", "the current one")
    section = collect_history(s, "self", 1000.0, ALERT, back_edge_s=600)
    assert "GPF escalation" in section
    assert "## Alert history (24h)" in section
    s.close()


def test_history_excludes_rows_inside_the_back_edge():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 970.0  # 30s old -- inside back_edge_s=600, must NOT appear here
    s.persist("recent", "[PROBLEM] host01 recent escalation")
    wall.t = 1000.0
    s.persist("self", "the current one")
    section = collect_history(s, "self", 1000.0, ALERT, back_edge_s=600)
    assert "recent escalation" not in section
    s.close()


def test_history_degrades_on_store_failure():
    class Boom:
        def recent(self, **kw):
            raise RuntimeError("db down")
    assert collect_history(Boom(), "k", 1000.0, ALERT) == UNAVAIL.format("history")


# --- Phase 3.5: collect_history gates too (the same causal-entity model as
# collect_correlated), and now actually receives `deps` (previously wired
# for `correlated` only -- a pre-existing inconsistency this phase fixes). ---

def test_history_gates_unrelated_same_host_rows_to_grouping_only():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 1000.0 - 7200.0
    s.persist("gpf", "[PROBLEM] host01 GPF escalation", host="host01", service="unrelated-check")
    wall.t = 1000.0
    s.persist("self", "the current one")
    section = collect_history(s, "self", 1000.0, ALERT, back_edge_s=600)
    assert "also active on host01" in section
    assert "possible root" not in section
    assert "possible symptom" not in section
    s.close()


def test_history_wires_deps_through_to_rank_correlated():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 1000.0 - 7200.0
    s.persist("dep", "[PROBLEM] infisical-postgres FATAL wedge",
              host="kprintr", service="infisical-postgres")
    wall.t = 1000.0
    s.persist("self", "the current one")
    alert = dict(ALERT, service="infisical", output="cannot connect to db")
    deps = {"infisical": ["infisical-postgres"]}
    section = collect_history(s, "self", 1000.0, alert, back_edge_s=600, deps=deps)
    assert "upstream dependency of infisical" in section
    s.close()
