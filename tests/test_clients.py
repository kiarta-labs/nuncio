"""Collector-client protocols + NullClient."""
import pytest

from nuncio.clients import CollectorHealth, ContainerClient, LogClient, MetricsClient, NullClient


def test_null_client_implements_all_three_protocols():
    n = NullClient()
    assert isinstance(n, LogClient)
    assert isinstance(n, ContainerClient)
    assert isinstance(n, MetricsClient)


def test_null_client_query_returns_empty_list_for_logs_call_shape():
    n = NullClient()
    assert n.query("host", "unit", 900) == []


def test_null_client_query_returns_empty_list_for_metrics_call_shape():
    n = NullClient()
    assert n.query("host", "service") == []


def test_null_client_inspect_returns_none():
    n = NullClient()
    assert n.inspect("any-container") is None


def test_null_client_feeds_collectors_to_the_none_found_markers():
    from nuncio.collectors import collect_recent_logs, collect_container_state, collect_metrics
    n = NullClient()
    alert = {"host": "web-1", "service": "sonarr"}
    assert "no matching log lines" in collect_recent_logs(n.query, alert)
    assert "container not found" in collect_container_state(n.inspect, alert)
    assert "(none)" in collect_metrics(n.query, alert)


# --- CollectorHealth ---

def test_collector_health_starts_empty():
    h = CollectorHealth()
    assert h.snapshot() == {}


def test_collector_health_records_success():
    h = CollectorHealth()
    wrapped = h.wrap("logs", lambda: "ok")
    assert wrapped() == "ok"
    snap = h.snapshot()
    assert snap["logs"]["ok"] is True
    assert snap["logs"]["fail_count"] == 0


def test_collector_health_records_failure_and_reraises():
    h = CollectorHealth()

    def boom():
        raise RuntimeError("connection refused")
    wrapped = h.wrap("logs", boom)
    with pytest.raises(RuntimeError):
        wrapped()
    snap = h.snapshot()
    assert snap["logs"]["ok"] is False
    assert "connection refused" in snap["logs"]["last_error"]
    assert snap["logs"]["fail_count"] == 1


def test_collector_health_fail_count_accumulates_and_ok_reflects_most_recent_call():
    h = CollectorHealth()
    wrapped_bad = h.wrap("logs", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    wrapped_good = h.wrap("logs", lambda: "ok")
    for _ in range(3):
        with pytest.raises(RuntimeError):
            wrapped_bad()
    assert h.snapshot()["logs"]["fail_count"] == 3
    assert h.snapshot()["logs"]["ok"] is False
    wrapped_good()
    assert h.snapshot()["logs"]["ok"] is True
    assert h.snapshot()["logs"]["fail_count"] == 3  # recovered, but failures stay counted


def test_collector_health_tracks_multiple_names_independently():
    h = CollectorHealth()
    h.wrap("logs", lambda: "ok")()
    wrapped_bad = h.wrap("metrics", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    with pytest.raises(RuntimeError):
        wrapped_bad()
    snap = h.snapshot()
    assert snap["logs"]["ok"] is True
    assert snap["metrics"]["ok"] is False


def test_collector_health_wrapped_passes_through_args_and_kwargs():
    h = CollectorHealth()
    wrapped = h.wrap("logs", lambda a, b, c=None: (a, b, c))
    assert wrapped(1, 2, c=3) == (1, 2, 3)
