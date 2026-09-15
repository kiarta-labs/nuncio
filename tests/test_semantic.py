"""C1 token-Jaccard near-dup similarity + correlate hook + metrics."""
from nuncio import semantic
from nuncio.correlate import _services_conflict, rank_correlated
from nuncio.fingerprint import fingerprint
from nuncio.server import Metrics


def _row(alert, payload, created_at=1000.0, source="checkmk", category="container",
         severity="warning", host="host01", service=None):
    return ("k", payload, created_at, source, category, severity,
            fingerprint(alert), host,
            service if service is not None else alert.get("service"))


def test_tokenize_drops_stops_and_short_tokens():
    assert "the" not in semantic.tokenize("the disk is full")
    assert "disk" in semantic.tokenize("disk FULL!")
    assert semantic.tokenize("") == frozenset()
    assert semantic.tokenize(None) == frozenset()


def test_jaccard_synonym_blind_documented():
    # Known limit, pinned: synonyms score ~0 (the embedding-upgrade trigger).
    assert semantic.jaccard(semantic.tokenize("disk full"),
                            semantic.tokenize("storage exhausted")) == 0.0
    assert semantic.jaccard(semantic.tokenize("aaa bbb"), semantic.tokenize("aaa bbb")) == 1.0
    assert semantic.jaccard(set(), {"a"}) == 0.0


def test_bonus_ramps_and_caps():
    assert semantic.bonus_for(0.29) == 0.0
    assert semantic.bonus_for(0.30) > 0.0
    assert semantic.bonus_for(1.0) == semantic.SIM_MAX_SCORE
    assert semantic.bonus_for(0.5) == semantic.SIM_MAX_SCORE  # 0.5*3 capped


def test_rank_adds_wording_bonus_inside_gate():
    alert = {"host": "host01", "service": "web",
             "output": "container restarting frequently, crash loop backoff",
             "severity": "warning"}
    rows = [_row(alert, "container keeps restarting, backoff crashloop on web")]
    lines = rank_correlated(rows, alert, now=2000.0)
    assert len(lines) == 1
    assert "same service" in lines[0]
    assert "similar wording" in lines[0]


def test_rank_no_bonus_below_threshold():
    alert = {"host": "host01", "service": "web",
             "output": "container restarting frequently here",
             "severity": "warning"}
    rows = [_row(alert, "unrelated snmp plugin flap on switch nine")]
    lines = rank_correlated(rows, alert, now=2000.0)
    assert len(lines) == 1  # still gated (same service), ranked without bonus
    assert "similar wording" not in lines[0]


def test_veto_blocks_bonus_but_keeps_gate():
    alert = {"host": "host01", "service": "web",
             "output": "connection timeout calling backend database",
             "severity": "warning"}
    # same fingerprint (same host+output shape), different service
    rows = [_row(alert, "connection timeout calling backend database on db",
                 service="db")]
    lines = rank_correlated(rows, alert, now=2000.0)
    assert len(lines) == 1
    assert "same recurring signature" in lines[0]  # gate authority untouched
    assert "similar wording" not in lines[0]  # vetoed


def test_veto_ignores_case_only_drift():
    alert = {"host": "host01", "service": "DB-Primary",
             "output": "connection pool exhausted, waits climbing",
             "severity": "warning"}
    rows = [_row(alert, "connection pool exhausted waits climbing high",
                 service="db-primary")]
    lines = rank_correlated(rows, alert, now=2000.0)
    assert "similar wording" in lines[0]


def test_services_conflict_unit_cases():
    assert _services_conflict("web", None, "db", None) is True
    assert _services_conflict("web", None, "web", None) is False
    assert _services_conflict(None, None, "db", None) is False  # missing: no veto
    assert _services_conflict("web", None, None, None) is False
    assert _services_conflict(None, "unit-a", None, "unit-b") is True
    assert _services_conflict(None, "unit-a", None, "unit-a") is False


def test_distribution_records_scored_pairs():
    before = semantic.distribution()["total"]
    alert = {"host": "h", "service": "s", "output": "disk latency high", "severity": "warning"}
    rank_correlated([_row(alert, "disk latency high on s")], alert, now=2000.0)
    after = semantic.distribution()
    assert after["total"] == before + 1
    assert after["n"] >= 1
    assert after["max"] > 0.0


def test_metrics_render_includes_semantic_lines():
    alert = {"host": "h", "service": "s", "output": "disk latency high", "severity": "warning"}
    rank_correlated([_row(alert, "disk latency high on s")], alert, now=2000.0)
    text = Metrics().render()
    assert "nuncio_semantic_pairs_observed_total" in text
    assert "nuncio_semantic_similarity_p50" in text
    assert "nuncio_semantic_similarity_max" in text
