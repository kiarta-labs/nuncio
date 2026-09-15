"""C5 past-incident RAG + calibrated confidence."""
from nuncio.collectors import collect_past_incidents
from nuncio.fingerprint import fingerprint
from nuncio.prompt import render_structured, validate_structured
from nuncio.store import Store


def _seed(store):
    fpweb = fingerprint({"host": "host01", "service": "web", "output": "down"})
    store.persist("k-root", "[FIRING] host01 / web -- down", source="checkmk",
                  category="container", severity="critical", fingerprint=fpweb,
                  host="host01", service="web")
    store.mark_delivered("k-root", "enriched")
    store.record_stats("k-root", outcome="enriched",
                       enrichment="Web service down on host01; fixed by restarting the pod.")
    store.persist("k-old", "[FIRING] host01 / web -- down", source="checkmk",
                  category="container", severity="critical", fingerprint=fpweb,
                  host="host01", service="web")
    store.mark_delivered("k-old", "raw")
    store.record_stats("k-old", outcome="raw", enrichment="")
    store.persist("k-open", "[FIRING] host01 / web -- down", source="checkmk",
                  category="container", severity="critical", fingerprint=fpweb,
                  host="host01", service="web")
    return fpweb, fingerprint({"host": "other", "service": "db", "output": "boom"})


def test_store_past_incidents_returns_redacted_first_lines_only():
    store = Store(":memory:")
    try:
        _seed(store)
        rows = store.past_incidents(fingerprint({"host": "host01", "service": "web", "output": "down"}), limit=3)
        assert len(rows) == 2  # only terminal delivered rows; 'received' excluded
        texts = [r[2] for r in rows]
        assert any(t == "Web service down on host01; fixed by restarting the pod." for t in texts)
        assert all(len(r) == 4 for r in rows)
        # raw leg falls back to its payload first line
        assert any("FIRING" in t for t in texts)
    finally:
        store.close()


def test_collect_past_incidents_section():
    import time
    store = Store(":memory:")
    try:
        _seed(store)
        alert = {"host": "host01", "service": "web", "output": "down"}
        out = collect_past_incidents(store, alert, time.time())
        assert out.startswith("## Similar past incidents")
        assert "fixed by restarting the pod" in out
        assert "age" not in out  # formatting sanity
    finally:
        store.close()


def test_collect_past_incidents_empty_and_never_raises():
    store = Store(":memory:")
    try:
        out = collect_past_incidents(store, {"service": "nothing"}, 1000.0)
        assert "(no past occurrence)" in out
    finally:
        store.close()

    class BoomStore:
        def past_incidents(self, *a, **k):
            raise RuntimeError("db gone")

    # alert with a stable fingerprint so the collector reaches the store call
    assert "context unavailable" in collect_past_incidents(
        BoomStore(), {"host": "h", "service": "x", "output": "boom"}, 1.0)


def test_validate_structured_accepts_optional_confidence():
    out = validate_structured({"issue": "db-primary is down on host01", "confidence": 0.8})
    assert out["confidence"] == 0.8
    out2 = validate_structured({"summary": "db-primary is down on host01"})
    assert out2["confidence"] is None
    assert validate_structured({"issue": "db-primary is down on host01", "confidence": "hi"}) is None
    assert validate_structured({"issue": "db-primary is down on host01", "confidence": 1.5}) is None
    assert validate_structured({"issue": "db-primary is down on host01", "confidence": -0.1}) is None


def test_render_confidence_high_annotates_percent():
    out = render_structured({"summary": "db is down on host01",
                             "likely_cause": "capacity exhaustion",
                             "correlation": None, "checks": [], "confidence": 0.8})
    assert "Confidence: 80%." in out


def test_render_confidence_low_marks_insufficient_signal():
    out = render_structured({"summary": "db is down on host01",
                             "likely_cause": "maybe capacity",
                             "correlation": None, "checks": [], "confidence": 0.3})
    assert "Insufficient signal" in out
    assert "Confidence:" not in out


def test_render_confidence_omitted_when_no_cause():
    out = render_structured({"summary": "db is down on host01",
                             "likely_cause": "", "correlation": None,
                             "checks": [], "confidence": 0.9})
    assert "Confidence" not in out  # recovery path: annotation withheld
    assert "Insufficient signal" not in out


def test_render_without_confidence_unchanged():
    assert render_structured({"summary": "db is down on host01",
                              "likely_cause": "x",
                              "correlation": None, "checks": []}) == "db is down on host01.\n\nLikely caused by x."