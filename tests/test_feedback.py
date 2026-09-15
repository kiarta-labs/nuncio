"""C6 operator feedback (store/endpoint/rank) + Alertmanager source parity."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from nuncio.correlate import rank_correlated
from nuncio.server import _handler_factory
from nuncio.sources.alertmanager import Alertmanager
from nuncio.store import Store


def _app(tmp_path, extra_env):
    from nuncio import config
    env = {"NUNCIO_LLM_URL": "http://ollama:11434",
           "NUNCIO_DATA_DIR": str(tmp_path)}
    env.update(extra_env)
    return config.build_app(config.load_settings(env))


def _seed(store):
    store.persist("k-a", "web down", source="checkmk", category="container",
                  severity="critical", fingerprint="fpa", host="h1", service="web")
    store.persist("k-b", "db down", source="checkmk", category="container",
                  severity="critical", fingerprint="fpb", host="h1", service="db")


# --- store.feedback ---

def test_record_feedback_validates_keys_and_dedupes():
    store = Store(":memory:")
    try:
        _seed(store)
        assert store.record_feedback("k-a", "confirm_root") is True
        assert store.record_feedback("k-a", "confirm_root") is False  # dedupe
        assert store.record_feedback("k-a", "split", ref_key="k-b") is True
        assert store.record_feedback("ghost", "confirm_root") is False  # unknown key
        assert store.record_feedback("k-a", "bogus") is False  # unknown action
        summary = store.feedback_summary()
        assert summary["total"] == 2
        assert summary["by_action"]["confirm_root"] == 1
        assert summary["by_action"]["split"] == 1
    finally:
        store.close()


def test_feedback_corrections_pair_votes_and_clamps():
    store = Store(":memory:")
    try:
        _seed(store)
        for _ in range(5):
            store.record_feedback("k-a", "split", ref_key="k-b")
        corr = store.feedback_corrections()
        assert corr == {("db", "web"): -1.0}  # clamped, normalized, sorted pair
        store.record_feedback("k-a", "merge", ref_key="k-b")
        corr2 = store.feedback_corrections()
        assert corr2[("db", "web")] == 0.0  # -1 + 1
    finally:
        store.close()


# --- rank correction hook (rank-only) ---

def _nine(key, payload, created_at, fp, host="host01", service="web"):
    return (key, payload, created_at, "checkmk", "container", "warning", fp, host, service)


def test_rank_applies_operator_correction_to_gated_rows_only():
    alert = {"host": "host01", "service": "web", "output": "x", "severity": "warning"}
    fp = "fp-web"
    gated = _nine("k1", "web service crash", 1500.0, fp, service="web")
    # same-service row is gated; the correction bump applies
    lines = rank_correlated([gated], alert, now=2000.0,
                            corrections={("web", "web"): -1.0})
    assert "operator split" in lines[0]
    lines2 = rank_correlated([gated], alert, now=2000.0,
                             corrections={("web", "web"): 1.0})
    assert "operator merge" in lines2[0]


def test_rank_correction_without_feedback_absent():
    alert = {"host": "host01", "service": "web", "output": "x", "severity": "warning"}
    gated = _nine("k1", "web service crash", 1500.0, "fp-web", service="web")
    lines = rank_correlated([gated], alert, now=2000.0)
    assert "operator" not in lines[0]


# --- /feedback endpoint ---

def _serve(app):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(app))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


def _post(url, body, token=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_feedback_endpoint_auth_validation_and_summary(tmp_path):
    app, settings = _app(tmp_path, {"NUNCIO_ADMIN_TOKEN": "tok"})
    _seed(app.store)
    try:
        srv, base = _serve(app)
        try:
            status, body = _post(base + "/feedback",
                                 {"key": "k-a", "action": "confirm_root"})
            assert status == 401  # no token
            status, body = _post(base + "/feedback",
                                 {"key": "k-a", "action": "confirm_root"}, token="tok")
            assert status == 200
            status, body = _post(base + "/feedback",
                                 {"key": "k-a", "action": "split"}, token="tok")
            assert status == 400  # split requires ref_key
            status, body = _post(base + "/feedback",
                                 {"key": "k-a", "action": "split", "ref_key": "k-b"},
                                 token="tok")
            assert status == 200
            status, body = _post(base + "/feedback",
                                 {"key": "ghost", "action": "confirm_root"}, token="tok")
            assert status == 404
            status, body = _get(base + "/feedback.json")
            data = json.loads(body)
            assert data["total"] == 2
        finally:
            srv.shutdown()
    finally:
        app.store.close()


# --- Alertmanager source parity ---

def test_alertmanager_extracts_value_and_links():
    adapter = Alertmanager()
    payload = {"alerts": [
        {"status": "firing",
         "labels": {"alertname": "DiskFull", "instance": "10.0.0.5",
                    "severity": "warning"},
         "annotations": {"summary": "disk 91% full",
                         "value": "91",
                         "runbook_url": "https://runbooks/disk"},
         "startsAt": "t1",
         "fingerprint": "fp1"},
    ]}
    parsed = adapter.parse(payload, {})
    assert len(parsed) == 1
    alert = parsed[0].alert
    assert alert["value"] == "91"
    assert alert["links"] == "https://runbooks/disk"
    assert alert["severity"] == "warning"
    assert parsed[0].raw_text.startswith("[FIRING] 10.0.0.5 / DiskFull")


def test_alertmanager_value_falls_back_to_values_map():
    adapter = Alertmanager()
    payload = {"alerts": [
        {"status": "firing",
         "labels": {"alertname": "CPU", "instance": "h"},
         "annotations": {"summary": "cpu"},
         "values": {"B": "42", "A": "1"},
         "startsAt": "t2", "fingerprint": "fp2"},
    ]}
    alert = adapter.parse(payload, {})[0].alert
    assert alert["value"] == "A=1,B=42"


def test_alertmanager_no_extras_when_absent():
    adapter = Alertmanager()
    payload = {"alerts": [
        {"status": "firing",
         "labels": {"alertname": "X", "instance": "h"},
         "annotations": {"summary": "x"},
         "startsAt": "t3", "fingerprint": "fp3"},
    ]}
    alert = adapter.parse(payload, {})[0].alert
    assert "value" not in alert
    assert "links" not in alert