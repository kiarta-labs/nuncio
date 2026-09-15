"""GET /providers.json + GET /providers/<id>/test (P0 provider registry)."""
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from nuncio import config
from nuncio.server import _handler_factory


def _build(env_extra):
    env = {"NUNCIO_LLM_URL": "http://ollama:11434"}
    env.update(env_extra)
    return config.build_app(config.load_settings(env))


def _serve(app):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(app))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}"


def _get(url, admin_token=None):
    req = urllib.request.Request(url)
    if admin_token:
        req.add_header("X-Admin-Token", admin_token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_providers_json_lists_seeded_legacy_private(tmp_path):
    app, _settings = _build({"NUNCIO_DATA_DIR": str(tmp_path)})
    try:
        srv, base = _serve(app)
        try:
            status, body = _get(base + "/providers.json")
            assert status == 200
            rows = {row["id"]: row for row in json.loads(body)}
            assert set(rows) == {"private"}
            assert rows["private"]["source"] == "legacy"
            assert rows["private"]["key"] == "«unset»"
        finally:
            srv.shutdown()
    finally:
        app.store.close()


def test_providers_json_masks_registry_secrets(tmp_path):
    app, _settings = _build({
        "NUNCIO_DATA_DIR": str(tmp_path),
        "NUNCIO_PROVIDERS_JSON": json.dumps({
            "ext": {"base_url": "https://llm.example.com/v1", "model": "m",
                    "api_key_ref": "EXT_LLM_KEY"}}),
        "EXT_LLM_KEY": "canary-secret-value",
    })
    try:
        srv, base = _serve(app)
        try:
            status, body = _get(base + "/providers.json")
            assert status == 200
            rows = {row["id"]: row for row in json.loads(body)}
            assert rows["ext"]["key"] == "«set»"
            assert rows["ext"]["api_key_ref"] == "EXT_LLM_KEY"
            assert b"canary-secret-value" not in body
        finally:
            srv.shutdown()
    finally:
        app.store.close()


def test_provider_test_requires_admin_token(tmp_path):
    app, _settings = _build({"NUNCIO_DATA_DIR": str(tmp_path)})
    try:
        srv, base = _serve(app)
        try:
            # no token configured anywhere -> fail-closed 403
            status, _body = _get(base + "/providers/private/test")
            assert status == 403
            # unknown id (with token configured) -> 404, not a probe
            app2, _s2 = _build({"NUNCIO_DATA_DIR": str(tmp_path / "b"),
                                "NUNCIO_ADMIN_TOKEN": "tok"})
            try:
                srv2, base2 = _serve(app2)
                try:
                    status, _body = _get(base2 + "/providers/nope/test", admin_token="tok")
                    assert status == 404
                    status, _body = _get(base2 + "/providers/private/test",
                                         admin_token="wrong")
                    assert status == 401
                finally:
                    srv2.shutdown()
            finally:
                app2.store.close()
        finally:
            srv.shutdown()
    finally:
        app.store.close()


def test_provider_test_reports_transport_failure_without_leaking(tmp_path):
    # Closed loopback port: fast connection-refused, no external network.
    # The canary key must not appear in the failure body.
    app, _settings = _build({
        "NUNCIO_DATA_DIR": str(tmp_path),
        "NUNCIO_ADMIN_TOKEN": "tok",
        "NUNCIO_PROVIDERS_JSON": json.dumps({
            "dead": {"base_url": "http://127.0.0.1:9/v1", "model": "m",
                     "api_key_ref": "DEAD_KEY"}}),
        "DEAD_KEY": "canary-secret-value",
    })
    try:
        srv, base = _serve(app)
        try:
            status, body = _get(base + "/providers/dead/test", admin_token="tok")
            assert status == 502
            payload = json.loads(body)
            assert payload["ok"] is False
            assert payload["error"]
            assert b"canary-secret-value" not in body
        finally:
            srv.shutdown()
    finally:
        app.store.close()
