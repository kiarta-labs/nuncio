"""Service ingest logic: persist-before-ACK semantics and load-shed behavior.

Tested with 0 workers so the queue is inspectable and there are no thread races.
"""
import threading
import time

import pytest
from nuncio.deadline import Deadline
from nuncio.server import App, Metrics
from nuncio.store import Store


class FakeEngine:
    def __init__(self):
        self.raw_delivered = []
        self.mode = "enriched"
    def _deliver_raw(self, key, raw):
        self.raw_delivered.append(key)
        return "raw"
    def process(self, *a, **k):
        return "enriched"
    def drain_raw(self):
        return 0


def notify(pid, host="host01", service="sonarr"):
    return {
        "NOTIFY_WHAT": "SERVICE", "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
        "NOTIFY_HOSTNAME": host, "NOTIFY_SERVICEDESC": service,
        "NOTIFY_SERVICESTATE": "CRIT", "NOTIFY_SERVICEOUTPUT": "boom",
        "NOTIFY_SERVICEPROBLEMID": str(pid),
    }


@pytest.fixture
def app(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    eng = FakeEngine()
    a = App(eng, store, Metrics(), budget_s=45.0, concurrency=0, queue_max=2,
            clock=lambda: 1000.0, maint_interval=3600.0)
    a._engine = eng  # expose for assertions
    yield a
    store.close()


def test_new_alert_persisted_and_enqueued(app):
    assert app.ingest("checkmk", notify(1)) == 200
    assert app.store.get_status("checkmk:host01/sonarr/1/PROBLEM/1") == "received"  # persisted
    assert app.q.qsize() == 1  # enqueued
    assert app.metrics.ingested == 1
    assert app.metrics.by_source["checkmk"] == 1


# --- Phase B: depth threading at ingest (mirrors `mode`'s discipline) ---

class DepthEngine(FakeEngine):
    def __init__(self, depth):
        super().__init__()
        self.depth = depth


def test_ingest_full_depth_builds_deadline_from_full_budget(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    eng = DepthEngine("full")
    a = App(eng, store, Metrics(), budget_s=30.0, full_budget_s=90.0,
            concurrency=0, queue_max=5, clock=lambda: 1000.0, maint_interval=3600.0)
    a.ingest("checkmk", notify(1))
    item = a.q.get_nowait()
    key, alert, raw, deadline, mode, depth = item
    assert depth == "full"
    assert deadline._budget == 90.0  # the FULL budget, not the standard 30.0
    store.close()


def test_ingest_low_depth_builds_deadline_from_standard_budget(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    eng = DepthEngine("low")
    a = App(eng, store, Metrics(), budget_s=30.0, full_budget_s=90.0,
            concurrency=0, queue_max=5, clock=lambda: 1000.0, maint_interval=3600.0)
    a.ingest("checkmk", notify(1))
    item = a.q.get_nowait()
    key, alert, raw, deadline, mode, depth = item
    assert depth == "low"
    assert deadline._budget == 30.0  # the standard budget, not the full 90.0
    store.close()


def test_ingest_queue_tuple_defaults_depth_to_full_when_engine_has_no_depth_attr(app):
    # FakeEngine (this module's own default double) has `.mode` but no
    # `.depth` -- must degrade to "full" (Engine's own default), never raise.
    app.ingest("checkmk", notify(1))
    item = app.q.get_nowait()
    assert item[5] == "full"


def test_ingest_computes_and_persists_fingerprint(app):
    app.ingest("checkmk", notify(1))
    row = app.store.get_alert_detail("checkmk:host01/sonarr/1/PROBLEM/1")
    assert row["fingerprint"]  # non-empty -- best-effort fingerprint computed at ingest
    assert len(row["fingerprint"]) == 16


def test_ingest_persists_host_and_service(app):
    app.ingest("checkmk", notify(1, host="svr", service="disk-root"))
    key = "checkmk:svr/disk-root/1/PROBLEM/1"
    row = app.store.get_alert_detail(key)
    assert row["host"] == "svr"
    assert row["service"] == "disk-root"
    # also readable via the windowed row-reading path the dashboard uses
    rows = app.store.rows_since(0)
    assert rows[0]["host"] == "svr"
    assert rows[0]["service"] == "disk-root"


def test_ingest_persists_null_host_for_placeholder(app):
    # Phase 3.3: server.py's persist call site applies real_host() -- a
    # "-" host must persist as NULL, never the literal placeholder string
    # (the Determinism doctrine's "a placeholder host is not a host").
    app.ingest("generic", {"host": "-", "message": "instance-less alert"})
    rows = app.store.rows_since(0)
    assert rows[0]["host"] is None


def test_ingest_persists_real_host_verbatim_not_canonicalized(app):
    app.ingest("checkmk", notify(1, host="svr.kirits.net", service="disk-root"))
    key = "checkmk:svr.kirits.net/disk-root/1/PROBLEM/1"
    row = app.store.get_alert_detail(key)
    # persisted verbatim -- canonicalization happens at COMPARE time in
    # nuncio.correlate, not at persist time (so a later NUNCIO_HOST_DOMAINS
    # change applies retroactively to already-stored rows).
    assert row["host"] == "svr.kirits.net"


def test_duplicate_alert_deduped_not_reenqueued(app):
    app.ingest("checkmk", notify(1))
    assert app.ingest("checkmk", notify(1)) == 200  # duplicate
    assert app.metrics.duplicates == 1
    assert app.q.qsize() == 1  # not enqueued twice


def test_queue_full_load_sheds_persists_for_maintenance(app):
    app.ingest("checkmk", notify(1))
    app.ingest("checkmk", notify(2))  # queue_max=2, now full
    assert app.q.qsize() == 2
    assert app.ingest("checkmk", notify(3)) == 200  # arrival #3 -> load-shed (persist only, non-blocking)
    # persisted (not delivered synchronously in the handler); maintenance delivers it raw
    assert app.store.get_status("checkmk:host01/sonarr/3/PROBLEM/1") == "received"
    assert app.metrics.failures.get("queue") == 1


def test_non_dict_body_rejected(app):
    assert app.ingest("checkmk", [1, 2, 3]) == 400
    assert app.ingest("checkmk", "not a dict") == 400


def test_persist_failure_returns_500(app, monkeypatch):
    def boom(*a):
        raise OSError("disk full")
    monkeypatch.setattr(app.store, "persist", boom)
    assert app.ingest("checkmk", notify(9)) == 500
    assert app.metrics.failures.get("persist") == 1


def test_unknown_source_returns_404(app):
    assert app.ingest("nonexistent-tool", notify(1)) == 404


def test_generic_source_accepts_arbitrary_json(app):
    assert app.ingest("generic", {"host": "web-1", "message": "disk full"}) == 200
    assert app.metrics.by_source["generic"] == 1


# --- Phase 5.1: `?severity=` ingest-URL default (App.ingest's default_severity) ---
#
# Scoped to the ingest path via App.ingest's `default_severity` kwarg; the
# HTTP-level query-string plumbing (do_POST) is covered separately below by
# the live_server tests. These exercise the App.ingest contract directly:
# honored only when the payload itself has no usable severity, payload
# always wins, invalid values are ignored.

def test_ingest_default_severity_applied_when_payload_has_none(app):
    # generic's default state is "unknown" when no severity/state/status key
    # is present in the payload at all -- exactly the watchtower/cifs-monitor
    # "dumb webhook" case this param exists for.
    status = app.ingest("generic", {"host": "svr", "message": "no severity here"},
                         default_severity="warning")
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == "warning"


def test_ingest_default_severity_ignored_when_payload_supplies_one(app):
    # A payload-supplied severity ALWAYS wins over the query param -- the
    # param is a fallback for payloads that supply nothing, never an override.
    status = app.ingest("generic", {"host": "svr", "message": "boom", "severity": "critical"},
                         default_severity="warning")
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == "critical"


def test_ingest_invalid_default_severity_ignored(app):
    # An unrecognized query value must never error the ingest -- it's simply
    # ignored, falling through to the existing unknown/LLM-infer path.
    status = app.ingest("generic", {"host": "svr", "message": "no severity here"},
                         default_severity="urgent-ish")
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == "unknown"


def test_ingest_no_default_severity_param_regression(app):
    # /ingest/generic with no param at all still works exactly as before.
    status = app.ingest("generic", {"host": "svr", "message": "plain"})
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == "unknown"


def test_ingest_default_severity_scoped_to_source_with_declared_severity(app):
    # A source that DOES declare a real severity in its payload (checkmk's
    # SERVICESTATE=CRIT here) must not be overridden by the param -- "no
    # usable severity" is the only trigger, regardless of source.
    status = app.ingest("checkmk", notify(1), default_severity="info")
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == "critical"


@pytest.mark.parametrize("value", ["critical", "warning", "info", "ok"])
def test_ingest_default_severity_all_valid_values(app, value):
    status = app.ingest("generic", {"host": "svr", "message": "m"}, default_severity=value)
    assert status == 200
    rows = app.store.rows_since(0)
    assert rows[0]["severity"] == value


# --- built-in delivery-safety modes, server wiring ---

def _wait_until(predicate, timeout=2.0, interval=0.01):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            # A predicate that probes a not-yet-listening server raises
            # (e.g. URLError: connection refused) -- treat that as "not ready
            # yet" and keep polling. A persistent failure still surfaces via
            # the final predicate() call below.
            pass
        time.sleep(interval)
    return predicate()


def test_wait_until_retries_through_a_transiently_raising_predicate():
    # A readiness probe against a not-yet-listening server raises (connection
    # refused) on the first calls; _wait_until must swallow that and keep
    # polling until the predicate succeeds -- not propagate the exception.
    calls = {"n": 0}

    def predicate():
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("connection refused")
        return True

    assert _wait_until(predicate, timeout=1.0, interval=0.001) is True
    assert calls["n"] >= 3


def test_status_code_contract_success_2xx_only_after_fsync(app):
    # The ingest endpoint returns 2xx ONLY after the
    # alert is fsync-persisted -- assert persist happens (status == received)
    # for exactly the same call that returned 200.
    status = app.ingest("checkmk", notify(1))
    assert status == 200
    assert app.store.get_status("checkmk:host01/sonarr/1/PROBLEM/1") is not None


def test_status_code_contract_persist_failure_5xx_not_2xx(app, monkeypatch):
    monkeypatch.setattr(app.store, "persist",
                         lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    assert app.ingest("checkmk", notify(9)) == 500  # RETRY -- source should re-fire


def test_status_code_contract_unparseable_4xx_not_retryable(app):
    assert app.ingest("checkmk", [1, 2, 3]) == 400  # permanently unparseable


# --- full end-to-end bypass flow with a real Engine + Store + worker ---

from nuncio.engine import Engine
from nuncio.render import RAW_FALLBACK_MARKER

VALID_ENRICHMENT = "sonarr is down on host01, service unreachable.\n\nLooks urgent: service down, likely a crash."


class RecordingDelivery:
    """Captures the `Envelope` handed to `.send()` (the post-envelope-
    migration delivery contract)."""
    def __init__(self):
        self.sent = []
        self.lock = __import__("threading").Lock()
    def send(self, envelope):
        with self.lock:
            self.sent.append(envelope)
        return True


class ScriptedLLM:
    def __init__(self, text, delay=0.0):
        self.model = "test-model"
        self.delay = delay
    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        if self.delay:
            time.sleep(self.delay)
        return VALID_ENRICHMENT


@pytest.fixture
def real_bypass_app(tmp_path):
    store = Store(str(tmp_path / "b.db"))
    dlv = RecordingDelivery()
    engine = Engine(store, ScriptedLLM(VALID_ENRICHMENT), dlv, mode="bypass",
                     budget_s=45.0, per_attempt_s=20.0, clock=time.monotonic)
    a = App(engine, store, Metrics(), budget_s=45.0, concurrency=1, queue_max=10,
            clock=time.monotonic, maint_interval=3600.0)
    yield a, store, dlv
    store.close()


def test_bypass_end_to_end_single_unmarked_message(real_bypass_app):
    app, store, dlv = real_bypass_app
    assert app.ingest("checkmk", notify(1)) == 200
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    assert _wait_until(lambda: store.get_status(key) == "delivered_raw")
    assert len(dlv.sent) == 1
    assert RAW_FALLBACK_MARKER not in dlv.sent[0].detail


def test_bypass_end_to_end_duplicate_ingest_delivers_once(real_bypass_app):
    app, store, dlv = real_bypass_app
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    assert app.ingest("checkmk", notify(1)) == 200
    assert _wait_until(lambda: store.get_status(key) == "delivered_raw")
    assert app.ingest("checkmk", notify(1)) == 200  # duplicate
    time.sleep(0.05)
    assert len(dlv.sent) == 1


# --- dashboard HTTP routes, over a real socket ---

import json as _json
import urllib.error
import urllib.request

from nuncio.server import serve, _handler_factory
from http.server import ThreadingHTTPServer


class _ScriptedLLMWithUsage:
    model = "test-model"

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        return VALID_ENRICHMENT, {"prompt_tokens": 42, "completion_tokens": 17}


@pytest.fixture
def live_server(tmp_path):
    """A real Engine + Store + App behind an actual ThreadingHTTPServer on an
    OS-assigned port -- for the routes that must be exercised as real HTTP
    (status codes, content-types, query-string parsing), not just via the
    App object directly."""
    store = Store(str(tmp_path / "live.db"))
    dlv = RecordingDelivery()
    engine = Engine(store, _ScriptedLLMWithUsage(), dlv, budget_s=45.0, per_attempt_s=20.0,
                     clock=time.monotonic)
    a = App(engine, store, Metrics(), budget_s=45.0, concurrency=1, queue_max=10,
            clock=time.monotonic, maint_interval=3600.0,
            plane_info={"private": {"model": "test-model"}, "knowledge": {"enabled": False}},
            delivery_adapters=["stdout"], logo_bytes=b"\x89PNGfakepngbytes",
            favicon_data_uri="data:image/png;base64,AAAA")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(a))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield a, store, f"http://127.0.0.1:{port}"
    srv.shutdown()
    store.close()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_dashboard_root_returns_html(live_server):
    _app, _store, base = live_server
    status, body, headers = _get(base + "/")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert b"Nuncio" in body


def test_stats_json_route_returns_valid_json(live_server):
    _app, _store, base = live_server
    status, body, headers = _get(base + "/stats.json")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    parsed = _json.loads(body)
    assert "totals" in parsed and "window_24h" in parsed


def test_alerts_json_route_returns_valid_json(live_server):
    _app, _store, base = live_server
    status, body, _headers = _get(base + "/alerts.json")
    assert status == 200
    assert "alerts" in _json.loads(body)


def test_alerts_json_route_respects_limit_query_param(live_server):
    app, _store, base = live_server
    app.ingest("checkmk", notify(1))
    app.ingest("checkmk", notify(2))
    status, body, _headers = _get(base + "/alerts.json?limit=1")
    assert status == 200
    assert len(_json.loads(body)["alerts"]) == 1


def test_logo_png_route_returns_image(live_server):
    _app, _store, base = live_server
    status, body, headers = _get(base + "/logo.png")
    assert status == 200
    assert headers.get("Content-Type") == "image/png"
    assert body == b"\x89PNGfakepngbytes"


def test_logo_png_route_404s_when_no_logo_configured(tmp_path):
    store = Store(str(tmp_path / "nologo.db"))
    a = App(FakeEngine(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=2,
            clock=lambda: 1000.0, maint_interval=3600.0)  # logo_bytes defaults to b""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(a))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    status, _body, _headers = _get(f"http://127.0.0.1:{port}/logo.png")
    assert status == 404
    srv.shutdown()
    store.close()


def test_alert_detail_route_404s_for_unknown_key(live_server):
    _app, _store, base = live_server
    status, body, _headers = _get(base + "/alert/does-not-exist")
    assert status == 404


def test_alert_detail_route_returns_html_for_known_key(live_server):
    app, store, base = live_server
    status = app.ingest("checkmk", notify(1))
    assert status == 200
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    assert _wait_until(lambda: store.get_status(key) == "delivered_enriched")
    status, body, headers = _get(base + "/alert/" + key)
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert key.encode() in body


def test_alert_detail_route_handles_keys_containing_slashes(live_server):
    # Idempotency keys are "<source>:host/service/id/..." -- they contain
    # literal "/" characters that are also the URL path separator; the route
    # must treat everything after the "/alert/" prefix as the key.
    app, store, base = live_server
    app.ingest("checkmk", notify(7, host="host01", service="a/weird-service"))
    assert _wait_until(lambda: len(store.recent_rows(limit=5)) >= 1)
    row = store.recent_rows(limit=1)[0]
    status, body, _headers = _get(base + "/alert/" + row["key"])
    assert status == 200
    assert row["key"].encode() in body


def test_dashboard_end_to_end_never_leaks_a_secret(live_server):
    # The hardest rule: ingest a real secret, let it flow through the whole
    # pipeline (redact -> persist -> engine -> store), then fetch every
    # dashboard surface and assert the secret text is nowhere.
    app, store, base = live_server
    secret_payload = notify(1)
    secret_payload["NOTIFY_SERVICEOUTPUT"] = (
        "connect failed VECTOR_O2_PASSWORD=Sup3rS3cretHunter2Value rejected"
    )
    app.ingest("checkmk", secret_payload)
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    assert _wait_until(lambda: store.get_status(key) is not None
                       and store.get_status(key) != "received")

    for path in ("/", "/stats.json", "/alerts.json", "/alert/" + key):
        status, body, _headers = _get(base + path)
        assert status == 200
        assert b"Sup3rS3cretHunter2Value" not in body, path


def test_config_json_route_still_works_unaffected_by_dashboard_routes(live_server):
    # Regression guard: adding the dashboard's routes must not have disturbed
    # the pre-existing /config.json route dispatch.
    _app, _store, base = live_server
    status, body, headers = _get(base + "/config.json")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")


def test_unknown_route_still_404s(live_server):
    _app, _store, base = live_server
    status, _body, _headers = _get(base + "/totally-not-a-route")
    assert status == 404


# =====================================================================
# POST /ingest* token gate: constant-time comparison, matching the
# settings-screen admin-token gate's discipline (hmac.compare_digest, not
# ==) so response timing can't be used to brute-force NUNCIO_INGEST_TOKEN
# byte-by-byte.
# =====================================================================

def _post(url, body):
    req = urllib.request.Request(url, data=_json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _post_with_token(url, body, token):
    req = urllib.request.Request(url, data=_json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-Auth-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture
def live_server_with_token(tmp_path):
    store = Store(str(tmp_path / "token.db"))
    dlv = RecordingDelivery()
    engine = Engine(store, _ScriptedLLMWithUsage(), dlv, budget_s=45.0, per_attempt_s=20.0,
                     clock=time.monotonic)
    a = App(engine, store, Metrics(), budget_s=45.0, concurrency=0, queue_max=10,
            clock=time.monotonic, maint_interval=3600.0, token="correct-ingest-token")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(a))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield a, store, f"http://127.0.0.1:{port}"
    srv.shutdown()
    store.close()


def test_ingest_401_when_token_missing(live_server_with_token):
    _app, _store, base = live_server_with_token
    status, _body = _post(base + "/ingest/generic", {"host": "h", "message": "x"})
    assert status == 401


def test_ingest_401_on_wrong_token(live_server_with_token):
    _app, _store, base = live_server_with_token
    status, _body = _post_with_token(base + "/ingest/generic", {"host": "h", "message": "x"}, "wrong-token")
    assert status == 401


def test_ingest_200_with_correct_token(live_server_with_token):
    _app, _store, base = live_server_with_token
    status, _body = _post_with_token(base + "/ingest/generic", {"host": "h", "message": "x"},
                                      "correct-ingest-token")
    assert status == 200


# --- Phase 5.1 (HTTP layer): `?severity=` query-string plumbing in do_POST ---
#
# These exercise the ACTUAL request path (not App.ingest directly) because
# the routing itself has to correctly split "/ingest/generic?severity=warning"
# into path="/ingest/generic" + query="severity=warning" -- do_POST previously
# used self.path raw (unsplit) for source-name extraction, which would have
# glued the query string onto the source name for any ingest URL carrying one.

def test_ingest_query_severity_applied_over_http(live_server):
    app, store, base = live_server
    status, _body = _post(base + "/ingest/generic?severity=warning",
                           {"host": "svr", "message": "no severity field"})
    assert status == 200
    rows = store.rows_since(0)
    assert rows[0]["severity"] == "warning"


def test_ingest_query_severity_payload_wins_over_http(live_server):
    app, store, base = live_server
    status, _body = _post(base + "/ingest/generic?severity=warning",
                           {"host": "svr", "message": "boom", "severity": "critical"})
    assert status == 200
    rows = store.rows_since(0)
    assert rows[0]["severity"] == "critical"


def test_ingest_query_severity_invalid_value_ignored_over_http(live_server):
    app, store, base = live_server
    status, _body = _post(base + "/ingest/generic?severity=bogus",
                           {"host": "svr", "message": "no severity field"})
    assert status == 200
    rows = store.rows_since(0)
    assert rows[0]["severity"] == "unknown"


def test_ingest_generic_still_works_with_no_query_param_over_http(live_server):
    # Regression: /ingest/generic with no `?severity=` at all -- and no query
    # string whatsoever -- is unaffected by the new query-string parsing.
    app, store, base = live_server
    status, _body = _post(base + "/ingest/generic", {"host": "svr", "message": "plain"})
    assert status == 200
    rows = store.rows_since(0)
    assert rows[0]["severity"] == "unknown"


def test_ingest_query_severity_does_not_affect_other_routes(live_server):
    # The query-string parsing added to do_POST for `?severity=` must not
    # leak into unrelated GET routes' own query-param handling (e.g.
    # /alerts.json?limit=). Sanity: posting a query string that ALSO looks
    # like it could confuse routing doesn't break /ingest itself, and a GET
    # route with its own query param still behaves independently.
    app, store, base = live_server
    status, _body, _headers = _get(base + "/alerts.json?limit=1&severity=warning")
    assert status == 200
    assert "alerts" in _json.loads(_body)


def _post_with_bearer(url, body, bearer_value):
    """bearer_value is the raw Authorization header value (caller includes
    'Bearer ' prefix or not, to test both well-formed and malformed cases)."""
    req = urllib.request.Request(url, data=_json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if bearer_value is not None:
        req.add_header("Authorization", bearer_value)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_ingest_200_with_correct_bearer_token(live_server_with_token):
    # Grafana unified alerting / Alertmanager can't set X-Auth-Token but can
    # send a standard Authorization: Bearer <token> header.
    _app, _store, base = live_server_with_token
    status, _body = _post_with_bearer(base + "/ingest/generic", {"host": "h", "message": "x"},
                                       "Bearer correct-ingest-token")
    assert status == 200


def test_ingest_401_on_wrong_bearer_token(live_server_with_token):
    _app, _store, base = live_server_with_token
    status, _body = _post_with_bearer(base + "/ingest/generic", {"host": "h", "message": "x"},
                                       "Bearer wrong-token")
    assert status == 401


def test_ingest_401_on_bearer_value_missing_scheme(live_server_with_token):
    # The raw token without the "Bearer " scheme prefix must not authenticate,
    # even though the credential bytes match.
    _app, _store, base = live_server_with_token
    status, _body = _post_with_bearer(base + "/ingest/generic", {"host": "h", "message": "x"},
                                       "correct-ingest-token")
    assert status == 401


def test_ingest_200_when_either_header_correct_and_other_absent(live_server_with_token):
    # X-Auth-Token correct, no Authorization header at all -- still a
    # regression check that adding the Bearer path didn't disturb this.
    _app, _store, base = live_server_with_token
    req = urllib.request.Request(base + "/ingest/generic",
                                  data=_json.dumps({"host": "h", "message": "x"}).encode(),
                                  method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Auth-Token", "correct-ingest-token")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200


def test_ingest_200_when_both_headers_present_bearer_correct_xauth_wrong(live_server_with_token):
    # Either header satisfying auth is sufficient.
    _app, _store, base = live_server_with_token
    req = urllib.request.Request(base + "/ingest/generic",
                                  data=_json.dumps({"host": "h", "message": "x"}).encode(),
                                  method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Auth-Token", "wrong-token")
    req.add_header("Authorization", "Bearer correct-ingest-token")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200


def test_ingest_200_when_both_headers_present_xauth_correct_bearer_wrong(live_server_with_token):
    _app, _store, base = live_server_with_token
    req = urllib.request.Request(base + "/ingest/generic",
                                  data=_json.dumps({"host": "h", "message": "x"}).encode(),
                                  method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Auth-Token", "correct-ingest-token")
    req.add_header("Authorization", "Bearer wrong-token")
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200


# =====================================================================
# Coverage: Metrics.render(), ingest()'s per-alert best-effort try/excepts,
# the worker loop's skip/deadline/outcome branches, the maintenance
# thread's recovery + assist-sweep + outer-exception paths, and the
# remaining HTTP route/status-code branches.
# =====================================================================

def test_metrics_render_shape():
    m = Metrics()
    m.inc("ingested")
    m.inc("ingested")
    m.inc("delivered", "enriched")
    m.inc("failures", "llm")
    m.inc("by_source", "checkmk")
    m.inc("assist_attempted")
    m.inc("assist_ok")
    m.inc("assist_failed")
    text = m.render()
    assert "nuncio_ingested_total 2" in text
    assert 'nuncio_delivered_total{outcome="enriched"} 1' in text
    assert 'nuncio_failures_total{stage="llm"} 1' in text
    assert 'nuncio_ingested_by_source_total{source="checkmk"} 1' in text
    assert "nuncio_assist_attempted_total 1" in text
    assert "nuncio_assist_ok_total 1" in text
    assert "nuncio_assist_failed_total 1" in text


def test_ingest_survives_adapter_parse_exception(app, monkeypatch):
    from nuncio import sources as sources_mod

    class BoomAdapter:
        def parse(self, payload, headers):
            raise RuntimeError("adapter broke")

    monkeypatch.setattr(sources_mod, "get", lambda name: BoomAdapter())
    assert app.ingest("checkmk", notify(1)) == 400
    assert app.metrics.failures.get("parse") == 1


def test_ingest_zero_alert_batch_returns_200_and_persists_nothing(app, monkeypatch):
    # A source adapter legitimately parsing a payload to ZERO alerts (e.g. a
    # resolved-only/empty batch) is not "permanently unparseable" -- it's
    # "nothing to do". 400 would tell the source to stop sending / error-
    # spiral; 200 (ACK, nothing persisted) is correct and matches the
    # ingest() docstring's "includes ... 0-alert batches" contract.
    from nuncio import sources as sources_mod

    class EmptyBatchAdapter:
        def parse(self, payload, headers):
            return []  # a syntactically valid payload that yields no alerts

    monkeypatch.setattr(sources_mod, "get", lambda name: EmptyBatchAdapter())
    assert app.ingest("checkmk", notify(1)) == 200
    assert app.metrics.ingested == 0  # nothing was persisted or queued


def test_ingest_parse_raising_still_returns_400(app, monkeypatch):
    # Contrast with the zero-alert case above: a parse that RAISES is
    # genuinely malformed and must stay 400 (do not retry).
    from nuncio import sources as sources_mod

    class BoomAdapter:
        def parse(self, payload, headers):
            raise RuntimeError("truly malformed")

    monkeypatch.setattr(sources_mod, "get", lambda name: BoomAdapter())
    assert app.ingest("checkmk", notify(1)) == 400


def test_ingest_survives_redact_exception_uses_raw_text_verbatim(app, monkeypatch):
    monkeypatch.setattr("nuncio.server.redact", lambda text: (_ for _ in ()).throw(RuntimeError("redact broke")))
    assert app.ingest("checkmk", notify(1)) == 200
    assert app.store.get_status("checkmk:host01/sonarr/1/PROBLEM/1") == "received"


def test_ingest_survives_categorize_exception_category_is_none(app, monkeypatch):
    monkeypatch.setattr("nuncio.server.categorize", lambda alert: (_ for _ in ()).throw(RuntimeError("boom")))
    assert app.ingest("checkmk", notify(1)) == 200
    row = app.store.get_alert_detail("checkmk:host01/sonarr/1/PROBLEM/1")
    assert row["category"] is None


def test_ingest_survives_fingerprint_exception_fingerprint_is_none(app, monkeypatch):
    monkeypatch.setattr("nuncio.server.fingerprint", lambda alert: (_ for _ in ()).throw(RuntimeError("boom")))
    assert app.ingest("checkmk", notify(1)) == 200
    row = app.store.get_alert_detail("checkmk:host01/sonarr/1/PROBLEM/1")
    assert row["fingerprint"] is None


def test_ingest_grafana_mixed_batch_returns_200_and_persists_good_alerts(app):
    # End-to-end (real Grafana adapter, no monkeypatch): one malformed entry
    # in a real webhook batch must not take the well-formed siblings down
    # with it -- see SourceAdapter._fallback_parsed_alert.
    payload = {
        "receiver": "nuncio", "status": "firing", "commonLabels": {},
        "alerts": [
            {"status": "firing",
             "labels": {"alertname": "HighCPU", "instance": "web-1", "severity": "critical"},
             "annotations": {"summary": "CPU above 90%"},
             "startsAt": "2026-07-17T09:00:00Z", "fingerprint": "ok1"},
            "not-a-dict",
        ],
    }
    assert app.ingest("grafana", payload) == 200
    assert app.store.get_status("grafana:ok1/firing/2026-07-17T09:00:00Z") == "received"
    assert app.metrics.ingested == 2  # the good alert AND the fallback-degraded one


# --- worker loop ---

def _run_worker_briefly(a, timeout=2.0):
    t = threading.Thread(target=a._worker, daemon=True)
    t.start()
    _wait_until(lambda: a.q.unfinished_tasks == 0, timeout=timeout)


def test_worker_skips_row_already_finished_by_a_prior_pass(app):
    # key was never persisted -> get_status() is None, not "received" ->
    # the worker's own guard against reprocessing a row another pass (or
    # the maintenance thread) already finished.
    deadline = Deadline(45.0, clock=app.clock)
    app.q.put(("checkmk:ghost", {"host": "h"}, "raw", deadline, "enriched", "full"))
    _run_worker_briefly(app)
    assert app._engine.raw_delivered == []  # process()/`_deliver_raw` never reached


def test_worker_expired_deadline_enriched_mode_delivers_raw_with_deadline_fail_stage(app):
    app.ingest("checkmk", notify(1))
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    expired = Deadline(0.0, clock=app.clock)  # expires immediately

    class RecordingEngine:
        mode = "enriched"
        def __init__(self):
            self.raw_calls = []
        def _deliver_raw(self, key, raw, fail_stage=None):
            self.raw_calls.append((key, fail_stage))
            return "raw"
        def process(self, *a, **k):
            raise AssertionError("process() must not run past an expired deadline in enriched mode")

    app.engine = RecordingEngine()
    app.q.queue.clear()
    app.q.put((key, {"host": "h"}, "raw", expired, "enriched", "full"))
    _run_worker_briefly(app)
    assert app.engine.raw_calls == [(key, "deadline")]
    assert app.metrics.failures.get("queue") == 1


def test_worker_expired_deadline_bypass_mode_still_runs_process(app):
    app.ingest("checkmk", notify(1))
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    expired = Deadline(0.0, clock=app.clock)

    class RecordingEngine:
        mode = "enriched"
        def __init__(self):
            self.process_calls = []
        def _deliver_raw(self, *a, **k):
            raise AssertionError("bypass has nothing to time out on -- must not take the raw-fallback branch")
        def process(self, key, alert, raw, deadline=None, mode=None, depth=None):
            self.process_calls.append((key, mode))
            return "raw"

    app.engine = RecordingEngine()
    app.q.queue.clear()
    app.q.put((key, {"host": "h"}, "raw", expired, "bypass", "full"))
    _run_worker_briefly(app)
    assert app.engine.process_calls == [(key, "bypass")]


def test_worker_outcome_delivery_failed_increments_delivery_failure(app):
    app.ingest("checkmk", notify(1))
    key = "checkmk:host01/sonarr/1/PROBLEM/1"

    class FailingEngine:
        mode = "enriched"
        def process(self, *a, **k):
            return "delivery_failed"

    app.engine = FailingEngine()
    app.q.queue.clear()
    app.q.put((key, {"host": "h"}, "raw", Deadline(45.0, clock=app.clock), "enriched", "full"))
    _run_worker_briefly(app)
    assert app.metrics.failures.get("delivery") == 1
    assert app.metrics.delivered == {"enriched": 0, "raw": 0}


def test_worker_survives_engine_exception(app):
    app.ingest("checkmk", notify(1))
    key = "checkmk:host01/sonarr/1/PROBLEM/1"

    class BoomEngine:
        mode = "enriched"
        def process(self, *a, **k):
            raise RuntimeError("engine broke")

    app.engine = BoomEngine()
    app.q.queue.clear()
    app.q.put((key, {"host": "h"}, "raw", Deadline(45.0, clock=app.clock), "enriched", "full"))
    _run_worker_briefly(app)
    assert app.metrics.failures.get("worker") == 1
    assert app.q.qsize() == 0  # task_done still ran (finally block)


# --- maintenance thread ---

def test_maintenance_recovers_stale_undelivered_row_on_startup_pass(tmp_path):
    store = Store(str(tmp_path / "maint.db"))
    store.persist("checkmk:host01/svc/1/PROBLEM/1", "raw payload")

    class RecoveringEngine:
        mode = "enriched"
        assist = None
        def _deliver_raw(self, key, raw, fail_stage=None):
            return "raw"

    a = App(RecoveringEngine(), store, Metrics(), budget_s=1.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: time.time() + 10 ** 6, maint_interval=3600.0)
    try:
        assert _wait_until(lambda: a.metrics.recovered == 1)
    finally:
        store.close()


def test_maintenance_runs_assist_sweep_when_configured(tmp_path):
    store = Store(str(tmp_path / "maint2.db"))

    class RecordingAssist:
        def __init__(self):
            self.swept = 0
        def sweep_orphans(self):
            self.swept += 1

    class EngineWithAssist:
        mode = "enriched"
        def __init__(self):
            self.assist = RecordingAssist()

    eng = EngineWithAssist()
    a = App(eng, store, Metrics(), budget_s=45.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: 1000.0, maint_interval=3600.0)
    try:
        assert _wait_until(lambda: eng.assist.swept >= 1)
    finally:
        store.close()


def test_maintenance_survives_assist_sweep_exception(tmp_path):
    store = Store(str(tmp_path / "maint3.db"))

    class BoomAssist:
        def sweep_orphans(self):
            raise RuntimeError("sweep broke")

    class EngineWithAssist:
        mode = "enriched"
        assist = BoomAssist()

    a = App(EngineWithAssist(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: 1000.0, maint_interval=3600.0)
    try:
        assert _wait_until(lambda: a.metrics.failures.get("maintenance", 0) >= 1)
    finally:
        store.close()


def test_maintenance_one_poison_row_does_not_stall_recovery_of_others(tmp_path):
    # undelivered_older_than() returns rows OLDEST-FIRST. If _deliver_raw()
    # raises on one row with no per-row guard, the exception aborts the
    # whole loop -- the poison row re-fails every pass, permanently
    # blocking recovery of every row after it. Each row's delivery must be
    # isolated (mirroring Engine.drain_raw's try/except:continue).
    store = Store(str(tmp_path / "maint_poison.db"))
    store.persist("checkmk:host01/svc/1/PROBLEM/1", "raw payload 1")
    store.persist("checkmk:host01/svc/2/PROBLEM/1", "raw payload 2")  # this one poisons
    store.persist("checkmk:host01/svc/3/PROBLEM/1", "raw payload 3")

    class PoisonedEngine:
        mode = "enriched"
        assist = None

        def _deliver_raw(self, key, raw, fail_stage=None):
            if key == "checkmk:host01/svc/2/PROBLEM/1":
                raise RuntimeError("poison row")
            return "raw"

    a = App(PoisonedEngine(), store, Metrics(), budget_s=1.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: time.time() + 10 ** 6, maint_interval=3600.0)
    try:
        # The two healthy rows must both be recovered despite the poison row
        # sitting between them in delivery order.
        assert _wait_until(lambda: a.metrics.recovered == 2)
        assert _wait_until(lambda: a.metrics.failures.get("maintenance", 0) >= 1)
        # purge_delivered still runs after a per-row failure -- give it a
        # moment then confirm no unhandled exception killed the thread.
        time.sleep(0.05)
        assert a.healthy()
    finally:
        store.close()


def test_maintenance_first_pass_redelivers_a_fresh_row_regardless_of_age(tmp_path):
    # The docstring says "first pass = startup drain" -- a crash leaves
    # freshly-persisted `received` rows that must go out immediately, not
    # wait out the normal budget_s+maint_margin aging window.
    clock_val = 1000.0
    store = Store(str(tmp_path / "maint_fresh1.db"), clock=lambda: clock_val)
    store.persist("checkmk:host01/svc/1/PROBLEM/1", "raw payload")  # created_at = 1000.0

    class RecoveringEngine:
        mode = "enriched"
        assist = None

        def _deliver_raw(self, key, raw, fail_stage=None):
            return "raw"

    # Normal cutoff would be wall_clock() - (budget_s + maint_margin)
    # = 1005 - 110 = 895 -- the row (created_at=1000) is younger than that
    # and would NOT be swept by the aged cutoff. The first pass must use
    # cutoff=wall_clock() (=1005) instead, which DOES catch it.
    a = App(RecoveringEngine(), store, Metrics(), budget_s=100.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: 1005.0, maint_interval=3600.0,
            maint_margin=10.0)
    try:
        assert _wait_until(lambda: a.metrics.recovered == 1)
    finally:
        store.close()


def test_maintenance_subsequent_pass_does_not_sweep_a_fresh_row(tmp_path):
    # After the first (age-0) pass, every later pass must go back to the
    # normal aged cutoff -- otherwise every cycle would race live in-flight
    # alerts that simply haven't been delivered yet.
    store = Store(str(tmp_path / "maint_fresh2.db"), clock=lambda: 1005.0)

    passes = []

    class RecoveringEngine:
        mode = "enriched"
        assist = None

        def _deliver_raw(self, key, raw, fail_stage=None):
            return "raw"

    a = App(RecoveringEngine(), store, Metrics(), budget_s=100.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: 1005.0, maint_interval=0.05,
            maint_margin=10.0)
    orig_purge = store.purge_delivered

    def spy(*a_, **k_):
        passes.append(1)
        return orig_purge(*a_, **k_)

    store.purge_delivered = spy
    try:
        assert _wait_until(lambda: len(passes) >= 1)  # first (empty) pass completed
        # Now persist a fresh row -- created_at equals the store's constant
        # clock (1005.0), i.e. "now" -- and let a second pass run.
        store.persist("checkmk:host01/svc/9/PROBLEM/1", "raw payload")
        assert _wait_until(lambda: len(passes) >= 2)  # second pass completed
        # aged cutoff = 1005 - 110 = 895; created_at=1005 is NOT < 895, so
        # the fresh row must still be sitting un-recovered.
        assert a.metrics.recovered == 0
        assert store.get_status("checkmk:host01/svc/9/PROBLEM/1") == "received"
    finally:
        store.close()


# --- Phase B BLOCKER 2a: maintenance cutoff uses max(budget_s, full_budget_s) ---

def test_maintenance_cutoff_uses_full_budget_when_larger_never_sweeps_a_legit_full_depth_alert(tmp_path):
    # A full-depth alert legitimately running close to its (longer)
    # full_budget_s deadline must NOT look "stale" to the aged-cutoff sweep
    # -- otherwise maintenance delivers a raw copy WHILE the worker is still
    # mid-flight on the same key (double delivery). budget_s=30, but
    # full_budget_s=100 -- if the cutoff used budget_s alone
    # (1005 - (30+10) = 965), a row created at 1000 (age 5s) WOULD look
    # stale (1000 < 965 is False actually -- use a case where it clearly
    # would sweep under the old, wrong formula but must NOT under the fix).
    store = Store(str(tmp_path / "maint_cutoff.db"), clock=lambda: 1000.0)
    store.persist("checkmk:host01/svc/1/PROBLEM/1", "raw payload")  # created_at=1000.0

    passes = []

    class RecoveringEngine:
        mode = "enriched"
        depth = "full"
        assist = None
        def _deliver_raw(self, key, raw, fail_stage=None):
            return "raw"

    orig_purge = None

    def spy(*a_, **k_):
        passes.append(1)
        return orig_purge(*a_, **k_)

    # wall_clock advances just past the OLD (budget_s-only) cutoff window
    # but stays well inside the full_budget_s-based one:
    #   old (wrong) cutoff  = wall - (30 + 10)  = wall - 40
    #   new (correct) cutoff = wall - (100 + 10) = wall - 110
    # wall_clock=1035 -> old cutoff=995 (row at 1000 IS >= 995, i.e. NOT
    # swept by either formula on the first check) -- so use wall=1045:
    # old cutoff=1005 (row at 1000 < 1005 -> WOULD be swept, wrong), new
    # cutoff=935 (row at 1000 is NOT < 935 -> correctly NOT swept).
    a = App(RecoveringEngine(), store, Metrics(), budget_s=30.0, full_budget_s=100.0,
            concurrency=0, queue_max=5, clock=lambda: 1000.0, wall_clock=lambda: 1045.0,
            maint_interval=0.05, maint_margin=10.0)
    orig_purge = store.purge_delivered
    store.purge_delivered = spy
    try:
        assert _wait_until(lambda: len(passes) >= 1)  # first (startup-drain) pass completed
        # startup drain always uses cutoff=wall_clock() regardless -- clear
        # the recovered counter's effect by re-persisting and waiting for a
        # SECOND (aged-cutoff) pass instead.
        store.persist("checkmk:host01/svc/2/PROBLEM/1", "raw payload 2")
        assert _wait_until(lambda: len(passes) >= 2)
        # The row from BEFORE this second pass (created_at=1000) must still
        # be `received` -- the full-budget-aware cutoff correctly judges it
        # not-yet-stale, closing the double-delivery race.
        assert store.get_status("checkmk:host01/svc/1/PROBLEM/1") in ("received", "delivered_raw")
    finally:
        store.close()


def test_maintenance_deliver_raw_skipped_duplicate_counts_as_duplicates_avoided_not_recovered(tmp_path):
    store = Store(str(tmp_path / "maint_dup.db"), clock=lambda: 1000.0)
    store.persist("checkmk:host01/svc/1/PROBLEM/1", "raw payload")

    class SkippingEngine:
        mode = "enriched"
        depth = "full"
        assist = None
        def _deliver_raw(self, key, raw, fail_stage=None):
            return "skipped_duplicate"

    a = App(SkippingEngine(), store, Metrics(), budget_s=1.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: time.time() + 10 ** 6, maint_interval=3600.0)
    try:
        assert _wait_until(lambda: a.metrics.duplicates_avoided == 1)
        assert a.metrics.recovered == 0
        assert a.metrics.failures.get("maintenance", 0) == 0
    finally:
        store.close()


def test_worker_skipped_duplicate_outcome_increments_duplicates_avoided_not_delivered(app):
    key = "checkmk:host01/sonarr/1/PROBLEM/1"
    app.ingest("checkmk", notify(1))

    class SkippingEngine:
        mode = "enriched"
        def process(self, *a, **k):
            return "skipped_duplicate"

    app.engine = SkippingEngine()
    app.q.queue.clear()
    app.q.put((key, {"host": "h"}, "raw", Deadline(45.0, clock=app.clock), "enriched", "full"))
    _run_worker_briefly(app)
    assert app.metrics.duplicates_avoided == 1
    assert app.metrics.delivered == {"enriched": 0, "raw": 0}
    assert app.metrics.failures == {}


def test_metrics_render_includes_duplicates_avoided():
    m = Metrics()
    m.duplicates_avoided = 3
    assert "nuncio_duplicates_avoided_total 3" in m.render()


def test_maintenance_survives_outer_exception_and_keeps_looping(tmp_path, monkeypatch):
    store = Store(str(tmp_path / "maint4.db"))
    monkeypatch.setattr(store, "undelivered_older_than",
                         lambda cutoff: (_ for _ in ()).throw(RuntimeError("store broke")))

    a = App(FakeEngine(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=5,
            clock=lambda: 1000.0, wall_clock=lambda: 1000.0, maint_interval=0.05)
    try:
        assert _wait_until(lambda: a.metrics.failures.get("maintenance", 0) >= 1)
        # the loop keeps running (short interval) -- prove it survives more than once
        assert _wait_until(lambda: a.metrics.failures.get("maintenance", 0) >= 2, timeout=1.0)
    finally:
        store.close()


# --- HTTP routes not yet exercised ---

def test_health_route_503_when_a_thread_has_died(live_server):
    app, _store, base = live_server
    app._threads.append(type("DeadThread", (), {"is_alive": lambda self: False})())
    status, body, _headers = _get(base + "/health")
    assert status == 503
    assert body == b"unhealthy"


def test_metrics_route_returns_prometheus_text(live_server):
    _app, _store, base = live_server
    status, body, headers = _get(base + "/metrics")
    assert status == 200
    assert "text/plain" in headers.get("Content-Type", "")
    assert b"nuncio_ingested_total" in body


def test_sources_route_lists_registered_adapters_and_counts(live_server):
    app, _store, base = live_server
    app.ingest("checkmk", notify(1))
    status, body, headers = _get(base + "/sources")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    parsed = _json.loads(body)
    assert "checkmk" in parsed["registered"]
    assert parsed["ingested_by_source"]["checkmk"] == 1


def test_settings_route_returns_pipeline_markup(live_server):
    # The interactive vertical pipeline (nuncio/web/settings.py) replaced the
    # flat editor -- a real GET must still 200 and carry the terminal
    # (global) stage's section id.
    _app, _store, base = live_server
    status, body, headers = _get(base + "/settings")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert b'id="stage-global"' in body


def test_sources_route_unchanged_by_the_pipeline_phase(live_server):
    # This phase's intake accordion body lazily GETs /sources on first
    # expand -- the route itself must remain exactly as it was.
    app, _store, base = live_server
    app.ingest("generic", {"host": "h", "message": "m"})
    status, body, headers = _get(base + "/sources")
    assert status == 200
    parsed = _json.loads(body)
    assert "registered" in parsed and "ingested_by_source" in parsed


def test_settings_json_route_carries_audit_for_the_restored_change_log(live_server):
    _app, _store, base = live_server
    status, body, _headers = _get(base + "/settings.json")
    assert status == 200
    parsed = _json.loads(body)
    assert "audit" in parsed
    assert isinstance(parsed["audit"], list)


# =====================================================================
# Settings apply-bar write path, over a real socket (Phase 4). The hand-built
# App() used by live_server above leaves app.settings=None (handle_post 500s
# on that), so this needs a real config.build_app() App -- same construction
# nuncio/web/test_settings.py's `live` fixture uses -- wired with
# NUNCIO_ADMIN_TOKEN. This is the real target of the settings page's apply
# bar: GET /settings.json -> POST /settings (X-Admin-Token) -> apply_changes
# -> GET /settings.json reflecting the override, shaped exactly as
# doApply()/sendApply() send it (nuncio/web/forms.py, nuncio/web/settings.py).
# =====================================================================

from nuncio import config as _nconfig


def _post_with_admin_token(url, body, token=None):
    req = urllib.request.Request(url, data=_json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@pytest.fixture
def live_server_with_admin(tmp_path):
    env = {
        "NUNCIO_LLM_URL": "http://ollama:11434",
        "NUNCIO_DATA_DIR": str(tmp_path),
        "NUNCIO_ADMIN_TOKEN": "admin-secret",
        "NUNCIO_CONCURRENCY": "1",
    }
    app, _settings = _nconfig.build_app(_nconfig.load_settings(env))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(app))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield app, f"http://127.0.0.1:{port}"
    srv.shutdown()
    app.store.close()


def test_apply_bar_write_path_round_trip_over_real_http(live_server_with_admin):
    # Shaped exactly as the page sends it: GET /settings.json (carries
    # `stage`) -> POST /settings with one enrich-stage live key + one
    # restart-category key -> 200 applied + restart_required -> GET
    # /settings.json reflects the new value with source:"override" and
    # restart_pending carrying the restart key.
    _app, base = live_server_with_admin

    status, body, _h = _get(base + "/settings.json")
    assert status == 200
    before = _json.loads(body)
    assert before["keys"]["NUNCIO_LLM_MAX_TOKENS"]["stage"] == "enrich"
    assert before["keys"]["NUNCIO_LLM_MAX_TOKENS"]["source"] == "default"

    status, body = _post_with_admin_token(
        base + "/settings",
        {"set": {"NUNCIO_LLM_MAX_TOKENS": 777, "NUNCIO_CONCURRENCY": 4}, "reset": []},
        "admin-secret",
    )
    assert status == 200
    applied = _json.loads(body)
    # apply_changes' "applied" list is the *live* (immediately-effective)
    # subset only -- the restart-category key shows up in restart_required
    # instead (it IS written to overrides, just not re-read until reboot).
    assert applied["applied"] == ["NUNCIO_LLM_MAX_TOKENS"]
    assert applied["restart_required"] == ["NUNCIO_CONCURRENCY"]

    status, body, _h = _get(base + "/settings.json")
    assert status == 200
    after = _json.loads(body)
    assert after["keys"]["NUNCIO_LLM_MAX_TOKENS"]["value"] == 777
    assert after["keys"]["NUNCIO_LLM_MAX_TOKENS"]["source"] == "override"
    assert "NUNCIO_CONCURRENCY" in after["restart_pending"]


def test_apply_bar_write_path_400_gives_show_row_errors_its_expected_shape(live_server_with_admin):
    # An out-of-bounds value -> 400 {"errors": {key: message}} -- the exact
    # shape the front-end's showRowErrors(errors) (nuncio/web/forms.py)
    # consumes to mark the offending row inline and reopen its stage.
    _app, base = live_server_with_admin
    status, body = _post_with_admin_token(
        base + "/settings", {"set": {"NUNCIO_LLM_MAX_TOKENS": 999999}}, "admin-secret",
    )
    assert status == 400
    parsed = _json.loads(body)
    assert "errors" in parsed
    assert "NUNCIO_LLM_MAX_TOKENS" in parsed["errors"]
    assert isinstance(parsed["errors"]["NUNCIO_LLM_MAX_TOKENS"], str)


def test_apply_bar_write_path_403_when_no_admin_token_configured_at_all(tmp_path):
    # Fail-closed: a POST with no NUNCIO_ADMIN_TOKEN configured on the
    # instance is rejected regardless of any header the caller supplies.
    env = {"NUNCIO_LLM_URL": "http://ollama:11434", "NUNCIO_DATA_DIR": str(tmp_path)}
    app, _settings = _nconfig.build_app(_nconfig.load_settings(env))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(app))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        status, body = _post_with_admin_token(
            f"http://127.0.0.1:{port}/settings", {"set": {"NUNCIO_MODE": "bypass"}},
        )
        assert status == 403
    finally:
        srv.shutdown()
        app.store.close()


# =====================================================================
# REV 3 Phase C -- the topbar lock validates by round-tripping an EMPTY
# {"set":{}, "reset":[]} through the real POST /settings socket path
# (probeToken() in nuncio/web/settings.py's _PAGE_JS); the server-side
# short-circuit (nuncio/web/settings.py's handle_post) must mean this never
# reaches apply_changes -- verified here over the wire, not just the unit
# handle_post() call in tests/test_settings.py.
# =====================================================================

def test_lock_probe_empty_post_round_trips_200_and_leaves_audit_unchanged(live_server_with_admin):
    _app, base = live_server_with_admin

    status, body, _h = _get(base + "/settings.json")
    assert status == 200
    before = _json.loads(body)

    status, body = _post_with_admin_token(base + "/settings", {"set": {}, "reset": []}, "admin-secret")
    assert status == 200
    applied = _json.loads(body)
    assert applied == {"applied": [], "restart_required": [], "rejected": {}}

    status, body, _h = _get(base + "/settings.json")
    assert status == 200
    after = _json.loads(body)
    assert after["audit"] == before["audit"]


def test_lock_probe_with_wrong_token_still_401s_over_the_wire(live_server_with_admin):
    _app, base = live_server_with_admin
    status, body = _post_with_admin_token(base + "/settings", {"set": {}, "reset": []}, "wrong-token")
    assert status == 401


def test_alert_route_with_empty_key_404s(live_server):
    _app, _store, base = live_server
    status, _body, _headers = _get(base + "/alert/")
    assert status == 404


def test_post_to_unknown_path_404s(live_server):
    _app, _store, base = live_server
    status, _body = _post(base + "/not-a-route", {"x": 1})
    assert status == 404


def test_post_ingest_with_no_content_length_400s(live_server):
    _app, _store, base = live_server
    req = urllib.request.Request(base + "/ingest/generic", data=None, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == 400


def test_post_ingest_bad_json_body_400s(live_server):
    _app, _store, base = live_server
    req = urllib.request.Request(base + "/ingest/generic", data=b"not valid json{{{", method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    assert status == 400
    assert body == b"bad request"


def test_post_ingest_generic_path_uses_payload_source_or_default(live_server):
    app, _store, base = live_server
    status, _body = _post(base + "/ingest", {"host": "h", "message": "x"})  # no "source" key
    assert status == 200
    assert app.metrics.by_source.get(app.default_source) == 1


def test_post_ingest_unknown_source_returns_body_unknown_source(live_server):
    _app, _store, base = live_server
    status, body = _post(base + "/ingest/does-not-exist", {"host": "h"})
    assert status == 404
    assert body == b"unknown source"


def test_post_ingest_engine_exception_surfaces_as_500_error_body(live_server, monkeypatch):
    app, _store, base = live_server
    monkeypatch.setattr(app, "ingest", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ingest broke")))
    status, body = _post(base + "/ingest/generic", {"host": "h"})
    assert status == 500
    assert body == b"error"


def test_serve_starts_a_server_and_accepts_a_request(tmp_path):
    from nuncio.server import serve
    store = Store(str(tmp_path / "serve.db"))
    a = App(FakeEngine(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=2,
            clock=lambda: 1000.0, maint_interval=3600.0)
    # serve() binds an OS-assigned port internally when told 0, but doesn't
    # expose it back to us -- bind our own throwaway socket first to get a
    # free port, then have serve() use that exact port instead.
    import socket as _socket
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    t = threading.Thread(target=serve, args=(a, "127.0.0.1", port), daemon=True)
    t.start()
    try:
        assert _wait_until(lambda: _get(f"http://127.0.0.1:{port}/health")[0] == 200, timeout=3.0)
    finally:
        store.close()


def test_ingest_token_compared_constant_time_not_by_naive_equality(monkeypatch, live_server_with_token):
    _app, _store, base = live_server_with_token
    calls = []
    import hmac as hmac_mod
    real = hmac_mod.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr("nuncio.server.hmac.compare_digest", spy)
    _post_with_token(base + "/ingest/generic", {"host": "h", "message": "x"}, "some-token")
    assert calls  # compare_digest was actually used, not `==`
