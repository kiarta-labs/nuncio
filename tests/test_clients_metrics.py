"""PrometheusClient / CheckmkClient: real MetricsClient implementations."""
import json
import re
from urllib.parse import parse_qs, urlsplit

from nuncio.clients.metrics import CheckmkClient, PrometheusClient


# --- PrometheusClient ---

def test_prometheus_formats_series_as_metric_equals_value_lines():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        assert method == "GET"
        return {
            "status": "success",
            "data": {"result": [
                {"metric": {"__name__": "up", "instance": "web-1:9100"}, "value": [1700000000, "1"]},
            ]},
        }

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    lines = client.query("web-1")  # host-only query: exactly one PromQL call
    assert lines == ['up{instance="web-1:9100"} = 1']


def test_prometheus_queries_both_instance_and_job_when_service_given():
    queried = []

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        queried.append(url)
        return {"status": "success", "data": {"result": []}}

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    client.query("web-1", "sonarr")
    assert len(queried) == 2
    assert any("instance" in q for q in queried)
    assert any("job" in q for q in queried)


def test_prometheus_skips_a_failed_status_response():
    def fake_transport(*a, **kw):
        return {"status": "error", "error": "bad query"}

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    assert client.query("web-1") == []


def test_prometheus_returns_empty_without_host():
    calls = []

    def fake_transport(*a, **kw):
        calls.append(1)
        return {"status": "success", "data": {"result": []}}

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    assert client.query(None) == []
    assert calls == []


def test_prometheus_degrades_to_empty_list_on_transport_exception():
    def raising_transport(*a, **kw):
        raise TimeoutError("no response")

    client = PrometheusClient("http://prom:9090", transport=raising_transport)
    assert client.query("web-1", "sonarr") == []


def test_prometheus_degrades_on_malformed_response_shape():
    def fake_transport(*a, **kw):
        return "not-even-a-dict"

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    assert client.query("web-1") == []


def test_prometheus_respects_limit():
    def fake_transport(*a, **kw):
        return {"status": "success", "data": {"result": [
            {"metric": {"__name__": f"m{i}"}, "value": [0, "1"]} for i in range(10)
        ]}}

    client = PrometheusClient("http://prom:9090", transport=fake_transport, limit=3)
    lines = client.query("web-1")
    assert len(lines) == 3


def test_prometheus_extra_queries_are_included():
    queried = []

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        queried.append(url)
        return {"status": "success", "data": {"result": []}}

    client = PrometheusClient("http://prom:9090", transport=fake_transport,
                               extra_queries=["node_load1"])
    client.query("web-1")
    assert any("node_load1" in q for q in queried)


# --- CheckmkClient ---

def test_checkmk_reports_host_and_service_state_fields():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        if "/objects/host/" in url:
            return {"extensions": {"state": 0, "plugin_output": "OK - all good"}}
        return {"extensions": {"state": 2, "plugin_output": "CRITICAL - disk full"}}

    client = CheckmkClient("http://cmk/check_mk/api/1.0", user="automation", token="secret",
                            transport=fake_transport)
    lines = client.query("web-1", "disk /")
    assert any("host.state = 0" in l for l in lines)
    assert any("service.plugin_output = CRITICAL - disk full" in l for l in lines)


def test_checkmk_sends_its_own_bearer_scheme():
    captured = {}

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        captured["headers"] = headers
        return {"extensions": {}}

    client = CheckmkClient("http://cmk/api", user="automation", token="secret", transport=fake_transport)
    client.query("web-1")
    assert captured["headers"]["Authorization"] == "Bearer automation secret"


def test_checkmk_works_with_host_only_when_no_service_given():
    calls = []

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        calls.append(url)
        return {"extensions": {"state": 0}}

    client = CheckmkClient("http://cmk/api", transport=fake_transport)
    lines = client.query("web-1")
    assert len(calls) == 1  # only the host object, no service call
    assert any("host.state = 0" in l for l in lines)


def test_checkmk_returns_empty_without_host():
    calls = []

    def fake_transport(*a, **kw):
        calls.append(1)
        return {"extensions": {}}

    client = CheckmkClient("http://cmk/api", transport=fake_transport)
    assert client.query(None) == []
    assert calls == []


def test_checkmk_degrades_to_empty_list_on_transport_exception():
    def raising_transport(*a, **kw):
        raise ConnectionResetError("reset")

    client = CheckmkClient("http://cmk/api", transport=raising_transport)
    assert client.query("web-1", "disk /") == []


def test_checkmk_host_failure_does_not_block_the_service_lookup():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        if "/objects/host/" in url:
            raise TimeoutError("host lookup timed out")
        return {"extensions": {"state": 1}}

    client = CheckmkClient("http://cmk/api", transport=fake_transport)
    lines = client.query("web-1", "disk /")
    assert any("service.state = 1" in l for l in lines)


# --- PromQL injection / regex-metachar escaping (host/service are
# alert-controlled and land unescaped-except-for-quotes in a double-quoted
# `=~` regex matcher; a bare host string containing `"` + PromQL syntax
# could break out of the matcher into arbitrary query text) ---------------

def _queried_promql(host, service=None):
    queries = []

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        queries.append(parse_qs(urlsplit(url).query)["query"][0])
        return {"status": "success", "data": {"result": []}}

    client = PrometheusClient("http://prom:9090", transport=fake_transport)
    client.query(host, service)
    return queries


def _regex_source_for(host):
    """Round-trip the rendered `up{instance=~"..."}"` query back to the raw
    regex source the PromQL engine would actually see: the value is
    double-quote-escaped exactly like a JSON string (only `\\` and `"` are
    ever escaped, same two characters, same escape char), so wrapping the
    captured content in quotes and running it through json.loads undoes
    exactly what _escape_promql applied."""
    decoded = _queried_promql(host)[0]
    m = re.match(r'^up\{instance=~"(.*)"\}$', decoded, re.DOTALL)
    assert m, f"query didn't match the expected shape: {decoded!r}"
    return json.loads('"' + m.group(1) + '"')


def test_promql_injection_breakout_is_neutralized():
    host = 'svr\\"} or up{job="x'
    src = _regex_source_for(host)
    # the rendered regex source is EXACTLY ".*" + re.escape(host) + ".*" --
    # every character of the hostile payload is regex-literal, so there is
    # no way for it to close the matcher's string or open a second `up{`.
    assert src == ".*" + re.escape(host) + ".*"
    decoded = _queried_promql(host)[0]
    assert decoded.count("up{") == 1


def test_promql_regex_metachars_in_host_are_literal():
    host = "web.1+"
    src = _regex_source_for(host)
    assert src == ".*" + re.escape(host) + ".*"
    # a DIFFERENT string that a loose (unescaped) ".", "+" would also match
    # must NOT match now that they're regex-literal.
    assert not re.fullmatch(src, "webX1")  # "." no longer means "any char"
    assert re.fullmatch(src, host)         # but the real value still matches itself


def test_dotted_host_still_queries():
    # documents the intentional stricter match: a dotted host is escaped
    # (its dots are literal, not "any char" wildcards) rather than left as a
    # loose regex, while the legitimate query is still issued and the real
    # host string still matches its own rendered pattern.
    host = "web-1.example.net"
    src = _regex_source_for(host)
    assert src == ".*" + re.escape(host) + ".*"
    assert re.fullmatch(src, host)
