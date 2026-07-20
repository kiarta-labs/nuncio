"""OpenObserveClient / LokiClient: real LogClient implementations."""
import json
import re
from urllib.parse import parse_qs, urlsplit

from nuncio.clients.logs import LokiClient, OpenObserveClient


# --- OpenObserveClient ---

def test_openobserve_parses_hits_and_orders_newest_last():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        assert method == "POST"
        # OpenObserve's search endpoint is org-level; the stream is named in the SQL.
        assert url.endswith("/api/default/_search")
        assert '"mystream"' in payload["query"]["sql"]
        return {"hits": [{"message": "newest line"}, {"message": "older line"}]}

    client = OpenObserveClient("http://o2:5080/api/default", stream="mystream", transport=fake_transport)
    lines = client.query("web-1", "sonarr", 900)
    assert lines == ["older line", "newest line"]


def test_openobserve_sends_basic_auth_headers():
    captured = {}

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        captured["headers"] = headers
        return {"hits": []}

    client = OpenObserveClient("http://o2:5080/api/default", user="svc", token="pw", transport=fake_transport)
    client.query("web-1")
    assert captured["headers"]["Authorization"].startswith("Basic ")


def test_openobserve_query_includes_window_as_microsecond_bounds():
    captured = {}

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        captured["payload"] = payload
        return {"hits": []}

    client = OpenObserveClient("http://o2:5080/api/default", transport=fake_transport)
    client.query("web-1", "sonarr", window_s=600)
    q = captured["payload"]["query"]
    assert q["end_time"] - q["start_time"] == 600 * 1_000_000


def test_openobserve_falls_back_to_str_of_hit_when_no_known_field():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        return {"hits": [{"weird_field": "value"}]}

    client = OpenObserveClient("http://o2:5080/api/default", transport=fake_transport)
    lines = client.query("web-1")
    assert "weird_field" in lines[0]


def test_openobserve_degrades_to_empty_list_on_transport_exception():
    def raising_transport(*a, **kw):
        raise TimeoutError("connection timed out")

    client = OpenObserveClient("http://o2:5080/api/default", transport=raising_transport)
    assert client.query("web-1", "sonarr", 900) == []


def test_openobserve_degrades_on_malformed_response_shape():
    def fake_transport(*a, **kw):
        return {"unexpected": "shape"}  # no "hits" key

    client = OpenObserveClient("http://o2:5080/api/default", transport=fake_transport)
    assert client.query("web-1") == []


def test_openobserve_with_no_base_url_returns_empty_without_calling_transport():
    calls = []

    def fake_transport(*a, **kw):
        calls.append(1)
        return {"hits": []}

    client = OpenObserveClient("", transport=fake_transport)
    assert client.query("web-1") == []
    assert calls == []


def test_openobserve_caps_lines_by_max_lines():
    hits = [{"message": f"line {i}"} for i in range(10)]

    def fake_transport(*a, **kw):
        return {"hits": hits}

    client = OpenObserveClient("http://o2:5080/api/default", transport=fake_transport, max_lines=3)
    lines = client.query("web-1")
    assert len(lines) == 3


def test_openobserve_caps_by_byte_budget():
    hits = [{"message": "x" * 100} for _ in range(20)]

    def fake_transport(*a, **kw):
        return {"hits": hits}

    client = OpenObserveClient("http://o2:5080/api/default", transport=fake_transport,
                                max_lines=100, max_bytes=250)
    lines = client.query("web-1")
    assert sum(len(l) for l in lines) <= 250
    assert len(lines) < 20


# --- LokiClient ---

def test_loki_parses_streams_and_orders_newest_last():
    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        assert method == "GET"
        assert "query_range" in url
        return {
            "data": {
                "result": [
                    {"stream": {"host": "web-1"}, "values": [
                        ["1000000000", "older line"],
                        ["3000000000", "newest line"],
                    ]},
                ]
            }
        }

    client = LokiClient("http://loki:3100", transport=fake_transport)
    lines = client.query("web-1", "sonarr", 900)
    assert lines == ["older line", "newest line"]


def test_loki_merges_multiple_streams_by_timestamp():
    def fake_transport(*a, **kw):
        return {
            "data": {
                "result": [
                    {"stream": {}, "values": [["2000000000", "middle"]]},
                    {"stream": {}, "values": [["1000000000", "first"], ["3000000000", "last"]]},
                ]
            }
        }

    client = LokiClient("http://loki:3100", transport=fake_transport)
    lines = client.query("web-1")
    assert lines == ["first", "middle", "last"]


def test_loki_returns_empty_without_host():
    calls = []

    def fake_transport(*a, **kw):
        calls.append(1)
        return {"data": {"result": []}}

    client = LokiClient("http://loki:3100", transport=fake_transport)
    assert client.query(None) == []
    assert calls == []


def test_loki_degrades_to_empty_list_on_transport_exception():
    def raising_transport(*a, **kw):
        raise ConnectionRefusedError("nope")

    client = LokiClient("http://loki:3100", transport=raising_transport)
    assert client.query("web-1", "sonarr", 900) == []


def test_loki_degrades_on_malformed_response_shape():
    def fake_transport(*a, **kw):
        return {"data": None}

    client = LokiClient("http://loki:3100", transport=fake_transport)
    assert client.query("web-1") == []


def test_loki_ignores_malformed_value_pairs():
    def fake_transport(*a, **kw):
        return {"data": {"result": [{"values": [["not-an-int", "bad"], ["5", "good"]]}]}}

    client = LokiClient("http://loki:3100", transport=fake_transport)
    lines = client.query("web-1")
    assert lines == ["good"]


def test_loki_sends_bearer_token_when_configured():
    captured = {}

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        captured["headers"] = headers
        return {"data": {"result": []}}

    client = LokiClient("http://loki:3100", token="tok123", transport=fake_transport)
    client.query("web-1")
    assert captured["headers"]["Authorization"] == "Bearer tok123"


# --- LogQL selector / line-filter escaping (host/unit are alert-controlled;
# the selector is a regex `=~` matcher, the line filter is a plain substring
# `|=` match -- different contexts need different escaping, see clients/logs.py) --

def _queried_logql(host, unit=None):
    queries = []

    def fake_transport(method, url, headers=None, payload=None, timeout=None, max_bytes=None):
        queries.append(parse_qs(urlsplit(url).query)["query"][0])
        return {"data": {"result": []}}

    client = LokiClient("http://loki:3100", transport=fake_transport)
    client.query(host, unit)
    return queries[0]


def _selector_regex_source(host, unit=None):
    logql = _queried_logql(host, unit)
    m = re.match(r'^\{host=~"(.*?)"\}', logql, re.DOTALL)
    assert m, f"unexpected logql shape: {logql!r}"
    return json.loads('"' + m.group(1) + '"')


def _line_filter_literal(host, unit):
    logql = _queried_logql(host, unit)
    m = re.search(r'\|= "(.*)"$', logql, re.DOTALL)
    assert m, f"unexpected logql shape: {logql!r}"
    return json.loads('"' + m.group(1) + '"')


def test_logql_selector_injection_breakout_is_neutralized():
    host = 'svr"} |= "pwned'
    src = _selector_regex_source(host)
    assert src == ".*" + re.escape(host) + ".*"
    logql = _queried_logql(host)
    # exactly one selector opening brace -- a successful breakout would
    # close the selector early and append its own stream matcher/filter.
    assert logql.count("{host") == 1


def test_logql_line_filter_escapes_backslash_before_quote():
    # the line filter is a plain substring match (NOT a regex context) --
    # only backslash-then-quote string-literal escaping applies here.
    unit = 'a"b'
    assert _line_filter_literal("web-1", unit) == unit

    unit2 = 'a\\"b'  # a literal backslash immediately followed by a quote
    assert _line_filter_literal("web-1", unit2) == unit2


def test_dotted_host_still_queries():
    host = "web-1.example.net"
    src = _selector_regex_source(host)
    assert src == ".*" + re.escape(host) + ".*"
    assert re.fullmatch(src, host)
