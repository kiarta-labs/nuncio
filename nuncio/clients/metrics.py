"""Real `MetricsClient` implementations: Prometheus and CheckMK.

Both are strictly read-only queries: Prometheus's instant-query HTTP API
(`/api/v1/query`, GET only) and CheckMK's REST API object-GET endpoints
(`/objects/host/<name>`, `/objects/service/<host;service>`) -- never an
action, activate-changes, or config-write endpoint. Any failure (timeout,
connection error, bad auth, unexpected shape) degrades to an empty list
rather than raising into the collector.
"""
import logging
import re
from urllib.parse import quote, urlencode

from nuncio.clients.http import request_json

log = logging.getLogger("nuncio.clients.metrics")


def _escape_promql(value):
    # host/service are alert-controlled and land in a double-quoted `=~`
    # regex matcher. re.escape() FIRST neutralizes the value as a regex (so
    # it can only ever match itself literally, closing the secondary
    # match-broadening risk from unescaped metachars) -- then the quote is
    # escaped for the string literal. Order matters: re.escape's own
    # backslashes must be string-escaped too, or a value containing a
    # backslash would double-escape and the literal-closing quote could
    # still break out (escape backslash BEFORE quote).
    return re.escape(str(value)).replace("\\", "\\\\").replace('"', '\\"')


class PrometheusClient:
    """Queries a small, generic set of PromQL instant-vector expressions
    scoped to the alert's host/service via broad label matching, and
    renders each returned series as a `metric{labels} = value` summary
    line. Exact metric names are deployment-specific (nobody agrees on
    what their exporters are called), so this deliberately matches on the
    common `instance`/`job` labels rather than assuming a particular
    exporter's metric catalog. `extra_queries` lets an operator add more
    PromQL expressions without a code change."""

    def __init__(self, base_url, timeout=4.0, limit=40, transport=None, extra_queries=()):
        self._base_url = (base_url or "").rstrip("/")
        self._timeout = timeout
        self._limit = limit
        self._transport = transport or request_json
        self._extra_queries = tuple(q for q in extra_queries if q)

    def query(self, host, service=None):
        if not self._base_url or not host:
            return []
        try:
            return self._query(host, service)
        except Exception as e:
            log.debug("prometheus metrics query failed: %r", e)
            return []

    def _queries_for(self, host, service):
        queries = [f'up{{instance=~".*{_escape_promql(host)}.*"}}']
        if service:
            queries.append(f'up{{job=~".*{_escape_promql(service)}.*"}}')
        queries.extend(self._extra_queries)
        return queries

    def _query(self, host, service):
        lines = []
        for promql in self._queries_for(host, service):
            if len(lines) >= self._limit:
                break
            url = f"{self._base_url}/api/v1/query?{urlencode({'query': promql})}"
            data = self._transport("GET", url, headers=None, payload=None,
                                    timeout=self._timeout, max_bytes=1_000_000)
            if not data or data.get("status") != "success":
                continue
            for series in ((data.get("data") or {}).get("result") or []):
                if len(lines) >= self._limit:
                    break
                line = _format_series(series)
                if line:
                    lines.append(line)
        return lines


def _format_series(series):
    metric = series.get("metric") or {}
    name = metric.get("__name__", "metric")
    labels = ",".join(f'{k}="{v}"' for k, v in sorted(metric.items()) if k != "__name__")
    value = None
    v = series.get("value")
    if isinstance(v, list) and len(v) == 2:
        value = v[1]
    label_part = f"{{{labels}}}" if labels else ""
    return f"{name}{label_part} = {value}"


_INTERESTING_FIELDS = (
    "state", "state_type", "plugin_output", "last_check",
    "acknowledged", "in_downtime", "perf_data",
)


def _fields_from_extensions(obj, prefix):
    ext = (obj or {}).get("extensions") or {}
    return [f"{prefix}.{key} = {ext[key]}" for key in _INTERESTING_FIELDS if key in ext]


class CheckmkClient:
    """Queries the CheckMK REST API's object-GET endpoints for a host's,
    and (if given) a service's, current monitored state -- state,
    plugin/check output, last check time, ack/downtime flags. Never touches
    an action or activation endpoint. `user`/`token` are an automation
    user's name and secret, sent as CheckMK's `Bearer <user> <secret>`
    scheme (not standard OAuth bearer -- this is CheckMK's own format)."""

    def __init__(self, base_url, user="", token="", timeout=4.0, limit=40, transport=None):
        self._base_url = (base_url or "").rstrip("/")
        self._headers = {"Authorization": f"Bearer {user} {token}"} if user else {}
        self._timeout = timeout
        self._limit = limit
        self._transport = transport or request_json

    def query(self, host, service=None):
        if not self._base_url or not host:
            return []
        try:
            return self._query(host, service)
        except Exception as e:
            log.debug("checkmk metrics query failed: %r", e)
            return []

    def _query(self, host, service):
        lines = []
        h = self._get_object(f"/objects/host/{quote(host, safe='')}")
        if h:
            lines.extend(_fields_from_extensions(h, "host"))
        if service:
            service_id = quote(f"{host};{service}", safe="")
            s = self._get_object(f"/objects/service/{service_id}")
            if s:
                lines.extend(_fields_from_extensions(s, "service"))
        return lines[: self._limit]

    def _get_object(self, path):
        url = f"{self._base_url}{path}"
        try:
            return self._transport("GET", url, headers=self._headers, payload=None,
                                    timeout=self._timeout, max_bytes=1_000_000)
        except Exception as e:
            log.debug("checkmk object fetch failed for %s: %r", path, e)
            return None
