"""Real `LogClient` implementations: OpenObserve and Loki.

Both speak their target's native read-only search HTTP API -- OpenObserve's
`_search` endpoint, Loki's `query_range` endpoint -- and never touch a
write/ingest/admin endpoint. Every public call is wrapped in a broad
`except Exception`: a timeout, connection failure, bad auth, malformed JSON,
or unexpected response shape all degrade to an empty result rather than
raising into the collector, so a misconfigured or unreachable log backend
never blocks or breaks alert enrichment -- the "Recent logs" section just
reads "no matching log lines" instead.

Exact field/label names in either backend are deployment-specific (nobody
agrees on what the message field or the host label is called), so both
clients make a best-effort, broadly-matching query rather than assuming one
particular schema.
"""
import logging
import time
import urllib.parse

from nuncio.clients.http import basic_or_bearer_auth, request_json

log = logging.getLogger("nuncio.clients.logs")


def _escape_sql(value):
    return str(value).replace("'", "''")


def _escape_logql(value):
    return str(value).replace('"', '\\"')


def _line_text(hit):
    if isinstance(hit, str):
        return hit
    if isinstance(hit, dict):
        for key in ("message", "log", "_raw", "line", "msg"):
            v = hit.get(key)
            if v:
                return str(v)
        return str(hit)
    return str(hit)


def _select_newest(newest_first_raws, max_lines, max_bytes):
    """`newest_first_raws` must already be ordered newest-first. Returns
    extracted text, still newest-first, capped both by count and by
    cumulative byte budget -- when trimming for size, this keeps the most
    recent lines and drops the older ones, not the other way round."""
    lines = []
    total = 0
    for raw in newest_first_raws[:max_lines]:
        text = _line_text(raw).strip()
        if not text:
            continue
        total += len(text) + 1
        if total > max_bytes:
            break
        lines.append(text)
    return lines


class OpenObserveClient:
    """Queries an OpenObserve `_search` endpoint via HTTP POST.

    `base_url` is the API base up to and including the org segment (e.g.
    `http://openobserve.example:5080/api/default`) -- this client appends
    `/_search` and names the stream in the SQL query. `stream` is the
    OpenObserve stream to query (configured via `NUNCIO_LOGS_INDEX`)."""

    def __init__(self, base_url, user="", token="", stream="", timeout=4.0,
                 max_lines=200, max_bytes=100_000, transport=None):
        self._base_url = (base_url or "").rstrip("/")
        self._headers = basic_or_bearer_auth(user, token)
        self._stream = stream or "default"
        self._timeout = timeout
        self._max_lines = max_lines
        self._max_bytes = max_bytes
        self._transport = transport or request_json

    def query(self, host, unit=None, window_s=900):
        if not self._base_url:
            return []
        try:
            return self._query(host, unit, window_s)
        except Exception as e:
            log.debug("openobserve log query failed: %r", e)
            return []

    def _query(self, host, unit, window_s):
        now_us = int(time.time() * 1_000_000)
        start_us = now_us - int(max(0, window_s) * 1_000_000)
        clauses = []
        if host:
            clauses.append(f"str_match_ignore_case(log, '{_escape_sql(host)}')")
        if unit:
            clauses.append(f"str_match_ignore_case(log, '{_escape_sql(unit)}')")
        where = f" WHERE {' OR '.join(clauses)}" if clauses else ""
        sql = f'SELECT * FROM "{self._stream}"{where} ORDER BY _timestamp DESC'
        payload = {
            "query": {
                "sql": sql,
                "start_time": start_us,
                "end_time": now_us,
                "from": 0,
                "size": self._max_lines,
            },
        }
        url = f"{self._base_url}/_search"
        data = self._transport("POST", url, headers=self._headers, payload=payload,
                                timeout=self._timeout, max_bytes=2_000_000)
        hits = (data or {}).get("hits") or []
        # OpenObserve returns newest-first (ORDER BY _timestamp DESC above);
        # the LogClient contract wants newest-LAST.
        newest_first = _select_newest(hits, self._max_lines, self._max_bytes)
        return list(reversed(newest_first))


class LokiClient:
    """Queries Loki's `query_range` API via HTTP GET.

    Builds a best-effort LogQL stream selector `{<label>=~".*<host>.*"}`
    (label name configurable, default `host`) and narrows further with a
    `|= "<unit>"` line filter when a unit is given. The exact label schema
    is deployment-specific -- this is a reasonable generic default, not a
    guarantee of an exact match against any particular Loki setup."""

    def __init__(self, base_url, user="", token="", label="host", timeout=4.0,
                 max_lines=200, max_bytes=100_000, transport=None):
        self._base_url = (base_url or "").rstrip("/")
        self._headers = basic_or_bearer_auth(user, token)
        self._label = label or "host"
        self._timeout = timeout
        self._max_lines = max_lines
        self._max_bytes = max_bytes
        self._transport = transport or request_json

    def query(self, host, unit=None, window_s=900):
        if not self._base_url or not host:
            return []
        try:
            return self._query(host, unit, window_s)
        except Exception as e:
            log.debug("loki log query failed: %r", e)
            return []

    def _query(self, host, unit, window_s):
        now_ns = int(time.time() * 1_000_000_000)
        start_ns = now_ns - int(max(0, window_s) * 1_000_000_000)
        logql = f'{{{self._label}=~".*{_escape_logql(host)}.*"}}'
        if unit:
            logql += f' |= "{_escape_logql(unit)}"'
        query_string = urllib.parse.urlencode({
            "query": logql,
            "start": str(start_ns),
            "end": str(now_ns),
            "limit": str(self._max_lines),
            "direction": "backward",
        })
        url = f"{self._base_url}/loki/api/v1/query_range?{query_string}"
        data = self._transport("GET", url, headers=self._headers, payload=None,
                                timeout=self._timeout, max_bytes=2_000_000)
        results = ((data or {}).get("data") or {}).get("result") or []
        entries = []
        for stream in results:
            for pair in stream.get("values") or []:
                if len(pair) != 2:
                    continue
                ts, line = pair
                try:
                    entries.append((int(ts), line))
                except (TypeError, ValueError):
                    continue
        entries.sort(key=lambda item: item[0], reverse=True)  # newest-first
        newest_first = _select_newest([line for _, line in entries], self._max_lines, self._max_bytes)
        return list(reversed(newest_first))  # newest-LAST, per the LogClient contract
