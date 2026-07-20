"""Collector-client protocols — the I/O layer the collectors
(`nuncio/collectors.py`, core logic, NOT pluggable) call through.

Two layers, and keeping them distinct is the design: collectors are the
bounded, never-raise, category-selected functions (core); clients are the
adapter ring that supplies their read-only data. The core never imports a
concrete client implementation; `nuncio/config.py` (composition root) selects
one per protocol from `NUNCIO_LOGS`/`NUNCIO_CONTAINERS`/`NUNCIO_METRICS` and
wires it into the gatherer.

Hard rule, stated here as a contract every implementation MUST honor: set a
socket timeout strictly below the gather timeout passed to the client's
constructor (`NUNCIO_GATHER_TIMEOUT_S` minus 1s, computed by config.py). A
client that can hang forever violates this interface — the gatherer's own
bounding only protects the WORKER thread, not the leaked I/O call underneath
it.
"""


class LogClient:
    """Feeds collect_recent_logs + collect_kernel."""

    def query(self, host, unit, window_s):
        """Return raw log lines, newest-LAST. [] = none found. May raise —
        the calling collector degrades to a "context unavailable" marker on
        any exception, so a client is free to just let errors propagate."""
        raise NotImplementedError


class ContainerClient:
    """Feeds collect_container_state."""

    def inspect(self, name):
        """Return {"status","restart_count","exit_code","started_at",
        "logs":[...]}, or None if the container/name wasn't found. May
        raise — the collector degrades."""
        raise NotImplementedError


class MetricsClient:
    """Feeds collect_metrics."""

    def query(self, host, service):
        """Return human-readable 'metric = value' summary lines. May raise —
        the collector degrades."""
        raise NotImplementedError


class CollectorHealth:
    """A small process-lifetime cache of collector health -- last
    success/failure per client, recorded as calls happen. Deliberately NOT
    persisted: only the per-alert stats need to survive a restart; a fresh
    process starts with a clean, honestly-"unknown yet" health state rather
    than stale data."""

    def __init__(self):
        self._state = {}  # name -> {"ok": bool, "last_error": str|None, "fail_count": int}

    def wrap(self, name, fn):
        """Return a callable identical to `fn` except every call's outcome
        (success/exception) updates this tracker's state for `name`. The
        wrapped call still raises/returns exactly as `fn` would -- this is
        purely an observer, never changes collector behavior."""

        def wrapped(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                self._record(name, False, repr(e))
                raise
            self._record(name, True, None)
            return result

        return wrapped

    def _record(self, name, ok, error):
        st = self._state.setdefault(name, {"ok": True, "last_error": None, "fail_count": 0})
        st["ok"] = ok
        if not ok:
            st["last_error"] = error
            st["fail_count"] += 1

    def snapshot(self):
        """{name: {"ok", "last_error", "fail_count"}} -- read by the
        dashboard's /stats.json `collectors` block."""
        return {name: dict(st) for name, st in self._state.items()}


class NullClient(LogClient, ContainerClient, MetricsClient):
    """The zero-config default: implements all three protocols as no-ops so
    Nuncio runs pure Level A with nothing wired. Every collector fed by a
    NullClient degrades to its "(none)" / "(container not found)" text —
    never an error, never a hang."""

    def query(self, host, unit=None, window_s=None):
        return []

    def inspect(self, name):
        return None
