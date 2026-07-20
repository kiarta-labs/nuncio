"""Generic bounded-retry wrapper so every delivery adapter gets bounded
exponential-backoff retry for free, and no individual adapter reimplements
it. This is the ONLY component permitted to retry. Transport failures and
non-boolean-True returns both count as a failed attempt; returns True on
success, False once retries are exhausted (the caller — the engine, via the
composition root — then leaves the alert queued on disk for the maintenance
safety net).
"""
import time


class Retrying:
    def __init__(self, adapter, retries=3, sleep=time.sleep, backoff=0.5):
        self.adapter = adapter
        self.retries = retries
        self._sleep = sleep
        self.backoff = backoff

    @property
    def name(self):
        return getattr(self.adapter, "name", "unknown")

    @property
    def durable(self):
        # Dispatch/Fanout read `.durable` off whatever they hold in
        # `channels`/`adapters` -- and config.build_delivery always wraps
        # every adapter in Retrying before handing it over. Without this
        # proxy, a non-durable sink (e.g. Stdout.durable=False) would read
        # back as durable=True (the getattr default), silently defeating
        # the durable-aware success rule those callers depend on.
        return getattr(self.adapter, "durable", True)

    def send(self, title, body, severity="unknown", **kw):
        attempts = self.retries + 1
        for i in range(attempts):
            try:
                if self.adapter.send(title, body, severity, **kw):
                    return True
            except Exception:
                pass  # treated as a failed attempt; retry below
            if i < attempts - 1:
                self._sleep(self.backoff * (2 ** i))
        return False
