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
