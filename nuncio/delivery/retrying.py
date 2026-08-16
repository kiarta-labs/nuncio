"""Generic bounded-retry wrapper so every delivery adapter gets bounded
exponential-backoff retry for free, and no individual adapter reimplements
it. This is the ONLY component permitted to retry. Transport failures and
non-boolean-True returns both count as a failed attempt; returns True on
success, False once retries are exhausted (the caller — the engine, via the
composition root — then leaves the alert queued on disk for the maintenance
safety net).
"""
import logging
import time

from nuncio.delivery import SendTimeout

log = logging.getLogger("nuncio.delivery.retrying")


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
        adapter_cls = getattr(self.adapter, "__class__", self.adapter).__name__
        for i in range(attempts):
            try:
                ok = self.adapter.send(title, body, severity, **kw)
            except SendTimeout:
                # The send may have already reached the far end (the POST is
                # non-idempotent) -- retrying risks a duplicate push, so give
                # up on this key now rather than retry like a transient
                # connection failure. See SendTimeout's docstring.
                log.warning(
                    "delivery timed out (SendTimeout) without confirmation for %r "
                    "adapter=%r attempt=%d/%d",
                    self.name, adapter_cls, i + 1, attempts,
                )
                return False
            except Exception as exc:
                log.debug(
                    "delivery attempt failed for %r adapter=%r attempt=%d/%d error=%s:%s",
                    self.name, adapter_cls, i + 1, attempts,
                    exc.__class__.__name__, str(exc)[:120],
                )  # treated as a failed attempt; retry below
            else:
                if ok:
                    return True
                log.debug(
                    "delivery returned failure for %r adapter=%r attempt=%d/%d",
                    self.name, adapter_cls, i + 1, attempts,
                )  # treated as a failed attempt; retry below
            if i < attempts - 1:
                self._sleep(self.backoff * (2 ** i))
        log.warning(
            "delivery exhausted after %d attempts for %r adapter=%r",
            attempts, self.name, adapter_cls,
        )
        return False
