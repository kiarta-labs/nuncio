"""Delivery-adapter ring — the output side of Nuncio's narrow waist.

Adapters send an already-rendered plain-markdown message to one notification
channel. The core never imports an adapter module directly; `nuncio/config.py`
(composition root) is the only place adapters are looked up, constructed with
their env-derived config dict, wrapped in bounded retry, and (if more than one
channel is configured) fanned out.

Built-in adapters self-register on import via the explicit list at the bottom
of this file (transparent beats clever — same convention as nuncio/sources/).
"""
import urllib.parse

_REGISTRY = {}  # name -> class (NOT an instance — construction needs per-adapter cfg)


def require_http_url(url):
    """Reject any URL whose scheme isn't http/https -- same allowlist
    clients/http.py already enforces on the ingest/collector side, applied
    here for consistency on the delivery side. Operator-config-only exposure
    (a misconfigured file://, ftp://, etc. adapter URL), but a transport
    helper should still fail closed before ever handing an unexpected scheme
    to urlopen."""
    scheme = urllib.parse.urlsplit(str(url or "")).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"unsupported URL scheme {scheme!r} (http/https only)")


def register(adapter_cls):
    """Class decorator: register an adapter CLASS by its `.name`. Unlike
    sources (instantiated eagerly with no args), delivery adapters need a
    config dict at construction time, so the registry holds classes and
    `build()` instantiates on demand."""
    _REGISTRY[adapter_cls.name] = adapter_cls
    return adapter_cls


def get(name):
    return _REGISTRY.get(name)


def names():
    return sorted(_REGISTRY)


def build(name, cfg):
    cls = _REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"unknown delivery adapter: {name!r}")
    return cls(cfg)


class DeliveryAdapter:
    """The adapter interface."""
    name = None
    # Durable = a real notification channel whose success means the alert
    # actually reached someone. False marks a diagnostic-only sink (e.g.
    # `stdout`) whose "success" must never, by itself, mark an alert
    # delivered -- see Fanout.send/Dispatch.send's durable-aware success
    # rule below. Default True: every adapter is durable unless it opts out.
    durable = True

    def __init__(self, cfg: dict):
        raise NotImplementedError

    def send(self, title: str, body: str, severity: str = "unknown", **kw) -> bool:
        """True = accepted by the channel. False/raise = failed (the caller —
        Retrying — retries per policy). MUST detect the channel's own
        'accepted but delivered to nobody' modes and return False (the
        Apprise-204 lesson, see delivery/apprise.py). `**kw` carries optional
        richer context (headline/summary/host/service/html) -- every
        built-in adapter accepts and ignores it except where noted in its own
        module."""
        raise NotImplementedError


BRIEF, FULL = "brief", "full"
DEFAULT_VERBOSITY = {
    "ntfy": BRIEF, "telegram": BRIEF, "apprise": BRIEF,
    "email": FULL, "slack": FULL, "webhook": FULL, "stdout": FULL,
}

_BRIEF_BODY_CAP = 120


class Dispatch:
    """Renders one `Envelope` per configured channel, in that channel's
    verbosity (`brief` or `full`), and sends it. Replaces the old
    title/body-only bridge -- this is the ONLY thing the engine calls.

    `channels` is `[(name, adapter, verbosity), ...]` where `adapter` is
    normally a `Retrying`-wrapped `DeliveryAdapter`. `send()` NEVER raises
    (the whole body is wrapped); it returns True if ANY channel accepted the
    message, mirroring `Fanout`'s any-success policy."""

    def __init__(self, channels, on_failure=None):
        self.channels = list(channels)  # [(name, adapter, verbosity), ...]
        self._on_failure = on_failure

    def has_verbosity(self, verbosity) -> bool:
        return any(v == verbosity for _n, _a, v in self.channels)

    def send_full(self, envelope) -> bool:
        return self.send(envelope, only=FULL)

    def send_brief(self, envelope) -> bool:
        return self.send(envelope, only=BRIEF)

    def _render(self, envelope, verbosity):
        if verbosity == BRIEF:
            title = envelope.headline
            summary = envelope.summary or ""
            if envelope.marker:
                marker_line, _, rest = envelope.detail.partition("\n")
                truncated = _truncate_brief(rest.strip() or summary)
                body = marker_line + "\n" + truncated
            else:
                body = _truncate_brief(summary)
            return title, body
        # full
        return envelope.headline, envelope.detail

    def send(self, envelope, only=None) -> bool:
        try:
            considered = [(n, a, v) for n, a, v in self.channels
                          if only is None or v == only]
            # A non-durable diagnostic sink (e.g. stdout) always "succeeding"
            # must never mask a real durable channel's failure. If any
            # considered channel is durable, the overall result is True only
            # when a DURABLE channel actually succeeded; if every considered
            # channel is non-durable (e.g. the stdout-only zero-config
            # default), any success counts -- see DeliveryAdapter.durable.
            any_durable = any(getattr(a, "durable", True) for _n, a, _v in considered)
            ok = False
            durable_ok = False
            for name, adapter, verbosity in considered:
                sent = False
                try:
                    title, body = self._render(envelope, verbosity)
                    sent = bool(adapter.send(
                        title, body, envelope.severity,
                        headline=envelope.headline, summary=envelope.summary,
                        host=envelope.host, service=envelope.service,
                        html=envelope.detail_html,
                    ))
                except Exception:
                    sent = False
                if sent:
                    ok = True
                    if getattr(adapter, "durable", True):
                        durable_ok = True
                elif self._on_failure:
                    try:
                        self._on_failure(name)
                    except Exception:
                        pass
            return durable_ok if any_durable else ok
        except Exception:
            return False


def _truncate_brief(text, limit=_BRIEF_BODY_CAP):
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


class Fanout:
    """Sends via every configured channel; `NUNCIO_DELIVERY=a,b` builds one of
    these. `send()` returns True if ANY channel accepted (never-lose favors
    any-success); per-channel failures are reported via `on_failure(name)` for
    metrics/transparency."""

    def __init__(self, adapters, on_failure=None):
        self.adapters = list(adapters)  # [(name, adapter), ...]
        self._on_failure = on_failure

    @property
    def name(self):
        return "fanout(" + ",".join(n for n, _ in self.adapters) + ")"

    def send(self, title, body, severity="unknown", **kw):
        # See Dispatch.send's durable-aware success rule: a non-durable
        # diagnostic sink (e.g. stdout) succeeding must never mask a real
        # durable channel's failure.
        any_durable = any(getattr(a, "durable", True) for _n, a in self.adapters)
        ok = False
        durable_ok = False
        for chan_name, adapter in self.adapters:
            sent = False
            try:
                sent = adapter.send(title, body, severity, **kw)
            except Exception:
                sent = False
            if sent:
                ok = True
                if getattr(adapter, "durable", True):
                    durable_ok = True
            elif self._on_failure:
                try:
                    self._on_failure(chan_name)
                except Exception:
                    pass
        return durable_ok if any_durable else ok


# Explicit built-in registrations.
from nuncio.delivery import apprise  # noqa: E402,F401
from nuncio.delivery import ntfy  # noqa: E402,F401
from nuncio.delivery import telegram  # noqa: E402,F401
from nuncio.delivery import slack  # noqa: E402,F401
from nuncio.delivery import webhook  # noqa: E402,F401
from nuncio.delivery import stdout  # noqa: E402,F401
from nuncio.delivery import email  # noqa: E402,F401
from nuncio.delivery.retrying import Retrying  # noqa: E402,F401
