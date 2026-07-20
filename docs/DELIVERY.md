# Writing a delivery adapter

A delivery adapter sends an already-rendered title/body to one notification channel. Nuncio ships adapters for Apprise, ntfy, Telegram, Slack, a generic webhook, email, and stdout.

## The interface

```python
from nuncio.delivery import DeliveryAdapter, register

@register
class MyChannel(DeliveryAdapter):
    name = "mychannel"  # used in NUNCIO_DELIVERY=mychannel

    def __init__(self, cfg: dict):
        self.url = cfg.get("url")

    def send(self, title: str, body: str, severity: str = "unknown", **kw) -> bool:
        """Return True only if the channel actually accepted the message
        for delivery. Return False (don't raise) on any failure -- the
        caller (Retrying) handles retry, and a raised exception is treated
        the same as a False return, but returning False directly is
        clearer.

        `**kw` carries optional richer context taken from the alert's
        Envelope: `headline`, `summary`, `host`, `service`, `html`. Most
        adapters ignore it entirely; the webhook adapter exposes
        headline/summary/host/service as extra template placeholders, and
        the email adapter attaches `html` as a multipart/alternative body
        when present. Always accept and ignore `**kw` even if you don't use
        it -- this is a widened, backward-compatible signature.

        Watch for a channel's own "accepted but delivered to nobody" modes.
        Apprise, for example, returns HTTP 204 when the configured
        destination key has no actual target configured -- trusting that as
        success would silently black-hole every alert, so the Apprise
        adapter treats 204 as failure.
        """
        ...
```

## Rendering: brief vs. full

The engine builds one `Envelope` per alert (`nuncio/envelope.py`, `nuncio/render.py`'s `build_envelope`) carrying a terse `headline`, a one-line `summary`, and the complete `detail` (enrichment + verbatim embedded raw alert). `nuncio/delivery/__init__.py`'s `Dispatch` renders that envelope differently per channel depending on the channel's verbosity:

- **`brief`** (default for `ntfy`, `telegram`, `apprise`) — `title=headline`, `body=summary` truncated to ≤120 chars.
- **`full`** (default for `email`, `slack`, `webhook`, `stdout`) — `title=headline`, `body=detail` (the complete text).

Override any adapter's verbosity with `NUNCIO_DELIVERY_VERBOSITY` (a JSON object of adapter name -> `"brief"`/`"full"`; see `docs/CONFIGURATION.md`). A degraded/raw-fallback alert's body always starts with the `[enrichment unavailable]` marker line, in both brief and full rendering, and that line is never truncated -- only the summary/detail text after it is.

## Wiring it in

Every configured adapter is automatically wrapped in bounded exponential-backoff retry (`nuncio/delivery/retrying.py`) — don't implement your own retry loop inside an adapter. `NUNCIO_DELIVERY=a,b,c` builds a `Dispatch` of `[(name, Retrying(adapter), verbosity), ...]`; `Dispatch.send(envelope)` reports success if *any* channel accepted the message (favoring never losing an alert over any single channel's reliability). The older `Fanout` class (title/body/severity only, no verbosity split) is kept for backward compatibility but is no longer built by `nuncio/config.py`.

Built-in adapters register themselves on import inside `nuncio/delivery/__init__.py`. A third-party adapter registers the same way in its own module; wire it up by importing that module from wherever you call `nuncio.config.build_app()` (there is currently no `NUNCIO_EXTRA_DELIVERY` env hook analogous to `NUNCIO_EXTRA_SOURCES` — if you need one, it's a small addition to `nuncio/config.py`'s `_delivery_cfg_by_name`/`build_delivery`). Also add your adapter's name to `nuncio.delivery.DEFAULT_VERBOSITY` if its default shouldn't be `full`.

## Config dict

Whatever config keys your adapter needs, thread them through `nuncio/config.py`'s `_delivery_cfg_by_name` (or your own composition root if you're not using `build_app()` directly), keyed by your adapter's `name`.

## Testing your adapter

Inject a fake transport instead of hitting the network — see `tests/test_delivery_*.py` for the pattern used by the built-in adapters (each one accepts an optional `transport` callable in its constructor for exactly this purpose). The email adapter instead accepts a `smtp_factory` (see `tests/test_delivery_email.py`).

## Email adapter

`NUNCIO_DELIVERY=email` sends via plain `smtplib`/`email.message.EmailMessage`, stdlib only: `NUNCIO_EMAIL_SMTP_HOST`, `NUNCIO_EMAIL_SMTP_PORT` (587), `NUNCIO_EMAIL_USER`/`NUNCIO_EMAIL_PASSWORD` (login skipped if either is empty), `NUNCIO_EMAIL_FROM`, `NUNCIO_EMAIL_TO` (comma-separated), `NUNCIO_EMAIL_TLS` (`starttls` default, `ssl`, or `none`). The subject line has `\r`/`\n` stripped as a header-injection guard. When the envelope carries an HTML rendering it's attached as a `multipart/alternative` part alongside the plain-text body.

This is at-least-once delivery: if the SMTP server accepts the message but the connection then times out before this call returns, the `Retrying` wrapper sees a failure and resends — a rare duplicate is accepted as the price of never silently losing an alert.

**Alternative:** if you already run an [Apprise](https://github.com/caronc/apprise) gateway (Nuncio's `apprise` adapter talks to one), a `mailto://` Apprise URL gets you email delivery with zero SMTP config in Nuncio itself — use the `email` adapter above only for a bare install with no Apprise gateway in front of it.
