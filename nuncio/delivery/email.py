"""Email delivery adapter, stdlib only (`smtplib`/`email.message`).

`cfg`: `smtp_host`, `smtp_port`, `user`, `password`, `from_addr`, `to`
(comma-separated), `tls` (`starttls` (default) | `ssl` | `none`).

At-least-once, same as every other adapter: a timeout AFTER the SMTP server
has accepted the message (but before this call returns) can cause the
Retrying wrapper to treat it as a failure and resend -- accepted, not a bug.
"""
import smtplib
import ssl
from email.message import EmailMessage

from nuncio.delivery import DeliveryAdapter, register


def _default_smtp_factory(host, port, timeout, tls):
    context = ssl.create_default_context()
    if tls == "ssl":
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    smtp = smtplib.SMTP(host, port, timeout=timeout)
    if tls == "starttls":
        smtp.starttls(context=context)
    return smtp


@register
class Email(DeliveryAdapter):
    name = "email"

    def __init__(self, cfg=None, smtp_factory=None, timeout=15):
        cfg = cfg or {}
        self.smtp_host = cfg.get("smtp_host") or None
        self.smtp_port = int(cfg.get("smtp_port") or 587)
        self.user = cfg.get("user") or None
        self.password = cfg.get("password") or None
        self.from_addr = cfg.get("from_addr") or None
        to_raw = cfg.get("to") or ""
        self.to = [a.strip() for a in to_raw.split(",") if a.strip()]
        self.tls = (cfg.get("tls") or "starttls").strip().lower()
        self._smtp_factory = smtp_factory or _default_smtp_factory
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.smtp_host or not self.to:
            return False
        msg = EmailMessage()
        # Header-injection guard: strip CR/LF from the subject so an
        # attacker-controlled title can't smuggle extra headers (e.g. a
        # forged "Bcc:" line).
        safe_title = (title or "Nuncio alert").replace("\r", "").replace("\n", " ")
        msg["Subject"] = safe_title
        if self.from_addr:
            msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to)
        msg.set_content(body or "")
        html = kw.get("html")
        if html:
            msg.add_alternative(html, subtype="html")
        try:
            smtp = self._smtp_factory(self.smtp_host, self.smtp_port, self.timeout, self.tls)
            with smtp:
                if self.user and self.password:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
            return True
        except Exception:
            return False
