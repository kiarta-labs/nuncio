#!/usr/bin/env python3
"""CheckMK custom notification -> Nuncio.

Forwards a CheckMK notification to an Nuncio instance for enrichment, and falls
back to delivering the raw alert straight to an Apprise gateway if Nuncio is
unreachable -- so an Nuncio outage never drops a notification. CheckMK RAW has
no notification spooling of its own, so this in-plugin fallback is what makes
routing notifications through Nuncio safe.

Install (the notifications directory is auto-scanned by CheckMK):

    cp notify_nuncio.py \
       /omd/sites/<site>/local/share/check_mk/notifications/notify_nuncio
    chmod +x /omd/sites/<site>/local/share/check_mk/notifications/notify_nuncio

Then create a notification rule (Setup > Notifications) using the method
"notify_nuncio" with these parameters:

    Parameter 1  Nuncio base URL         (default: http://nuncio:8095)
    Parameter 2  Nuncio ingest token     (optional; sent as X-Auth-Token)
    Parameter 3  Apprise fallback URL   (optional but recommended; the raw
                                         alert is delivered here if Nuncio is
                                         unreachable, e.g.
                                         http://apprise:8000/notify/checkmk)

It reads the standard NOTIFY_* environment variables CheckMK passes in and
forwards all of them to Nuncio as a JSON object. Nuncio's "checkmk" source
adapter derives a stable idempotency key and a structured alert from them.

This module runs inside CheckMK's own bundled Python and therefore cannot
import the `nuncio` package -- it carries small self-contained copies of the
unexpanded-macro scrub and severity-emoji mapping that also live in
`nuncio/sources/checkmk.py` and `nuncio/envelope.py`, so the fallback path
degrades the same way the primary (Nuncio-enriched) path does.

Local spool: CheckMK RAW has no notification spool of its own -- if a
notification can't be handed off (to Nuncio, or to Apprise as a fallback),
CheckMK will NOT retry it, and it is gone. So when BOTH the Nuncio handoff
and the Apprise fallback fail in one run, the alert is written to a small
on-disk spool (`spool_write`) instead of being dropped; every subsequent
invocation of this plugin first tries to drain that spool (`spool_drain`)
before handling its own new notification, so a later, healthy run finishes
the delivery. This is what makes it safe to route notifications through
Nuncio even though CheckMK RAW itself gives no delivery guarantee.
"""
import json
import os
import re
import sys
import time
import urllib.request


def env(key, default=""):
    return os.environ.get(key, default)


def post(url, payload, headers, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode()


# CheckMK occasionally leaves a macro unexpanded (e.g. a HOST notification
# arriving with NOTIFY_SERVICEDESC="$SERVICEDESC$" instead of the macro
# being omitted). Treat any NOTIFY_* value that is exactly "$SOME_MACRO$" as
# absent -- same rule as nuncio.sources.checkmk._clean.
_MACRO_RE = re.compile(r"^\$[A-Z0-9_]+\$$")


def _clean(value):
    """Return `value` unless it's an unexpanded CheckMK macro literal, in
    which case return "" (i.e. "field is absent")."""
    if isinstance(value, str) and _MACRO_RE.match(value):
        return ""
    return value


# state -> colored-emoji token. Mirrors nuncio.envelope's severity -> emoji
# map (kept as an independent copy since this module cannot import nuncio).
_STATE_EMOJI = {
    "CRITICAL": "❗", "CRIT": "❗", "DOWN": "❗",
    "WARNING": "🟡", "WARN": "🟡",
    "OK": "✅", "UP": "✅",
    "UNKNOWN": "❔", "UNREACHABLE": "❔",
}


def state_symbol(state):
    """Map a CheckMK state string to its colored-emoji token. Unknown/blank
    states default to "❔"."""
    return _STATE_EMOJI.get((state or "").upper(), "❔")


def is_service_notification(notification):
    """True if `notification` (a dict of NOTIFY_* values) describes a REAL
    service notification. A bare NOTIFY_WHAT=="SERVICE" is not sufficient by
    itself -- CheckMK has been observed sending NOTIFY_WHAT=="SERVICE" with a
    blank/unexpanded NOTIFY_SERVICEDESC, which used to be misclassified as a
    service notification. A literal unexpanded "$SERVICEDESC$" does not
    count as a real service either. This mirrors
    `nuncio.sources.checkmk._is_service` exactly -- plugin and adapter must
    never disagree on classification."""
    service = _clean(notification.get("NOTIFY_SERVICEDESC", ""))
    return bool(service)


def build_fallback(notification):
    """Build the Apprise-fallback (title, body, kind) from a dict of
    NOTIFY_* values -- the same dict forwarded to Nuncio. Severity-led,
    terse: "{emoji} {entity} — {output}", consistent with the enriched
    delivery path's format (nuncio/envelope.py build_headline /
    nuncio/sources/checkmk.py raw_text)."""
    host = notification.get("NOTIFY_HOSTNAME", "?")
    ntype = notification.get("NOTIFY_NOTIFICATIONTYPE", "PROBLEM")

    if is_service_notification(notification):
        service = _clean(notification.get("NOTIFY_SERVICEDESC", "?")) or "?"
        state = _clean(notification.get("NOTIFY_SERVICESTATE", "?")) or "?"
        output = _clean(notification.get("NOTIFY_SERVICEOUTPUT", "")) or ""
        entity = "{} / {}".format(host, service)
    else:
        state = _clean(notification.get("NOTIFY_HOSTSTATE", "?")) or "?"
        output = _clean(notification.get("NOTIFY_HOSTOUTPUT", "")) or ""
        entity = host

    emoji = state_symbol(state)
    title = "{} {} — {}".format(emoji, entity, output)

    upper = state.upper()
    if ntype.startswith("RECOVERY") or upper in ("UP", "OK"):
        kind = "success"
    elif upper in ("WARN", "WARNING"):
        kind = "warning"
    elif upper in ("DOWN", "CRIT", "CRITICAL", "UNREACH", "UNREACHABLE"):
        kind = "failure"
    else:
        kind = "info"

    body = "{}: {}".format(ntype, output).strip()
    return title, body, kind


# --- local spool (see module docstring) --------------------------------

_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def spool_dir():
    """Resolve the spool directory and create it (best-effort).

    Precedence: `NUNCIO_PLUGIN_SPOOL_DIR` env var (testability / operator
    override) > `$OMD_ROOT/var/tmp/nuncio_spool` (CheckMK site tmp, durable
    across plugin runs) > `/var/tmp/nuncio_spool` (no OMD_ROOT known).
    Returns None if the directory can't be created, so callers can fall back
    to the pre-spool behavior instead of crashing."""
    override = env("NUNCIO_PLUGIN_SPOOL_DIR")
    if override:
        base = override
    else:
        omd_root = env("OMD_ROOT")
        base = (os.path.join(omd_root, "var", "tmp", "nuncio_spool") if omd_root
                else "/var/tmp/nuncio_spool")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        return None
    return base


def _spool_key_hint(notification):
    """A short, filesystem-safe discriminator for the spool filename, built
    from the same fields nuncio.sources.checkmk.derive_key uses -- purely
    cosmetic (uniqueness comes from pid+time below), but keeps spooled files
    identifiable at a glance during an incident."""
    host = _clean(notification.get("NOTIFY_HOSTNAME", "")) or "unknown"
    if is_service_notification(notification):
        extra = _clean(notification.get("NOTIFY_SERVICEDESC", "")) or ""
        pid = _clean(notification.get("NOTIFY_SERVICEPROBLEMID", "")) or "0"
    else:
        extra = ""
        pid = _clean(notification.get("NOTIFY_HOSTPROBLEMID", "")) or "0"
    num = _clean(notification.get("NOTIFY_NOTIFICATIONNUMBER", "")) or "1"
    hint = "-".join(part for part in (host, extra, pid, num) if part)
    return _SLUG_RE.sub("_", hint) or "alert"


def spool_write(directory, record):
    """Atomically write `record` (JSON-serializable) as a new file in
    `directory`. Returns True on success, False on any failure (directory
    unwritable, disk full, ...) -- callers must treat False as "still lost"
    and act accordingly (e.g. return a non-zero exit code)."""
    if not directory:
        return False
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        return False
    key_hint = _SLUG_RE.sub("_", str(record.get("key_hint", "alert")))
    # pid + high-resolution time -> unique even for two notifications
    # spooled in the same process in the same millisecond.
    fname = "{}-{}-{}.json".format(key_hint, os.getpid(), int(time.time() * 1e6))
    final_path = os.path.join(directory, fname)
    tmp_path = final_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(record, f)
        os.rename(tmp_path, final_path)  # atomic on both POSIX and Windows NTFS
        return True
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


def spool_list(directory, limit=None):
    """Sorted (oldest-filename-first) list of spooled alert file paths in
    `directory`, capped at `limit` if given. Returns [] if the directory
    doesn't exist or can't be read."""
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError:
        return []
    if limit is not None:
        names = names[:limit]
    return [os.path.join(directory, n) for n in names]


def spool_drain(directory, nuncio_url, ingest_token, fallback_url, timeout=10, limit=20):
    """Attempt to redeliver every spooled alert in `directory` (bounded by
    `limit` so a single notify invocation can't hang draining a large
    backlog): re-POST to Nuncio, else to Apprise. Delete the file on a 2xx
    from either; leave it untouched on failure so the next drain retries it.
    Returns the count successfully redelivered."""
    drained = 0
    for path in spool_list(directory, limit=limit):
        try:
            with open(path, encoding="utf-8") as f:
                record = json.load(f)
        except (OSError, ValueError):
            # Corrupt/unreadable spool file: nothing more can be done with
            # it, and leaving it in place would jam every future drain.
            try:
                os.remove(path)
            except OSError:
                pass
            continue

        delivered = False
        notification = record.get("notification")
        if notification:
            headers = {"Content-Type": "application/json"}
            if ingest_token:
                headers["X-Auth-Token"] = ingest_token
            try:
                code = post(nuncio_url + "/ingest/checkmk", notification, headers, timeout)
                delivered = 200 <= code < 300
            except Exception:  # noqa: BLE001 -- fall through to the Apprise leg
                delivered = False

        if not delivered and fallback_url:
            try:
                code = post(fallback_url,
                             {"title": record.get("title", ""), "body": record.get("body", ""),
                              "type": record.get("kind", "info")},
                             {"Content-Type": "application/json"}, timeout)
                delivered = 200 <= code < 300
            except Exception:  # noqa: BLE001
                delivered = False

        if delivered:
            try:
                os.remove(path)
            except OSError:
                pass
            drained += 1
    return drained


def main():
    nuncio_url = (env("NOTIFY_PARAMETER_1") or "http://nuncio:8095").rstrip("/")
    ingest_token = env("NOTIFY_PARAMETER_2")
    fallback_url = env("NOTIFY_PARAMETER_3")

    if not fallback_url:
        # Missing safety net: make this loudly visible in CheckMK's
        # notification log rather than silently relying on the spool alone.
        print("WARNING: no Apprise fallback URL configured (Parameter 3) -- "
              "an Nuncio outage has only the local spool as a safety net.")

    # Drain any alerts stuck from a previous run FIRST, bounded so this
    # invocation can't hang -- best-effort; a drain failure must not block
    # handling the current notification.
    directory = spool_dir()
    if directory:
        try:
            drained = spool_drain(directory, nuncio_url, ingest_token, fallback_url)
            if drained:
                print("Spool drain: redelivered {} alert(s)".format(drained))
        except Exception as exc:  # noqa: BLE001 -- draining must never block delivery
            print("Spool drain failed: {}".format(exc))

    # Forward every NOTIFY_* variable verbatim; the adapter reads the subset
    # it needs and keeps the rest available as raw context.
    notification = {k: v for k, v in os.environ.items() if k.startswith("NOTIFY_")}

    # --- Primary path: hand the notification to Nuncio ---------------------
    headers = {"Content-Type": "application/json"}
    if ingest_token:
        headers["X-Auth-Token"] = ingest_token

    try:
        code = post(nuncio_url + "/ingest/checkmk", notification, headers, 10)
        if 200 <= code < 300:
            print("Nuncio ingest -> HTTP {}".format(code))
            return 0
        raise RuntimeError("Nuncio returned HTTP {}".format(code))
    except Exception as exc:  # noqa: BLE001 -- any failure must trigger the fallback
        print("Nuncio ingest failed: {}".format(exc))

    # --- Fallback path: deliver the raw alert straight to Apprise ---------
    # build_fallback() is wrapped too so a raise there (e.g. a malformed
    # notification) still reaches the spool path below instead of escaping
    # and losing the alert.
    try:
        title, body, kind = build_fallback(notification)
    except Exception as exc:  # noqa: BLE001
        print("build_fallback failed: {}".format(exc))
        title, body, kind = ("Nuncio/CheckMK notification (unrenderable)",
                              "build_fallback failed while handling a delivery failure",
                              "failure")

    if fallback_url:
        try:
            code = post(fallback_url, {"title": title, "body": body, "type": kind},
                        {"Content-Type": "application/json"}, 10)
            print("Apprise fallback -> HTTP {}".format(code))
            if 200 <= code < 300:
                return 0
        except Exception as exc:  # noqa: BLE001
            print("Apprise fallback failed: {}".format(exc))

    # --- Both Nuncio and Apprise failed (or there is no fallback URL): spool
    # the alert for retry by a later invocation instead of losing it. -------
    record = {
        "key_hint": _spool_key_hint(notification),
        "notification": notification,
        "title": title, "body": body, "kind": kind,
    }
    if directory and spool_write(directory, record):
        print("Spooled alert for later retry (both Nuncio and Apprise unavailable)")
        return 0

    print("Spool write failed -- alert could not be delivered or saved")
    return 1


if __name__ == "__main__":
    sys.exit(main())
