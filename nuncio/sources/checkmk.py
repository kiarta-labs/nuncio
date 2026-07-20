"""CheckMK notification source adapter.

CheckMK passes a notification to a plugin as NOTIFY_* environment variables.
The bundled plugin (`integrations/checkmk/notify_nuncio.py`)
forwards them to Nuncio as JSON; this module turns that native payload into a
stable idempotency key + a structured alert + the verbatim raw text.

Idempotency key = source-prefixed host/service/problem-id/notification-type/
notification-number. The problem-id (NOTIFY_SERVICEPROBLEMID or
NOTIFY_HOSTPROBLEMID) is stable for the life of one problem, and including the
notification type keeps PROBLEM and RECOVERY distinct; the notification
number distinguishes a legitimate periodic re-notification/escalation of the
SAME problem (which must get through) from an Nuncio-restart replay of the
exact same notification (same number -> correctly deduped).

If CheckMK ever omits the problem-id or notification-number macro, deriving
the key from a hardcoded constant would collapse distinct incidents onto one
key -- and since `store.persist` is INSERT OR IGNORE, that means silently
dropping every incident after the first (true loss). `_discriminator()`
degrades instead to a CheckMK-provided timestamp (NOTIFY_MICROTIME /
NOTIFY_SHORTDATETIME / NOTIFY_LONGDATETIME, in that preference order): a
replay of the same notification still dedupes (same timestamp), but two
distinct incidents no longer collide (different timestamps). "Never lose"
outranks "never duplicate", so an absent macro degrades toward at-least-once,
never toward collision.
"""
import re

from nuncio.envelope import severity_symbol
from nuncio.model import ParsedAlert, normalize_severity
from nuncio.sources import SourceAdapter, register

# CheckMK notification plugins sometimes run with a macro that never got
# expanded (observed in production: a HOST notification arriving with
# NOTIFY_SERVICEDESC="$SERVICEDESC$" instead of being omitted). Any
# NOTIFY_* value that is exactly "$SOME_MACRO$" is not a real value -- it
# must be treated the same as the field being absent.
_UNEXPANDED_MACRO_RE = re.compile(r"^\$[A-Z0-9_]+\$$")


def _clean(value):
    """Return `value` unless it's an unexpanded CheckMK macro literal, in
    which case return None (i.e. "field is absent")."""
    if isinstance(value, str) and _UNEXPANDED_MACRO_RE.match(value):
        return None
    return value


def _get(notify, key, default=None):
    return _clean(notify.get(key, default))


def _is_service(notify):
    """True iff this notification describes a REAL service. A bare
    NOTIFY_WHAT=="SERVICE" is not sufficient by itself: CheckMK has been
    observed sending NOTIFY_WHAT=="SERVICE" with a blank/unexpanded
    NOTIFY_SERVICEDESC, which used to manufacture a garbage "-"/"-" service
    alert. Requiring a real SERVICEDESC makes that case fall to the host
    branch instead (host identity + host state), which is the correct,
    more-specific classification. Mirrored in the CheckMK plugin's
    `is_service_notification` (integrations/checkmk/notify_nuncio.py) --
    plugin and adapter must never disagree on classification."""
    return bool(_get(notify, "NOTIFY_SERVICEDESC"))


# Preference order for the stable-timestamp fallback used when a
# problem-id/notification-number macro is missing. Any of these being equal
# across two notifications means "the same CheckMK-side event" (safe to keep
# deduped); differing means "a different event" (must not collapse).
_TIME_FALLBACK_KEYS = ("NOTIFY_MICROTIME", "NOTIFY_SHORTDATETIME", "NOTIFY_LONGDATETIME")


def _time_discriminator(notify):
    """The best available stable substitute for a missing problem-id or
    notification-number: a CheckMK-provided timestamp for this notification.
    A replay of the exact same notification carries the same timestamp (still
    correctly deduped); two distinct incidents essentially never share one
    (correctly NOT deduped). Returns None if no time field is present at
    all, so the caller can fall back further."""
    for time_key in _TIME_FALLBACK_KEYS:
        value = _get(notify, time_key)
        if value:
            return value
    return None


def _discriminator(notify, key, default):
    """Idempotency-key component from `notify[key]` if present; otherwise a
    timestamp-based fallback; otherwise `default`.

    Why not just `default`: `key` (NOTIFY_SERVICEPROBLEMID/
    NOTIFY_HOSTPROBLEMID/NOTIFY_NOTIFICATIONNUMBER) is the ONLY thing that
    distinguishes two genuinely different incidents on the same host/service.
    If the macro is ever absent, collapsing straight to a hardcoded constant
    would make every such incident derive an IDENTICAL key -- and because
    `store.persist` is INSERT OR IGNORE, every incident after the first is
    silently dropped (true loss, not a harmless duplicate). Falling back to a
    timestamp instead degrades toward "maybe an extra key" (at-least-once)
    rather than "guaranteed collision" (loss) -- see module docstring."""
    value = _get(notify, key)
    if value:
        return value
    return _time_discriminator(notify) or default


def derive_key(notify, source="checkmk"):
    host = notify.get("NOTIFY_HOSTNAME", "-")
    ntype = notify.get("NOTIFY_NOTIFICATIONTYPE", "PROBLEM")
    if _is_service(notify):
        service = _get(notify, "NOTIFY_SERVICEDESC", "-") or "-"
        pid = _discriminator(notify, "NOTIFY_SERVICEPROBLEMID", "0")
    else:
        service = "-"
        pid = _discriminator(notify, "NOTIFY_HOSTPROBLEMID", "0")
    num = _discriminator(notify, "NOTIFY_NOTIFICATIONNUMBER", "1")
    # Source-prefixed so keys can never collide across sources.
    return f"{source}:{host}/{service}/{pid}/{ntype}/{num}"


_BACKSLASH_PLACEHOLDER = "\x00NUNCIO-BACKSLASH\x00"


def _unescape_literal_whitespace(value):
    """CheckMK's LONG(SERVICE|HOST)OUTPUT macros arrive with literal two-char
    "\\n"/"\\t" escape sequences (not real newlines/tabs) -- turn them into
    the real characters so multi-line plugin output actually renders as
    multiple lines.

    A real backslash in the plugin output (e.g. a Windows path like
    "D:\\network\\tools") arrives escaped as a literal two-char "\\\\"
    sequence. Naively replacing "\\n"/"\\t" first would consume the "n"/"t"
    right after such an escaped backslash and mangle the path (turning
    "D:\\network" into "D:" + a real newline + "etwork"). Protect real
    backslashes FIRST (swap "\\\\" for a placeholder unlikely to occur in
    plugin output), THEN unescape "\\n"/"\\t", THEN restore the placeholder
    back to a single literal backslash."""
    if not value:
        return value
    value = value.replace("\\\\", _BACKSLASH_PLACEHOLDER)
    value = value.replace("\\n", "\n").replace("\\t", "\t")
    return value.replace(_BACKSLASH_PLACEHOLDER, "\\")


def _extra_details(notify, is_service):
    key = "NOTIFY_LONGSERVICEOUTPUT" if is_service else "NOTIFY_LONGHOSTOUTPUT"
    value = _get(notify, key)
    return _unescape_literal_whitespace(value) if value else None


def _extra_perfdata(notify, is_service):
    key = "NOTIFY_SERVICEPERFDATA" if is_service else "NOTIFY_HOSTPERFDATA"
    return _get(notify, key)


def _extra_check_command(notify, is_service):
    key = "NOTIFY_SERVICECHECKCOMMAND" if is_service else "NOTIFY_HOSTCHECKCOMMAND"
    return _get(notify, key)


def _extra_event(notify):
    return _get(notify, "NOTIFY_NOTIFICATIONTYPE")


def _extra_ack(notify, is_service):
    if is_service:
        author = _get(notify, "NOTIFY_SERVICEACKAUTHOR")
        comment = _get(notify, "NOTIFY_SERVICEACKCOMMENT")
    else:
        author = _get(notify, "NOTIFY_HOSTACKAUTHOR")
        comment = _get(notify, "NOTIFY_HOSTACKCOMMENT")
    notif_comment = _get(notify, "NOTIFY_NOTIFICATIONCOMMENT")

    parts = []
    if author and comment:
        parts.append(f"{author}: {comment}")
    elif author:
        parts.append(author)
    elif comment:
        parts.append(comment)
    if notif_comment:
        parts.append(notif_comment)
    return "; ".join(parts) if parts else None


def _extra_downtime(notify, is_service):
    key = "NOTIFY_SERVICEDOWNTIME" if is_service else "NOTIFY_HOSTDOWNTIME"
    value = _get(notify, key)
    try:
        count = int(value)
    except (TypeError, ValueError):
        return None
    if count <= 0:
        return None
    return "in scheduled downtime" if count == 1 else f"in scheduled downtime ({count})"


def _extra_groups(notify, is_service):
    pieces = []
    if is_service:
        pieces.append(_get(notify, "NOTIFY_SERVICEGROUPNAMES"))
    pieces.append(_get(notify, "NOTIFY_HOSTGROUPNAMES"))
    pieces.append(_get(notify, "NOTIFY_HOSTTAGS"))
    pieces = [p for p in pieces if p]
    return "; ".join(pieces) if pieces else None


def _extra_address(notify):
    address = _get(notify, "NOTIFY_HOSTADDRESS")
    alias = _get(notify, "NOTIFY_HOSTALIAS")
    if address and alias:
        return f"{address} ({alias})"
    return address or alias or None


def _extra_recurrence(notify, is_service):
    pid_key = "NOTIFY_SERVICEPROBLEMID" if is_service else "NOTIFY_HOSTPROBLEMID"
    pid = _get(notify, pid_key)
    number = _get(notify, "NOTIFY_NOTIFICATIONNUMBER")
    try:
        num = int(number)
    except (TypeError, ValueError):
        return None
    if num <= 1:
        return None
    return f"notification #{num} of problem {pid}" if pid else f"notification #{num}"


def _populate_extras(notify, alert, is_service):
    """Populate Phase 0's canonical extra-field keys on `alert` from
    CheckMK's rich NOTIFY_* macros. Skips any extra that's empty/absent
    after `_clean()` -- see the module-level mapping table in the Phase 1
    task brief for the full service/host macro mapping."""
    details = _extra_details(notify, is_service)
    if details:
        alert["details"] = details
    perfdata = _extra_perfdata(notify, is_service)
    if perfdata:
        alert["perfdata"] = perfdata
    check_command = _extra_check_command(notify, is_service)
    if check_command:
        alert["check_command"] = check_command
    event = _extra_event(notify)
    if event:
        alert["event"] = event
    ack = _extra_ack(notify, is_service)
    if ack:
        alert["ack"] = ack
    downtime = _extra_downtime(notify, is_service)
    if downtime:
        alert["downtime"] = downtime
    groups = _extra_groups(notify, is_service)
    if groups:
        alert["groups"] = groups
    address = _extra_address(notify)
    if address:
        alert["address"] = address
    recurrence = _extra_recurrence(notify, is_service)
    if recurrence:
        alert["recurrence"] = recurrence


# NOTIFICATIONTYPEs that describe a lifecycle/administrative event rather
# than an active problem -- when the state macro alone is unrecognizable
# (blank/unexpanded), these are the deterministic "info" rung of the
# severity ladder (see `_severity_from`).
_NOTIFICATIONTYPE_INFO = frozenset({
    "ACKNOWLEDGEMENT", "DOWNTIMESTART", "DOWNTIMEEND", "DOWNTIMECANCELLED",
    "FLAPPINGSTART", "FLAPPINGSTOP",
})


def _severity_from(notify, state):
    """Deterministic severity ladder (determinism doctrine: lifecycle state
    decides severity, never the LLM):

    1. `normalize_severity(state)` if it is not "unknown" -- state remains
       primary, unchanged behavior for every normal notification.
    2. Else NOTIFY_NOTIFICATIONTYPE: a RECOVERY* type -> "ok"; an
       ACKNOWLEDGEMENT/DOWNTIME*/FLAPPING* type -> "info".
    3. Else "unknown" (the existing LLM-infer path -- reserved for genuine
       problem notifications whose state CheckMK never told us)."""
    severity = normalize_severity(state)
    if severity != "unknown":
        return severity
    ntype = _get(notify, "NOTIFY_NOTIFICATIONTYPE") or ""
    if ntype.startswith("RECOVERY"):
        return "ok"
    if ntype in _NOTIFICATIONTYPE_INFO:
        return "info"
    return "unknown"


def parse_notification(notify, source="checkmk"):
    """Return (idempotency_key, alert_dict, raw_text). Kept as a standalone
    function (not just inlined in `.parse()`) so the parsing logic stays
    directly unit-testable on its own."""
    host = notify.get("NOTIFY_HOSTNAME", "-")
    if _is_service(notify):
        service = _get(notify, "NOTIFY_SERVICEDESC")
        state = _get(notify, "NOTIFY_SERVICESTATE", "-") or "-"
        output = _get(notify, "NOTIFY_SERVICEOUTPUT", "-") or "-"
    else:
        service = None
        state = _get(notify, "NOTIFY_HOSTSTATE", "-") or "-"
        output = _get(notify, "NOTIFY_HOSTOUTPUT", "-") or "-"
    timestamp = notify.get("NOTIFY_SHORTDATETIME", "")

    alert = {
        "host": host, "state": state, "severity": _severity_from(notify, state),
        "output": output, "source": source,
    }
    if service:
        alert["service"] = service
    if timestamp:
        alert["timestamp"] = timestamp

    # Phase 1: fold in the canonical "extra" keys (details/perfdata/
    # check_command/event/ack/downtime/groups/address/recurrence) from
    # CheckMK's rich macros -- rendered/capped by nuncio.prompt._alert_block,
    # never here. Must not touch host/service/state/output/timestamp above.
    _populate_extras(notify, alert, is_service=_is_service(notify))

    # CheckMK's own plugin always forwards str NOTIFY_* env vars, but this
    # endpoint accepts arbitrary JSON -- coerce defensively (see
    # SourceAdapter._coerce_str_fields) so a non-string field can't reach the
    # prompt f-strings untyped.
    SourceAdapter._coerce_str_fields(alert)

    # Use the SAME ladder-derived severity as `alert["severity"]` (not a
    # fresh normalize_severity(state) call) -- a degenerate notification
    # with an unexpanded state macro (e.g. a RECOVERY whose HOSTSTATE macro
    # never expanded) has state -> "unknown" but a correct ladder-derived
    # severity of "ok"; deriving the emoji from state alone would render the
    # generic ❔ symbol on the raw-fallback path while the canonical severity
    # (and every other rendering of this alert) correctly shows ✅.
    emoji = severity_symbol(alert["severity"])
    entity = f"{host}/{service}" if service else host
    raw_text = f"{emoji} {entity} — {output}"
    return derive_key(notify, source), alert, raw_text


@register
class CheckMK(SourceAdapter):
    name = "checkmk"

    def parse(self, payload, headers):
        if not isinstance(payload, dict):
            raise ValueError("checkmk payload must be a JSON object of NOTIFY_* fields")
        key, alert, raw_text = parse_notification(payload, source=self.name)
        return [ParsedAlert(key=key, alert=alert, raw_text=raw_text)]
