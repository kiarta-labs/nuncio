"""Pattern-based secret redactor.

`redact(text) -> (text', findings)` — a pure function applied to EVERY outbound
payload on BOTH planes before egress. Secrets that were present are replaced
with a typed placeholder (`«REDACTED:<type>»`) so the LLM still sees that a
credential of a given kind existed (often diagnostic on its own — e.g. a bare
401 tells you auth failed even with the token itself stripped).

`findings` is a list of `{"type": <str>, "count": <int>}` — type + count only,
NEVER the secret value, so findings are safe to log.

Ordering matters: specific/structural patterns run before generic key=value ones
so a recognizable token (jwt/sk-) is typed precisely and a later generic pass
cannot re-process an already-inserted placeholder (value captures exclude `«`).

`NUNCIO_REDACT_EXTRA` (see `load_extra_rules` below) lets an operator add
org-specific `{"type", "regex"}` rules on top of this catalog without forking
— the built-in catalog is a generic, actively-maintained heuristic, not a
claim of completeness for any particular environment's secret formats.

`scrub_for_assist_plane()` (Batch C) is a THIRD, stricter scrubber for the
optional out-of-band assist plane (a single hosted-LLM call, see
`nuncio.assist`) — on top of `redact()`'s secret-stripping it also replaces
emails/IPs/FQDNs/usernames with stable `<type-N>` placeholders. Honesty
note: it only catches usernames in `user=`/`username=`/`login=`-shaped
key-value pairs and `/home/<name>/` paths — a username mentioned in free
prose ("ping me, kirit, if this recurs") has no reliable generic pattern and
will NOT be caught. Operators with org-specific username shapes (or any
other identifying pattern) should cover them via `NUNCIO_REDACT_EXTRA`, same
mechanism as any other secret shape.
"""
import re
from dataclasses import dataclass

# (type, compiled pattern, replacement) applied in order.
_RULES = [
    # Structural blocks and URL creds first.
    ("private_key",
     re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL),
     "«REDACTED:private_key»"),
    ("basic_auth",
     re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s:/@]+:[^\s:/@]+@"),
     r"\1«REDACTED:basic_auth»@"),
    ("auth_header",
     re.compile(r"(?im)^(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token|Api-Key):[ \t]*[^\r\n]+"),
     r"\1: «REDACTED:auth_header»"),
    # Recognizable token formats (a broadened catalog of known secret shapes).
    ("jwt",
     re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),  # 3rd seg may be empty (alg=none)
     "«REDACTED:jwt»"),
    ("api_key",
     re.compile(
         r"\b(?:"
         r"sk-[A-Za-z0-9_-]{20,}"              # OpenAI / sk-ant- style / generic
         r"|[sr]k_live_[A-Za-z0-9]{20,}"       # Stripe secret/restricted live keys
         r"|gh[opusr]_[A-Za-z0-9]{20,}"        # GitHub PAT / oauth / server / refresh
         r"|github_pat_[A-Za-z0-9_]{20,}"      # GitHub fine-grained PAT
         r"|xox[baprs]-[A-Za-z0-9-]{10,}"      # Slack tokens
         r"|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"  # SendGrid
         r"|AIza[0-9A-Za-z_-]{20,}"            # Google API key
         r"|AQ\.[A-Za-z0-9_-]{20,}"            # Google/Gemini gateway token shape (AQ.<b64url>)
         r"|A(?:KIA|SIA|ROA)[0-9A-Z]{16}"      # AWS access/temp/role key ids
         r")\b"),
     "«REDACTED:api_key»"),
    # Generic key:value / key=value with a known-secret KEY NAME (JSON/YAML/env/TOML).
    # Value may be a full quoted string (spaces ok) OR an unquoted token; never a
    # placeholder. Key match allows a leading `_` (compound names like smb_pass).
    ("kv_secret",
     re.compile(r'(?i)"?(?:\b|(?<=_))(password|passwd|pwd|pass|token|apikey|api[_-]?key|secret|access[_-]?key|client[_-]?secret|cred(?:ential)?|auth[_-]?pass)"?\s*[:=]\s*(?:"[^"«]*"|[^\s"«,}]+)'),
     r"\1=«REDACTED:kv_secret»"),
    # Env-var line whose NAME hits the denylist — keep the name (diagnostic), strip
    # the value. Denylist includes PASS/PWD/CRED/AUTH so compound names like
    # SMB_PASS, PGPASS, or auth_pass are caught, not just PASSWORD itself.
    ("env",
     re.compile(r"\b([A-Z_][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|KEY|CREDENTIAL|CRED)[A-Z0-9_]*)\s*=\s*(?:\"[^\"«]*\"|[^\s«]\S*)"),
     r"\1=«REDACTED:env»"),
]


# Operator-supplied extra rules — appended after the built-in catalog, before
# the entropy backstop, so they get first crack at typing a match precisely.
# Two independent sources feed the same effective list, kept apart so one can
# never erase the other:
#   _ENV_EXTRA_RULES  -- loaded once at startup from NUNCIO_REDACT_EXTRA (a
#                         file path; env-only, see config.py). Immutable after
#                         load except by adding more via add_extra_rule().
#   _UI_EXTRA_RULES    -- managed at runtime via the settings screen
#                         (NUNCIO_REDACT_EXTRA_RULES). Replaced WHOLESALE on
#                         every settings apply, but can never remove or
#                         disable an env-loaded rule -- see set_ui_extra_rules.
# _EXTRA_RULES is the list redact() actually reads; it is rebuilt as a brand
# new list object (never mutated in place) any time either source changes, so
# a concurrent redact() call can never observe a half-updated list.
_ENV_EXTRA_RULES = []  # list of (type, compiled_pattern)
_UI_EXTRA_RULES = []   # list of (type, compiled_pattern)
_EXTRA_RULES = []      # = _ENV_EXTRA_RULES + _UI_EXTRA_RULES, rebuilt on change


def _rebuild_extra_rules():
    global _EXTRA_RULES
    _EXTRA_RULES = list(_ENV_EXTRA_RULES) + list(_UI_EXTRA_RULES)


def add_extra_rule(rtype, pattern):
    """Register one additional ENV-sourced redaction rule at runtime.
    `pattern` is a regex string; matches are replaced with
    «REDACTED:<rtype>». Env-sourced rules can never be removed by the
    settings API (see set_ui_extra_rules)."""
    _ENV_EXTRA_RULES.append((rtype, re.compile(pattern)))
    _rebuild_extra_rules()


def load_extra_rules(path):
    """Load `{"type": ..., "regex": ...}` rules from `path` (NUNCIO_REDACT_EXTRA)
    and register them via add_extra_rule(). Zero-dependency constraint means no
    YAML library is available; a JSON file is valid YAML 1.2 flow style, so
    this reads the file as JSON — a documented subset, not full YAML support."""
    import json
    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    for r in rules:
        add_extra_rule(r["type"], r["regex"])


def compile_extra_rules(rules):
    """Validate + compile a list of `{"type": ..., "regex": ...}` dicts
    (the settings screen's on-disk/wire shape for NUNCIO_REDACT_EXTRA_RULES).
    Raises ValueError on any malformed entry or non-compiling pattern --
    used by the settings apply path so a bad rule is rejected (400) before
    anything is persisted or swapped, never silently skipped."""
    compiled = []
    for r in rules or []:
        try:
            rtype = str(r["type"])
            pattern = str(r["regex"])
        except (KeyError, TypeError, IndexError) as e:
            raise ValueError(f"invalid redaction rule entry: {r!r}") from e
        if not rtype or not pattern:
            raise ValueError(f"invalid redaction rule entry: {r!r}")
        try:
            compiled.append((rtype, re.compile(pattern)))
        except re.error as e:
            raise ValueError(f"invalid regex {pattern!r}: {e}") from e
    return compiled


def set_ui_extra_rules(rules):
    """Replace the UI-managed extra rules WHOLESALE with a new list object
    (never `.clear()` + `.append()` on the live list -- a concurrent
    redact() could observe it half-empty). `rules` is a list of
    `{"type", "regex"}` dicts; compiled (and validated) here defensively even
    though the settings apply path already validates via
    compile_extra_rules() before persisting.

    This is strictly additive over the built-in catalog and can never remove
    an env-loaded rule: _ENV_EXTRA_RULES is untouched and always re-appears
    in the rebuilt _EXTRA_RULES."""
    global _UI_EXTRA_RULES
    _UI_EXTRA_RULES = compile_extra_rules(rules)
    _rebuild_extra_rules()


def get_ui_extra_rules():
    """The current UI-managed extra rules as `{"type", "regex"}` dicts
    (pattern source text, not compiled objects) -- for round-tripping
    through /settings.json."""
    return [{"type": t, "regex": p.pattern} for t, p in _UI_EXTRA_RULES]


def _shannon_entropy(s):
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * log2(k / n) for k in counts.values())


# Entropy backstop (defense-in-depth): catch a BARE secret with no key name
# and no known prefix (e.g. an echoed password). A candidate is a
# long token drawn from secret-ish chars; we redact it only if it has high entropy
# AND ≥3 distinct character classes, so ordinary words/hostnames/paths survive.
_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_@$!%.\-]{20,}")


def _looks_secret(tok):
    classes = sum([
        any(c.islower() for c in tok),
        any(c.isupper() for c in tok),
        any(c.isdigit() for c in tok),
        any(not c.isalnum() for c in tok),
    ])
    return classes >= 3 and _shannon_entropy(tok) >= 3.2


def redact(text):
    """Strip secrets from `text`. Returns (redacted_text, findings).

    Used on BOTH planes. Does NOT touch identifiers (IPs/hostnames) — the
    private plane keeps those; the knowledge plane additionally strips them
    via scrub_for_knowledge_plane().
    """
    counts = {}
    for rtype, pattern, repl in _RULES:
        text, n = pattern.subn(repl, text)
        if n:
            counts[rtype] = counts.get(rtype, 0) + n
    for rtype, pattern in _EXTRA_RULES:
        text, n = pattern.subn(f"«REDACTED:{rtype}»", text)
        if n:
            counts[rtype] = counts.get(rtype, 0) + n

    def _sub_entropy(m):
        tok = m.group(0)
        if _looks_secret(tok):
            counts["high_entropy"] = counts.get("high_entropy", 0) + 1
            return "«REDACTED:high_entropy»"
        return tok

    text = _ENTROPY_TOKEN.sub(_sub_entropy, text)
    findings = [{"type": t, "count": c} for t, c in counts.items()]
    return text, findings


# Knowledge-plane (hosted LLM) additional stripping. Policy: bare hostnames
# are fine to send to a hosted/cloud provider, but IPs and FULL DOMAINS
# (FQDNs) are not — those are treated as identifying and stripped. IPv6 is
# best-effort (requires >=3 colon-groups or a `::` so it won't eat a clock
# time like 10:30:45).
_KNOWLEDGE_PLANE_TLDS = "net|com|org|io|dev|lan|local|internal|home|arpa|co|uk|me|app|cloud|gg|xyz|sh"
_IDENTIFIER_RULES = [
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "«REDACTED:ip»"),
    ("ip", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{0,4}::[0-9a-fA-F:]{1,}\b"),
     "«REDACTED:ip»"),
    ("fqdn",
     re.compile(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:" + _KNOWLEDGE_PLANE_TLDS + r")\b", re.I),
     "«REDACTED:fqdn»"),
]


def scrub_for_knowledge_plane(text):
    """Redact secrets AND strip IPs + FQDNs (bare hostnames survive).

    For the hosted/knowledge-plane endpoint only. Returns (scrubbed_text, findings).
    """
    text, findings = redact(text)
    counts = {}
    for rtype, pattern, repl in _IDENTIFIER_RULES:
        text, n = pattern.subn(repl, text)
        if n:
            counts[rtype] = counts.get(rtype, 0) + n
    findings.extend({"type": t, "count": c} for t, c in counts.items())
    return text, findings


# --- Assist-plane scrubber (Batch C) -----------------------------------
#
# ScrubbedPayload is a structural gate: `nuncio/assist.py::AssistClient.insight`
# only accepts this exact type, and this module is the ONLY place it may be
# constructed (enforced by a grep test, tests/test_assist_gate.py) -- so the
# only way text reaches the assist plane's LLM call is by passing through
# scrub_for_assist_plane() first. No caller can hand-roll a bypass.

@dataclass(frozen=True)
class ScrubbedPayload:
    text: str
    findings: tuple


_ASSIST_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Reuse the exact IPv4/IPv6 identifier patterns the knowledge plane already
# uses (index-matched to _IDENTIFIER_RULES' declaration order above) rather
# than duplicating the regex source.
_ASSIST_IPV4_RE = _IDENTIFIER_RULES[0][1]
_ASSIST_IPV6_RE = _IDENTIFIER_RULES[1][1]
# Same TLD catalog as the knowledge plane's FQDN rule, but with the first
# label captured separately so it can be KEPT bare while the rest of the
# domain is stripped (policy: bare hostnames survive, full domains don't).
_ASSIST_FQDN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)((?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:"
    + _KNOWLEDGE_PLANE_TLDS + r"))\b",
    re.I,
)
_ASSIST_USER_KV_RE = re.compile(r"(?:user|username|login)\s*[=:]\s*\"?([\w.\-]+)", re.I)
_ASSIST_HOME_RE = re.compile(r"/home/([\w.\-]+)/")


def scrub_for_assist_plane(text):
    """Scrub `text` for the optional out-of-band assist plane. Returns a
    `ScrubbedPayload(text, findings)`. Pipeline, IN ORDER (each stage runs on
    the previous stage's output, so an already-inserted placeholder can never
    be re-matched by a later stage):

      1. `redact()` -- secrets ALWAYS first.
      2. Emails -> `<email-N>` (their local part is queued for the username
         map in stage 5).
      3. IPv4 then IPv6 -> `<ip-N>`, stable within this call: the same
         address always gets the same placeholder, a different address
         always gets a new one.
      4. FQDNs (known TLD catalog) -> the bare first label is KEPT, the rest
         of the domain is stripped (`svr01.lan.example.net` -> `svr01`).
      5. Usernames -> `<user-N>`, a stable map built by scanning (in text
         order, after stages 2-4 have already run) `user=`/`username=`/
         `login=`-shaped key-value pairs and `/home/<name>/` paths, PLUS the
         local parts collected from stage 2's emails (queued first, so an
         email's local part claims the lowest-numbered slot if the same name
         also appears in a `user=` pair later in the same text). Whole-word
         substitution only -- never a substring match.

    Bare hostnames and container/service names are left untouched (same
    policy as the knowledge plane). See the module docstring for the honest
    limitation on prose-only usernames.
    """
    text, sec_findings = redact(text)
    counts = {}
    for f in sec_findings:
        counts[f["type"]] = counts.get(f["type"], 0) + f["count"]

    user_order = []
    seen_users = set()

    def _queue_user(name):
        if name and name not in seen_users:
            seen_users.add(name)
            user_order.append(name)

    def _email_sub(m):
        counts["email"] = counts.get("email", 0) + 1
        _queue_user(m.group(1))
        return f"<email-{counts['email']}>"

    text = _ASSIST_EMAIL_RE.sub(_email_sub, text)

    ip_map = {}

    def _ip_sub(m):
        addr = m.group(0)
        if addr not in ip_map:
            ip_map[addr] = f"<ip-{len(ip_map) + 1}>"
            counts["ip"] = counts.get("ip", 0) + 1
        return ip_map[addr]

    text = _ASSIST_IPV4_RE.sub(_ip_sub, text)
    text = _ASSIST_IPV6_RE.sub(_ip_sub, text)

    def _fqdn_sub(m):
        counts["fqdn"] = counts.get("fqdn", 0) + 1
        return m.group(1)

    text = _ASSIST_FQDN_RE.sub(_fqdn_sub, text)

    # Scan the (by-now email/ip/fqdn-substituted) text for both username
    # shapes together, in left-to-right text order, so a name's registration
    # order matches where it's first actually seen post-substitution.
    positional = []
    for m in _ASSIST_USER_KV_RE.finditer(text):
        positional.append((m.start(1), m.group(1)))
    for m in _ASSIST_HOME_RE.finditer(text):
        positional.append((m.start(1), m.group(1)))
    positional.sort(key=lambda t: t[0])
    for _pos, name in positional:
        _queue_user(name)

    if user_order:
        user_map = {name: f"<user-{i + 1}>" for i, name in enumerate(user_order)}
        # Longest-name-first substitution order is defensive/deterministic
        # (word-boundary matching already prevents a short name from eating
        # part of a longer one, but this keeps behavior unambiguous).
        for name in sorted(user_map, key=len, reverse=True):
            text = re.sub(r"(?<![\w.\-])" + re.escape(name) + r"(?![\w.\-])", user_map[name], text)
        counts["user"] = len(user_map)

    findings = tuple({"type": t, "count": c} for t, c in counts.items())
    return ScrubbedPayload(text=text, findings=findings)
