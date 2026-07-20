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

The entropy backstop (see `_looks_secret`/`_sub_entropy` below) is a
heuristic and can false-positive on long, high-variety non-secret tokens
(device names, model numbers). `NUNCIO_REDACT_ALLOW_KEYWORDS` (see
`compile_allow_keywords`) lets an operator exempt specific tokens from THAT
BACKSTOP ONLY, by keyword-segment match. It can never un-redact anything
matched by a named rule or an EXTRA_RULES pattern — those insert
`«REDACTED:...»` placeholders before the entropy pass runs; the allowlist
only makes `_sub_entropy` return an already-unredacted token unchanged, it
never rewrites text.

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
     # Scheme quantifier is bounded (real URL schemes are short, RFC 3986
     # gives no hard limit but nothing legitimate runs past ~32 chars) --
     # UNBOUNDED here made every position in a long "://"-free run a
     # backtracking start point, O(n^2) on ordinary long alnum log lines
     # (base64, hex) with no attacker involved. See _RULE_PREFILTER below
     # for the belt-and-suspenders short-circuit.
     re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]{0,31}://)[^\s:/@]+:[^\s:/@]+@"),
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

# Per-rule prefilter: a cheap `in` check that must hold before a rule's
# (potentially costlier) regex is even tried. basic_auth's backtracking cost
# is only reachable when there's no "://" in the text to anchor a match on
# in the first place -- skip the regex entirely rather than just bounding it.
_RULE_PREFILTER = {"basic_auth": "://"}


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
    anything is persisted or swapped, never silently skipped. Note: an
    operator pattern with pathological (catastrophic-backtracking) structure
    is still bounded at runtime by redact()'s global _INPUT_CAP, same as the
    rest of the catalog -- it's a foot-gun mitigant, not a complexity
    validator."""
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


# Operator-configurable exemption from the entropy backstop ONLY -- it can
# never rescue a token already matched by a named rule (kv_secret, env,
# api_key, ...) or an EXTRA_RULES pattern; those run earlier and replace the
# match with a `«REDACTED:...»` placeholder before the entropy pass ever
# runs, so there is nothing left for the allowlist to see. This exists
# because the entropy heuristic alone false-positives on long, high-variety
# non-secret tokens such as device names (e.g. `USW-Pro-Max-48-PoE-Gen2`).
#
# Matching is SEGMENT-ANCHORED and case-sensitive: a token is exempt iff,
# after splitting it on `-` `.` `_`, some segment is an EXACT match (`==`)
# for some allow-keyword. A raw substring match was rejected deliberately --
# it would let a keyword like "U6" ride through a meaningful fraction of
# random secrets that merely happen to contain that substring; segment
# anchoring reduces that to effectively zero.
#
# Rebuilt as a brand-new list object on every change (never mutated in
# place), same discipline as _EXTRA_RULES above, so a concurrent redact()
# call never observes a half-updated list.
_ALLOW_KEYWORDS = []


def compile_allow_keywords(keywords):
    """Validate a list of allow-keyword strings (the settings screen's
    wire shape for NUNCIO_REDACT_ALLOW_KEYWORDS). Raises ValueError on any
    malformed entry -- used by the settings apply path so a bad value is
    rejected (400) before anything is persisted or swapped."""
    if not isinstance(keywords, list):
        raise ValueError(f"expected a list of keywords, got {keywords!r}")
    if len(keywords) > 64:
        raise ValueError(f"too many allow-keywords ({len(keywords)}, max 64)")
    cleaned = []
    for kw in keywords:
        if not isinstance(kw, str) or not kw:
            raise ValueError(f"invalid allow-keyword entry: {kw!r}")
        if len(kw) < 2:
            raise ValueError(f"allow-keyword too short (min 2 chars): {kw!r}")
        if len(kw) > 64:
            raise ValueError(f"allow-keyword too long (max 64 chars): {kw!r}")
        cleaned.append(kw)
    return cleaned


def set_allow_keywords(keywords):
    """Replace the allow-keyword list WHOLESALE with a new list object
    (never mutate the live list in place -- a concurrent redact() could
    observe it half-updated). Validated defensively here too, even though
    the settings apply path already validates via compile_allow_keywords()
    before persisting."""
    global _ALLOW_KEYWORDS
    _ALLOW_KEYWORDS = compile_allow_keywords(keywords)


def get_allow_keywords():
    """The current allow-keyword list, for round-tripping through
    /settings.json."""
    return list(_ALLOW_KEYWORDS)


def _is_allowlisted(tok):
    segments = re.split(r"[-._]", tok)
    return any(seg in _ALLOW_KEYWORDS for seg in segments)


# Hard cap on the size of text redact() will ever run its regex catalog
# over. This is the architectural backstop behind every per-pattern fix in
# this module (bounded basic_auth, bounded FQDN, operator NUNCIO_REDACT_EXTRA
# patterns of unknown complexity): no matter how expensive a pattern turns
# out to be, the input it runs against is bounded. Direction is
# truncate-and-DROP the remainder -- never pass the untruncated tail through
# unredacted, since a secret past the cap must not leak.
_INPUT_CAP = 200_000
_TRUNCATION_MARKER = "…«TRUNCATED:redactor-input-cap»"


def redact(text):
    """Strip secrets from `text`. Returns (redacted_text, findings).

    Used on BOTH planes. Does NOT touch identifiers (IPs/hostnames) — the
    private plane keeps those; the knowledge plane additionally strips them
    via scrub_for_knowledge_plane(). Both scrub_for_knowledge_plane() and
    scrub_for_assist_plane() inherit the _INPUT_CAP bound below via this
    call (stage 1 of each) -- neither duplicates it.
    """
    counts = {}
    if len(text) > _INPUT_CAP:
        text = text[:_INPUT_CAP] + _TRUNCATION_MARKER
        counts["input_truncated"] = 1
    for rtype, pattern, repl in _RULES:
        if rtype in _RULE_PREFILTER and _RULE_PREFILTER[rtype] not in text:
            continue
        text, n = pattern.subn(repl, text)
        if n:
            counts[rtype] = counts.get(rtype, 0) + n
    for rtype, pattern in _EXTRA_RULES:
        text, n = pattern.subn(f"«REDACTED:{rtype}»", text)
        if n:
            counts[rtype] = counts.get(rtype, 0) + n

    def _sub_entropy(m):
        tok = m.group(0)
        if not _looks_secret(tok):
            return tok
        if _is_allowlisted(tok):
            counts["entropy_exempt"] = counts.get("entropy_exempt", 0) + 1
            return tok
        counts["high_entropy"] = counts.get("high_entropy", 0) + 1
        return "«REDACTED:high_entropy»"

    text = _ENTROPY_TOKEN.sub(_sub_entropy, text)
    findings = [{"type": t, "count": c} for t, c in counts.items()]
    return text, findings


# Finding types that record something OTHER than a value removed. `entropy_exempt`
# is the inverse of a redaction -- a token the backstop deliberately SPARED -- so
# it must not inflate any "redaction_count" tally (the dashboard's "Redaction
# findings" stat). `input_truncated` records an input-length event, not a
# secret removed. Both still appear in `findings` for audit/logging.
_NON_REDACTION_FINDING_TYPES = frozenset({"entropy_exempt", "input_truncated"})


def count_redactions(findings):
    """Total number of values actually redacted in `findings`, EXCLUDING
    non-redaction findings (see `_NON_REDACTION_FINDING_TYPES`). Use this
    wherever a redaction_count is tallied so an exemption never reads as a
    redaction."""
    if not findings:
        return 0
    return sum(f.get("count", 0) for f in findings
               if f.get("type") not in _NON_REDACTION_FINDING_TYPES)


# Knowledge-plane (hosted LLM) additional stripping. Policy: bare hostnames
# are fine to send to a hosted/cloud provider, but IPs and FULL DOMAINS
# (FQDNs) are not — those are treated as identifying and stripped. IPv6 is
# best-effort (requires >=3 colon-groups or a `::` so it won't eat a clock
# time like 10:30:45).
_KNOWLEDGE_PLANE_TLDS = "net|com|org|io|dev|lan|local|internal|home|arpa|co|uk|me|app|cloud|gg|xyz|sh"
# RFC-1035 label shape, length-capped (1-63 chars, alnum-bookended, hyphens
# allowed mid-label only) -- the ONE source of truth for both the knowledge-
# and assist-plane FQDN patterns below. The old unbounded `[a-z0-9-]*` label
# plus an unbounded `(?:\.label)*` outer repetition meant every dot position
# in a long dotted run was a fresh backtracking branch point: O(n^2) on
# adversarial input like "a."*n with no closing known TLD. Capping the label
# at 63 chars (the RFC limit anyway) and the label-chain depth at 16 removes
# the quadratic without changing which real hostnames match -- nothing
# legitimate has a 64+ char label or a 17+ label chain.
_FQDN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_IDENTIFIER_RULES = [
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "«REDACTED:ip»"),
    ("ip", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{1,4}\b|\b[0-9a-fA-F]{0,4}::[0-9a-fA-F:]{1,}\b"),
     "«REDACTED:ip»"),
    ("fqdn",
     re.compile(r"\b" + _FQDN_LABEL + r"(?:\." + _FQDN_LABEL + r"){0,15}\.(?:" + _KNOWLEDGE_PLANE_TLDS + r")\b", re.I),
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
    r"\b(" + _FQDN_LABEL + r")((?:\." + _FQDN_LABEL + r"){0,15}\.(?:"
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
