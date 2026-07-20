"""The settings screen -- machine-readable `/settings.json`, its HTML UI at
`/settings`, and the `POST /settings` request handling glue. Same
construction rules as `nuncio/web/dashboard.py`: one self-contained module,
inline CSS/JS (shared with the dashboard via `nuncio/web/shell.py`), no
dependencies, no build step.

Security posture:
GETs are always allowed and always read-only, with secrets masked exactly
like `/config.json`. Writes require `NUNCIO_ADMIN_TOKEN` to be configured at
all (403 if not -- fail CLOSED, never an unauthenticated default-writable
mutator) and a matching `X-Admin-Token` header, compared with
`hmac.compare_digest` (401 on mismatch). This module never decides WHAT is
editable or HOW a change is applied -- that is entirely `nuncio.config`'s
`UI_EDITABLE` table and `apply_changes()`; this module is purely the HTTP/UI
skin over it.
"""
import hmac
import json
from html import escape as _esc

from nuncio.redactor import redact
from nuncio.web.forms import FORM_JS as _FORM_JS
from nuncio.web.shell import page_shell as _page_shell
from nuncio.web.shell import FORM_CSS as _FORM_CSS
from nuncio.web.shell import PIPE_CSS as _PIPE_CSS

# nuncio.config imports nuncio.server (App/Metrics), and nuncio.server imports
# THIS module to wire the /settings routes -- a module-level `import
# nuncio.config` here would be circular. Imported lazily inside each function
# instead; cheap (module caching) and keeps the import graph acyclic.


def _cfg():
    from nuncio import config
    return config


MAX_BODY_BYTES = 64 * 1024


def _mask(value):
    return "«set»" if value else "«unset»"


def _redacted(value):
    """Defense-in-depth for every NON-secret-flagged value rendered here:
    GET /settings.json is unauthenticated, same threat model as GET
    /config.json (which already dogfoods the redactor via
    nuncio.config.masked_config_dict) -- a key that isn't explicitly marked
    `secret=True` could still embed a credential (e.g. basic-auth creds in a
    collector URL), and this catches that even if a key's `secret` flag is
    ever wrong or missing. Only string values are meaningful input to the
    (text-pattern) redactor; non-string JSON-typed values (bool/int/float/
    list/dict) pass through unchanged."""
    if isinstance(value, str) and value:
        return redact(value)[0]
    return value


# --- /settings.json ---

def build_settings_json(app):
    settings = app.settings
    keys = {}
    if settings is not None:
        secret_keys = _cfg().SECRET_KEYS
        for name, spec in _cfg().UI_EDITABLE.items():
            value = getattr(settings, name, spec.default)
            secret = name in secret_keys
            keys[name] = {
                "value": _mask(value) if secret else _redacted(value),
                "source": settings.source.get(name, "default"),
                "default": spec.default,
                "editable": True,
                "restart_required": spec.category == "restart",
                "secret": secret,
                "type": spec.type,
                "allowed": list(spec.allowed) if spec.allowed else None,
                "min": spec.min,
                "max": spec.max,
                "confirm": spec.confirm,
                "group": spec.group,
                "label": spec.label,
                "help": spec.help,
                "stage": _cfg().stage_for(name, spec),
            }
        for name, reason in _cfg().NEVER_REASONS.items():
            value = getattr(settings, name, "")
            secret = name in secret_keys
            keys[name] = {
                "value": _mask(value) if secret else _redacted(value),
                "source": settings.source.get(name, "env" if value else "default"),
                "default": _cfg()._SCHEMA.get(name, (None, None))[0],
                "editable": False,
                "restart_required": False,
                "secret": secret,
                "reason": reason,
                "group": "env-pinned",
                "stage": _cfg().stage_for(name, None),
            }
    return {
        "admin_token_configured": bool(getattr(app, "admin_token", None)),
        "restart_pending": _cfg().restart_pending(app) if settings is not None else [],
        "audit": ((settings.overrides_doc or {}).get("audit") or [])[:100] if settings is not None else [],
        "keys": keys,
    }


def render_settings_json(app):
    return json.dumps(build_settings_json(app), sort_keys=True, default=str).encode()


# --- POST /settings ---

def check_admin_token(app, headers):
    """(allowed: bool, status_code_if_denied: int). 403 when no token is
    configured at all (fail-closed default); 401 on a present-but-wrong
    token. Constant-time comparison (hmac.compare_digest) so response timing
    can't be used to brute-force the token byte-by-byte."""
    token = getattr(app, "admin_token", None)
    if not token:
        return False, 403
    supplied = headers.get("X-Admin-Token", "") or ""
    if not hmac.compare_digest(supplied, token):
        return False, 401
    return True, 200


def handle_post(app, body_bytes, headers):
    """Returns (http_status, response_dict) -- the caller (server.py) is
    responsible for turning that into an actual HTTP response; kept here so
    the logic is unit-testable without a live socket."""
    # M-2: auth strictly before any other 4xx from this handler -- so an
    # unauthenticated over-large POST 401/403s instead of leaking a 413
    # ahead of the auth check.
    ok, code = check_admin_token(app, headers)
    if not ok:
        if code == 403:
            return 403, {"error": "settings are read-only -- set NUNCIO_ADMIN_TOKEN to enable editing"}
        return 401, {"error": "invalid admin token"}
    if len(body_bytes) > MAX_BODY_BYTES:
        return 413, {"error": "request body too large"}
    if app.settings is None:
        return 500, {"error": "settings not available on this instance"}
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return 400, {"error": "invalid JSON body"}
    if not isinstance(payload, dict):
        return 400, {"error": "invalid JSON body"}
    set_map = payload.get("set") if payload.get("set") is not None else {}
    reset_list = payload.get("reset") if payload.get("reset") is not None else []
    if not isinstance(set_map, dict) or not isinstance(reset_list, list):
        return 400, {"error": "'set' must be an object and 'reset' a list of key names"}
    if not all(isinstance(k, str) for k in reset_list):
        return 400, {"error": "'reset' must be a list of key names"}
    # REV 3 §A5 -- the topbar lock validates a typed-in admin token by
    # round-tripping an EMPTY {"set":{}, "reset":[]} through this exact
    # endpoint (no new endpoint, no new writer). Short-circuit it here --
    # AFTER the auth check above (so a bad/absent token still 401/403s
    # first) and BEFORE apply_changes -- so a token probe never writes the
    # overrides file or appends an audit entry. Narrowing only: a non-empty
    # request is completely unaffected.
    if not set_map and not reset_list:
        return 200, {"applied": [], "restart_required": [], "rejected": {}}
    try:
        result = _cfg().apply_changes(app, set_map, reset_list)
    except _cfg().SettingsValidationError as e:
        return 400, {"errors": e.errors}
    except OSError as e:
        return 500, {"error": f"failed to persist settings: {e}"}
    result["rejected"] = {}
    return 200, result


# --- GET /settings (HTML) ---

# The pipeline stages, in run order -- these ids drive both the rail/section
# ids in the markup below and (in a later phase) which of UI_EDITABLE's
# server-emitted `stage` values a body's rows are filtered to. Kept as a
# plain tuple (not sourced from nuncio.config) because the *page layout* --
# five sections, this order, these ids -- is a UI decision independent of
# how config.stage_for() buckets any individual key.
_STAGES = [
    ("intake", "01", "Sources & intake", "Where alerts enter."),
    ("context", "02", "Context", "Evidence gathered around each alert — logs, metrics, containers."),
    ("enrich", "03", "Enrichment", "The model that explains each alert."),
    ("deliver", "04", "Delivery", "Where finished alerts go."),
    ("global", "⟛", "Pipeline", "Budgets, mode, redaction, retention — and the server itself."),
]


def _pipeline_html():
    """The vertical accordion skeleton. Each stage contributes THREE cells
    per grid row (§A3): `.pworld` (the outside-world column -- `_PAGE_JS`'s
    `renderFans()` fills it with the live fan-in/fan-out SVG), `.prail` (rail
    segment + node) and `.pstage` (header button + an empty, hidden
    accordion body); row rendering and the open/close behavior are Phase 3.
    Every cell for a stage carries that stage's `st-{key}` plumbing class
    (shell.py's PIPE_CSS §A2) so the diagram/panel paint with its circuit
    color; ids/ARIA are unchanged from the shipped accordion. The global
    stage's `.prail` cell also carries `prail-term` so shell.py's CSS can
    truncate its spine at the terminal square instead of running the row's
    full height (see the `.prail-term` comment in _PIPE_CSS_SOURCE)."""
    parts = []
    for key, ordinal, title, subtitle in _STAGES:
        st_cls = f"st-{key}"
        node_cls = "pnode pterm" if key == "global" else "pnode"
        rail_cls = f"prail prail-term {st_cls}" if key == "global" else f"prail {st_cls}"
        # The global stage's ordinal is the decorative glyph "⟛", not a
        # reader-meaningful step number like the other stages' "01"-"04" --
        # hide it from assistive tech. The chevron is always purely
        # decorative (aria-expanded on the button already conveys the
        # open/closed state).
        n_attr = ' aria-hidden="true"' if key == "global" else ""
        parts.append(
            f'<div class="pworld {st_cls}" id="world-{key}"></div>'
            f'<div class="{rail_cls}" id="rail-{key}"><span class="{node_cls}"></span></div>'
            f'<section class="pstage {st_cls}" id="stage-{key}"><h2>'
            f'<button class="phead" id="phead-{key}" aria-expanded="false" aria-controls="pbody-{key}">'
            f'<span class="n"{n_attr}>{_esc(ordinal)}</span>'
            f'<span class="ptitle">{_esc(title)}</span>'
            f'<span class="psub">{_esc(subtitle)}</span>'
            f'<span class="pmeta"></span>'
            f'<span class="pchev" aria-hidden="true">▾</span>'
            "</button></h2>"
            f'<div class="pbody-wrap" id="pwrap-{key}"><div class="pbody" id="pbody-{key}" role="region" '
            f'aria-labelledby="phead-{key}" hidden></div></div>'
            "</section>"
        )
    return '<div class="pipeline">' + "".join(parts) + "</div>"


# --- Phase 3 page glue: read-only interaction over the static Phase 2
# skeleton -- accordion open/close, per-stage row rendering (filtered by the
# server-emitted `.stage`, ordered by the §A3 sub-section spec), page
# banners, lazy intake inventory, load-time health tinting, deep-linking,
# and the restored audit/change-log.
#
# Phase 4 adds the write path on top: `doApply`/`discardChanges`/
# `renderApplyBar`/`reviewChanges`/`onApplyRejected` below wire the sticky
# `.applybar` (markup in render_settings_html) to the shared `sendApply` +
# `apply_changes` contract (nuncio/web/forms.py) -- this module adds no new
# endpoint or writer, only front-end callers of the existing one.
#
# Two client-side lookup tables below have no equivalent export from
# nuncio/config.py and are maintained by hand, mirroring it:
#   - STAGE_SUBSECTIONS: the §A3 sub-section order within a stage body
#     (Enrichment: Model/Knowledge/After delivery; Pipeline: Budgets &
#     mode/Redaction/Retention/Server). Editable keys are bucketed by their
#     real `spec.group`; NEVER_GROUP (below) supplies the same for locked
#     keys, whose `/settings.json` `group` field is flattened to the literal
#     string "env-pinned" (see build_settings_json) and so can't be used
#     for this.
#   - NEVER_GROUP: locked (NEVER_REASONS) key -> its true settings group,
#     hand-mapped from nuncio/config.py's UI_EDITABLE table so a locked key
#     (e.g. NUNCIO_LLM_URL) renders beside the group it actually belongs to
#     (e.g. "Model", beside NUNCIO_LLM_MODEL) instead of in an unlabeled tail.


def _minify_lock_js(js):
    """Same conservative whitespace/comment-line compaction as `_minify_css`
    (never rewrites a token, only strips comment-only lines and joins lines
    that are provably safe to join -- see dashboard.py's private
    `_minify_js`, which this mirrors). Wrapped around the §A5 topbar-lock
    block plus a handful of other self-contained blocks (renderMeta,
    renderAudit, the fan-drawing helpers, tintNode/applyHealthTints, the
    STAGES.forEach rail-forwarding wiring -- I5) --
    NOT the whole of `_PAGE_JS`. Several existing tests locate specific
    OTHER functions (openStage, closeStage, discardChanges, load,
    onApplied, renderFans) in the unminified source by scanning for a
    `"\\n}\\n"` line (see tests/test_settings.py's `_fn_body` helper and
    the equivalent inline scans), so minifying THOSE would break them --
    every block passed through this function is one nothing else depends
    on for its internal line formatting, so each can carry its own
    byte-budget discipline without that risk. Keep trailing `//` comments
    OUT of any block passed here: a comment that swallows the rest of its
    line is safe (an unterminated block never gets joined onto the next
    line, since the loop below only ever compares WHOLE stripped lines),
    but is still fragile to eyeball -- prefer a comment on its own line."""
    lines = []
    for line in js.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        lines.append(stripped)
    if not lines:
        return ""
    out = lines[0]
    for prev, nxt in zip(lines, lines[1:]):
        safe = prev[-1:] in ";{}(),:" and nxt[:1] not in "([`+-"
        out += ("" if safe else "\n") + nxt
    return out


_PAGE_JS = r"""
const STAGES = ['intake', 'context', 'enrich', 'deliver', 'global'];

const STAGE_SUBSECTIONS = {
  enrich: [
    ['Model', ['llm', 'pipeline']],
    ['Knowledge', ['knowledge']],
    ['After delivery (assist)', ['assist']],
  ],
  global: [
    ['Budgets & mode', ['pipeline', 'misc']],
    ['Redaction', ['redaction']],
    ['Retention', ['storage']],
    ['Server — restart required', ['server']],
    // Boot-pinned, never-settable keys (NUNCIO_DATA_DIR/CONFIG/ADMIN_TOKEN)
    // get their own divider rather than sitting under "Server — restart
    // required", which would wrongly imply a restart makes them editable --
    // they're never settable via this page, period.
    ['Environment (set at boot)', ['env-boot']],
  ],
};

// Stage titles for the apply bar's aggregate summary -- hand-kept in the
// same run order as Python's _STAGES (settings.py); STAGES above is already
// a hand-kept mirror of that same list, so this follows the same pattern
// rather than introducing a second source of truth for stage *order*.
const STAGE_TITLES = {
  intake: 'Sources & intake', context: 'Context', enrich: 'Enrichment',
  deliver: 'Delivery', global: 'Pipeline',
};

const NEVER_GROUP = {
  NUNCIO_LLM_URL: 'llm', NUNCIO_LLM_KEY: 'llm', NUNCIO_LLM_HEADERS: 'llm',
  NUNCIO_KNOWLEDGE_URL: 'knowledge', NUNCIO_KNOWLEDGE_KEY: 'knowledge',
  NUNCIO_ASSIST_URL: 'assist', NUNCIO_ASSIST_KEY: 'assist',
  NUNCIO_ASSIST_DATA_POSTURE: 'assist', NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK: 'assist',
  NUNCIO_EXTRA_SOURCES: 'ingest',
  NUNCIO_REDACT_EXTRA: 'redaction',
  NUNCIO_DATA_DIR: 'env-boot', NUNCIO_CONFIG: 'env-boot', NUNCIO_ADMIN_TOKEN: 'env-boot',
};

let STATS = null;
let SOURCES = null;
let RESTART_PENDING = [];
let OPEN_STAGE = null;
let INITIALIZED = false;

function effectiveGroup(k) {
  const spec = KEYS[k];
  if (!spec) return 'misc';
  return spec.editable ? (spec.group || 'misc') : (NEVER_GROUP[k] || 'misc');
}

function stageKeys(stage) {
  return Object.keys(KEYS).filter(k => KEYS[k].stage === stage);
}

function renderStage(key) {
  const wrap = document.getElementById('pbody-' + key);
  if (!wrap || wrap.dataset.rendered) return;
  const keys = stageKeys(key);
  let html = '';
  if (key === 'intake') html += '<div id="intake-inv" class="muted">Loading adapters&hellip;</div>';
  const subs = STAGE_SUBSECTIONS[key];
  if (subs) {
    const used = {};
    subs.forEach(([label, groups]) => {
      const names = keys.filter(k => groups.indexOf(effectiveGroup(k)) !== -1);
      names.forEach(k => { used[k] = true; });
      if (names.length) html += '<div class="pdiv">' + esc(label) + '</div>' + groupRows(names, { keys: KEYS });
    });
    const rest = keys.filter(k => !used[k]);
    if (rest.length) html += groupRows(rest, { keys: KEYS });
  } else {
    html += groupRows(keys, { keys: KEYS });
  }
  wrap.innerHTML = html;
  wrap.dataset.rendered = '1';
  // Capped power-up stagger (shell.py's `.pbody-wrap.open .row` keyframe):
  // rows 0-5 get their own 22ms step, rows 6+ all share step 5 so a long
  // panel (Delivery, ~20 rows) never adds extra wait past the sixth row.
  wrap.querySelectorAll('.row').forEach((row, i) => row.style.setProperty('--i', Math.min(i, 5)));
  // A re-render (e.g. the unlock-editing reload in load(), or a rejected
  // apply re-rendering the stage) rebuilds every input from server truth --
  // reapply any still-pending DIRTY value for this stage's keys so a typed-
  // but-not-yet-applied edit doesn't visually snap back. RESET keys have no
  // typed value to restore (they render at default already).
  keys.forEach(k => {
    if (!DIRTY.hasOwnProperty(k)) return;
    const el = wrap.querySelector('[data-k="' + k + '"]');
    if (!el) return;
    if (el.tagName === 'BUTTON') el.classList.toggle('on', DIRTY[k] === true);
    else el.value = KEYS[k].type === 'json' ? JSON.stringify(DIRTY[k]) : DIRTY[k];
  });
  if (key === 'intake') loadSources();
}

async function loadSources() {
  // Phase E: /sources is fetched once in load() and cached in SOURCES --
  // this reuses that result instead of a second round trip.
  try {
    const data = SOURCES || {};
    const registered = data.registered || [];
    const counts = (STATS && STATS.by_source_24h) || {};  // real 24h count, not the resettable in-memory one
    const currentSpec = KEYS.NUNCIO_DEFAULT_SOURCE;
    // Seed from a pending typed edit first -- otherwise this async upgrade
    // (which lands after renderStage()'s DIRTY-reapply loop already ran)
    // rebuilds the input from the SERVER value and silently overwrites an
    // edit the user already made but hasn't applied yet.
    const current = DIRTY.hasOwnProperty('NUNCIO_DEFAULT_SOURCE')
      ? DIRTY.NUNCIO_DEFAULT_SOURCE : (currentSpec ? currentSpec.value : '');
    const rows = registered.map(name =>
      '<div class="row"><div class="lbl">' + esc(name) +
      (name === current ? ' <span class="badge-src default">default</span>' : '') + '</div>' +
      '<div class="muted">' + (counts[name] || 0) + ' ingested (24h)</div><div></div><div></div></div>'
    ).join('');
    const inv = document.getElementById('intake-inv');
    if (inv) inv.outerHTML = rows || '<p class="muted">No adapters registered.</p>';
    upgradeDefaultSourceSelect(registered, current);
    const tokInput = document.querySelector('[data-k="NUNCIO_INGEST_TOKEN"]');
    const tokRow = tokInput && tokInput.closest('.row');
    const tokLbl = tokRow && tokRow.querySelector('.lbl');
    if (tokLbl) {
      const cur = tokLbl.getAttribute('data-help') || '';
      if (cur.indexOf('rotated here') === -1) {
        tokLbl.setAttribute('data-help', (cur ? cur + ' ' : '') + 'Can be rotated here, never cleared.');
      }
    }
  } catch (e) { /* leave the loading placeholder and the plain text input in place */ }
}

function upgradeDefaultSourceSelect(registered, current) {
  const input = document.querySelector('[data-k="NUNCIO_DEFAULT_SOURCE"]');
  if (!input || input.tagName === 'SELECT' || !registered.length) return;
  const select = document.createElement('select');
  select.setAttribute('data-k', 'NUNCIO_DEFAULT_SOURCE');
  select.disabled = !(ADMIN_TOKEN_CONFIGURED && TOKEN);
  select.innerHTML = registered.map(name =>
    '<option value="' + esc(name) + '"' + (name === current ? ' selected' : '') + '>' + esc(name) + '</option>'
  ).join('');
  select.addEventListener('change', () => onEdit('NUNCIO_DEFAULT_SOURCE', select.value));
  input.replaceWith(select);
}

// Phase E/F: world-column fan-in/fan-out. Labels are HTML <span>s, not SVG
// <text> (SVG text stretched under the non-uniform viewBox scale).
""" + _minify_lock_js(r"""
function fanLabel(n) { return n.length > 9 ? n.slice(0, 9) + '…' : n; }
function fanYs(rows) {
  if (rows < 2) return [34];
  const top = 8, step = (56 - top) / (rows - 1), ys = [];
  for (let i = 0; i < rows; i++) ys.push(top + i * step);
  return ys;
}
function fanCurves(cap, colorVar, ys) {
  const parts = cap.map((name, i) => '<path d="M2,' + ys[i] + ' C40,' + ys[i] + ' 72,32 96,34" stroke="'
    + colorVar + '" stroke-opacity=".35" stroke-width="1.5" fill="none"/>').join('');
  return '<svg viewBox="0 0 100 60" preserveAspectRatio="none">' + parts + '</svg>';
}
function fanLabels(cap, colorVar, highlight, ys, overflow) {
  const spans = cap.map((name, i) => {
    const hi = highlight && name === highlight;
    return '<span class="fanlbl" style="top:' + (ys[i] - 5) + 'px' + (hi ? ';color:' + colorVar : '') + '">'
      + esc(fanLabel(name)) + '</span>';
  }).join('');
  const more = overflow > 0
    ? '<span class="fanlbl" style="top:' + (ys[cap.length] - 5) + 'px">' + '+' + overflow + ' more</span>' : '';
  return spans + more;
}
function paintFan(elId, stage, items, colorVar, highlight, collapsed, chipText) {
  const meta = document.querySelector('#phead-' + stage + ' .pmeta');
  if (meta) {
    let chip = meta.querySelector('.fanchip');
    if (collapsed) {
      if (!chip) { chip = document.createElement('span'); chip.className = 'fanchip'; meta.insertBefore(chip, meta.firstChild); }
      chip.textContent = chipText;
    } else if (chip) { chip.remove(); }
  }
  const el = document.getElementById(elId);
  if (!el) return;
  if (collapsed) { el.innerHTML = ''; return; }
  const cap = items.slice(0, 5), overflow = items.length - cap.length;
  const ys = fanYs(cap.length + (overflow > 0 ? 1 : 0));
  el.innerHTML = fanCurves(cap, colorVar, ys) + fanLabels(cap, colorVar, highlight, ys, overflow);
}
""") + r"""

function renderFans() {
  if (!KEYS) return;
  const registered = (SOURCES && SOURCES.registered) || [];
  const raw = (KEYS.NUNCIO_DELIVERY && KEYS.NUNCIO_DELIVERY.value) || '';
  let channels = raw.split(',').map(s => s.trim()).filter(Boolean);
  if (!channels.length) channels = ['stdout'];  // honest empty state: the real default, never a fake
  const collapsed = window.innerWidth <= 900;
  const defSrc = KEYS.NUNCIO_DEFAULT_SOURCE ? KEYS.NUNCIO_DEFAULT_SOURCE.value : '';
  // M3: singularize (default config used to read "1 channels out").
  paintFan('world-intake', 'intake', registered, 'var(--st-intake)', defSrc, collapsed,
    registered.length + ' source' + (registered.length === 1 ? '' : 's') + ' in');
  paintFan('world-deliver', 'deliver', channels, 'var(--st-deliver)', null, collapsed,
    channels.length + ' channel' + (channels.length === 1 ? '' : 's') + ' out');
}
// I3: re-run on resize -- fans used to vanish/stick across 900px (incl. tablet rotation).
matchMedia('(max-width:900px)').addEventListener('change', renderFans);

""" + _minify_lock_js(r"""
// Phase 5 judgment call (§A5's flagged residual risk): the header .pmeta
// cluster was counts + a live 24h stat + the dirty chip + a restart badge +
// the chevron -- five items in one row felt busy in build, per the
// addendum's "restrained in quantity, high in craft" brief. The live stat
// is dropped here (STATS is still fetched -- it drives the health tints
// below, which are load-bearing); counts + dirty chip + restart badge +
// chevron stay, since those are the state signals an operator actually
// needs before opening a stage.
function renderMeta(stage) {
  const meta = document.querySelector('#phead-' + stage + ' .pmeta');
  if (!meta) return;
  const keys = stageKeys(stage);
  const locked = keys.filter(k => !KEYS[k].editable).length;
  const bits = keys.length + ' settings' + (locked ? ' · ' + locked + ' env-locked' : '');
  const restart = keys.some(k => RESTART_PENDING.indexOf(k) !== -1)
    ? '<span class="badge-restart">restart</span>' : '';
  meta.innerHTML = esc(bits) + '<span class="dirty" id="dirty-' + stage + '"></span>' + restart;
}
function renderBanners(data) {
  // §A5: both auth banners retired -- renderLock() is the one auth surface.
  const restartEl = document.getElementById('restartbanner');
  restartEl.innerHTML = (data.restart_pending && data.restart_pending.length)
    ? '<div class="banner warn">Waiting on a restart: ' + data.restart_pending.map(esc).join(', ') + '.</div>' : '';
}

// §A5 topbar lock: state = f(ADMIN_TOKEN_CONFIGURED, TOKEN). Unlock validates
// through the EXISTING write contract (empty POST /settings + X-Admin-Token)
// -- handle_post's empty-set guard means a probe never touches apply_changes.
// Minified below (unlike the rest of _PAGE_JS) purely for byte budget -- the
// source stays fully commented/readable here; nothing about behavior changes
// (nuncio.web.shell's CSS minifier already does the same thing for CSS).
const LOCK_SHACKLE_CLOSED = 'M4 5V4a2 2 0 014 0v1';
const LOCK_SHACKLE_OPEN = 'M4 5V3a2 2 0 014-1v2';

function lockState() {
  if (!ADMIN_TOKEN_CONFIGURED) return 'none';
  if (!TOKEN) return 'locked';
  return 'unlocked';
}

function renderLock() {
  const state = lockState();
  const trig = document.getElementById('locktrig');
  if (!trig) return;
  trig.classList.toggle('unlocked', state === 'unlocked');
  const shackle = document.getElementById('lockshackle');
  if (shackle) shackle.setAttribute('d', state === 'unlocked' ? LOCK_SHACKLE_OPEN : LOCK_SHACKLE_CLOSED);
  const label = document.getElementById('locklabel');
  if (label) label.textContent = state === 'none' ? 'read-only' : (state === 'locked' ? 'locked' : 'editing');
  renderLockPopoverBody(state);
  const caption = document.getElementById('pcaption');
  if (caption) caption.textContent = state === 'unlocked' ? '' : 'read-only — unlock in the top bar';
}

function renderLockPopoverBody(state) {
  const body = document.getElementById('lockpopbody');
  if (!body) return;
  if (state === 'none') {
    body.innerHTML = '<p>Editing is off. Set <code>NUNCIO_ADMIN_TOKEN</code> in the environment and restart to enable it.</p>';
  } else if (state === 'locked') {
    // I4 fix: wrapped in a <form> (was a bare input+button) so Enter in the
    // token field submits -- previously the keyboard-only path was Tab to
    // the button. M8: aria-label on the input (placeholder alone isn't an
    // accessible name).
    body.innerHTML = '<p>Locked — read-only.</p><form onsubmit="unlockNow();return false">'
      + '<input type="password" id="lockinput" placeholder="Admin token" aria-label="Admin token">'
      + '<div class="rowerr" id="lockerr"></div><button class="btn primary" type="submit">Unlock</button></form>';
  } else {
    body.innerHTML = '<p>Editing unlocked for this tab.</p><button class="btn" onclick="lockNow()">Lock</button>';
  }
}

function toggleLock() {
  const pop = document.getElementById('lockpop');
  if (pop && !pop.hidden) closeLock(); else openLock();
}

function openLock() {
  const pop = document.getElementById('lockpop'), trig = document.getElementById('locktrig');
  if (!pop) return;
  renderLockPopoverBody(lockState());
  pop.hidden = false;
  if (trig) trig.setAttribute('aria-expanded', 'true');
  const input = document.getElementById('lockinput');
  if (input) input.focus(); else if (trig) trig.focus();
}

function closeLock() {
  const pop = document.getElementById('lockpop'), trig = document.getElementById('locktrig');
  if (!pop || pop.hidden) return;
  pop.hidden = true;
  if (trig) { trig.setAttribute('aria-expanded', 'false'); trig.focus(); }
}

// C2 fix: forms.py's sendApply() calls this (in
// preference to promptToken()) on a 401 -- the token the server just
// rejected is still sitting in TOKEN/sessionStorage, so a bare promptToken()
// would render openLock() for the CURRENT (still truthy-TOKEN) state, i.e.
// the popover claims "Editing unlocked for this tab." at the exact moment
// the server said the token was invalid. Drop the dead token FIRST, then
// render the now-honestly-locked state before opening the popover.
function lockInvalid() {
  TOKEN = '';
  sessionStorage.removeItem('nuncio_admin_token');
  renderLock();
  openLock();
}

// Always-on (not attached per open/close -- closeLock() no-ops when already
// closed) -- Esc and outside-click both close the popover if it's open.
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeLock(); });
document.addEventListener('click', e => {
  const wrap = document.getElementById('lockwrap');
  if (wrap && !wrap.contains(e.target)) closeLock();
}, true);

async function probeToken(tok) {
  try {
    const r = await fetch('/settings', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': tok },
      body: JSON.stringify({ set: {}, reset: [] }),
    });
    return r.status;
  } catch (e) { return 0; }
}

async function unlockNow() {
  const input = document.getElementById('lockinput');
  if (!input) return;
  const status = await probeToken(input.value);
  if (status === 200) {
    TOKEN = input.value;
    sessionStorage.setItem('nuncio_admin_token', TOKEN);
    closeLock(); renderLock(); load();
  } else if (status === 403) {
    // Server truth wins.
    ADMIN_TOKEN_CONFIGURED = false;
    renderLock();
  } else if (status === 0) {
    // M4: probeToken() returns 0 when the fetch itself throws (server
    // unreachable) -- "That token didn't match." is simply wrong there.
    const err = document.getElementById('lockerr');
    if (err) err.textContent = "Couldn't reach the server.";
  } else {
    const err = document.getElementById('lockerr');
    if (err) err.textContent = "That token didn't match.";
  }
}

function lockNow() {
  TOKEN = '';
  sessionStorage.removeItem('nuncio_admin_token');
  closeLock(); renderLock(); load();
}
""") + _minify_lock_js(r"""
function renderAudit(data) {
  const el = document.getElementById('auditlist');
  const rows = (data.audit || []).slice(0, 100);
  if (!rows.length) { el.innerHTML = '<p class="muted">No changes recorded yet.</p>'; return; }
  el.innerHTML = '<div class="tablewrap"><table><thead><tr><th>Time</th><th>Key</th><th>Change</th></tr></thead><tbody>'
    + rows.map(a => '<tr><td>' + esc(a.ts || '') + '</td><td>' + esc((a.keys || []).join(', ')) + '</td><td>'
      + esc(a.action || '') + '</td></tr>').join('') + '</tbody></table></div>';
}
function tintNode(stage, cls) {
  const node = document.querySelector('#rail-' + stage + ' .pnode');
  if (node) node.classList.add(cls);
  const ord = document.querySelector('#phead-' + stage + ' .n');
  if (ord) ord.classList.add(cls);
  const head = document.getElementById('phead-' + stage);
  if (head) head.classList.add(cls);
  // I2 fix: also tint the RAIL cell, not just the
  // node inside it -- the junction stub (.prail::after), the twin-hairline
  // bus, and the segment gradient all paint from the rail's OWN --st, not
  // the node's, so without this a sick stage kept an identity-colored stub
  // physically attached to its own breach-red echo ring (off-spec vs "a
  // sick stage's circuit color drops out entirely").
  const rail = document.getElementById('rail-' + stage);
  if (rail) rail.classList.add(cls);
}

function applyHealthTints() {
  // M5 fix: this used to only ADD tint classes, so a
  // stage that recovered stayed breach/amber-tinted until a full page
  // reload. Clear all three before re-adding so a load()/re-apply always
  // reflects current health, not stale history.
  document.querySelectorAll('.nodebad,.nodewarn,.nodering').forEach(el =>
    el.classList.remove('nodebad', 'nodewarn', 'nodering'));
  if (!STATS) return;
  try {
    if (STATS.totals && STATS.totals.undelivered_now > 0) tintNode('deliver', 'nodebad');
  } catch (e) { /* no-op -- a missing/malformed stats field simply doesn't tint */ }
  try {
    // Only warn on a low enriched-rate when there is actual 24h traffic --
    // enriched_rate is 0.0 (not null) on an idle instance (see dashboard.py
    // _rate), which would otherwise always tint this node amber.
    if (STATS.window_24h && STATS.window_24h.ingested > 0 && STATS.window_24h.enriched_rate < 0.6) tintNode('enrich', 'nodewarn');
  } catch (e) { /* no-op -- a missing/malformed stats field simply doesn't tint */ }
  try {
    if (STATS.queue && STATS.queue.depth >= STATS.queue.max) tintNode('intake', 'nodering');
  } catch (e) { /* no-op -- a missing/malformed stats field simply doesn't tint */ }
}
""") + r"""

function onDirtyChange() {
  STAGES.forEach(stage => {
    const chip = document.getElementById('dirty-' + stage);
    if (!chip) return;
    const n = stageKeys(stage).filter(k => DIRTY.hasOwnProperty(k) || RESET.hasOwnProperty(k)).length;
    chip.textContent = n ? ('● ' + n + ' edit' + (n === 1 ? '' : 's')) : '';
  });
  renderApplyBar();
}

function pendingKeys() {
  return Array.from(new Set(Object.keys(DIRTY).concat(Object.keys(RESET))));
}

function firstDirtyStage() {
  const pending = pendingKeys();
  return STAGES.find(s => pending.some(k => KEYS[k] && KEYS[k].stage === s)) || null;
}

function renderApplyBar() {
  const bar = document.getElementById('applybar');
  const diff = document.getElementById('applydiff');
  if (!bar || !diff) return;
  const pending = pendingKeys();
  if (!pending.length) { bar.classList.remove('show'); diff.textContent = ''; return; }
  const counts = {};
  pending.forEach(k => {
    const stage = (KEYS[k] && KEYS[k].stage) || 'global';
    counts[stage] = (counts[stage] || 0) + 1;
  });
  const titles = STAGES.filter(s => counts[s]).map(s => STAGE_TITLES[s] || s);
  diff.textContent = pending.length + ' change' + (pending.length === 1 ? '' : 's') + ' in ' + titles.join(', ');
  bar.classList.add('show');
}

function reviewChanges() {
  const stage = firstDirtyStage();
  if (stage) openStage(stage);
}

function applyConfirmMessage() {
  const confirmKeys = pendingKeys().filter(k => KEYS[k] && KEYS[k].confirm);
  return confirmKeys.length
    ? 'This will change ' + confirmKeys.join(', ') + '. Apply now?'
    : 'Apply these changes?';
}

async function onApplied() {
  // sendApply() has already cleared DIRTY/RESET and toasted success before
  // this runs -- a load() failure below must not swallow that: onDirtyChange
  // (which also re-renders the apply bar) runs in `finally` so a rejected
  // refresh can never leave the apply bar claiming stale pending changes
  // after a SUCCESSFUL apply.
  try {
    await load();
  } finally {
    onDirtyChange();
  }
}

function doApply() {
  if (needsConfirm()) {
    showModal(applyConfirmMessage(), () => sendApply(onApplied));
  } else {
    sendApply(onApplied);
  }
}

function discardChanges() {
  DIRTY = {}; RESET = {};
  clearRowErrors();
  // Invalidate EVERY rendered stage, not just the open one -- a stage the
  // user opened, edited, and collapsed keeps dataset.rendered='1', so
  // renderStage() would otherwise early-return on next open and show the
  // just-discarded typed values as if still pending. Same loop load() uses
  // for the same reason (unlock-editing re-render).
  STAGES.forEach(key => {
    const body = document.getElementById('pbody-' + key);
    if (body && body.dataset.rendered) body.dataset.rendered = '';
  });
  if (OPEN_STAGE) renderStage(OPEN_STAGE);
  onDirtyChange();
}

function onApplyRejected(firstKey) {
  if (firstKey && KEYS[firstKey]) openStage(KEYS[firstKey].stage);
}

function reducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Gates `.pbody`'s `hidden` and `overflow` off the wrap's own
// `grid-template-rows` transition actually finishing, so assistive tech
// only ever sees `hidden` at true rest, never mid-animation -- and a rapid
// open/close can't strand it: this reads the wrap's CURRENT `.open` class
// at transitionend time, not a snapshot from when the transition started,
// so an interrupted collapse (re-opened again before it finished -- which
// cancels the pending transitionend and starts a fresh expand instead)
// never wrongly hides a stage that's actually open, and vice versa.
// Registered once per stage (below), not per open/close call, so it never
// accumulates duplicate listeners.
function wrapTransitionEnd(key, e) {
  if (e.propertyName !== 'grid-template-rows') return;
  const wrap = document.getElementById('pwrap-' + key);
  const body = document.getElementById('pbody-' + key);
  if (!wrap || !body) return;
  if (wrap.classList.contains('open')) {
    body.style.overflow = 'visible';
  } else {
    body.hidden = true;
    wrap.classList.remove('closing');
    body.style.overflow = 'hidden';
  }
}

function closeStage(key) {
  const stage = document.getElementById('stage-' + key);
  const rail = document.getElementById('rail-' + key);
  const wrap = document.getElementById('pwrap-' + key);
  const head = document.getElementById('phead-' + key);
  const body = document.getElementById('pbody-' + key);
  // If focus is inside the body about to collapse, move it to this stage's
  // own header first. A mouse click normally focuses the header being
  // clicked before this runs, but not on every engine (Safari doesn't focus
  // a <button> on click) -- without this, closing a stage whose body held
  // focus (e.g. an input mid-edit) drops focus to <body> once `hidden`
  // lands. The Esc handler already restores focus this way; this covers
  // every other path that closes a stage (header click, [Review], the 400
  // auto-open) too.
  if (body && head && document.activeElement && body.contains(document.activeElement)) {
    head.focus();
  }
  // A reload should not reopen a stage the user explicitly closed.
  if (location.hash === '#stage-' + key) history.replaceState(null, '', '#');
  // Re-clip before the collapse starts -- it may have been released to
  // `visible` at rest while open (see openStage()/wrapTransitionEnd()).
  if (body) body.style.overflow = 'hidden';
  if (wrap) wrap.classList.add('closing');
  if (stage) stage.classList.remove('open');
  if (rail) rail.classList.remove('open');
  if (wrap) wrap.classList.remove('open');
  if (head) head.setAttribute('aria-expanded', 'false');
  if (reducedMotion()) {
    // No transition fires under reduced motion, so no `transitionend` will
    // ever arrive to gate `hidden` -- set it synchronously instead.
    if (body) body.hidden = true;
    if (wrap) wrap.classList.remove('closing');
  }
  // Otherwise `hidden` is set by wrapTransitionEnd() once the collapse's
  // `grid-template-rows` transition actually completes.
}

function openStage(key) {
  // The [Review] button (reviewChanges()) and the 400 auto-open
  // (onApplyRejected()) both call openStage() directly, bypassing
  // toggleStage()'s one-open-at-a-time bookkeeping -- close whatever is
  // currently open first (unless it's already this stage) so those two side
  // doors respect the same invariant the accordion's whole design rests on.
  if (OPEN_STAGE === key) return;
  if (OPEN_STAGE) closeStage(OPEN_STAGE);
  renderStage(key);
  const stage = document.getElementById('stage-' + key);
  const rail = document.getElementById('rail-' + key);
  const wrap = document.getElementById('pwrap-' + key);
  const head = document.getElementById('phead-' + key);
  const body = document.getElementById('pbody-' + key);
  // Clear any stale collapse-in-progress state from a rapid re-open (see
  // wrapTransitionEnd()'s guard) so this expand runs at the full `--dur`,
  // not the faster collapse duration `.closing` overrides.
  if (wrap) wrap.classList.remove('closing');
  // Un-hide FIRST, force a reflow, THEN add `.open` -- so the transition
  // runs from the true collapsed state instead of jumping straight open.
  if (body) body.hidden = false;
  if (wrap) void wrap.offsetHeight;
  if (stage) stage.classList.add('open');
  if (rail) rail.classList.add('open');
  if (wrap) wrap.classList.add('open');
  if (head) head.setAttribute('aria-expanded', 'true');
  OPEN_STAGE = key;
  history.replaceState(null, '', '#stage-' + key);
  if (stage) stage.scrollIntoView({ block: 'nearest' });
  if (reducedMotion() && body) body.style.overflow = 'visible';
}

function toggleStage(key) {
  if (OPEN_STAGE === key) { closeStage(key); OPEN_STAGE = null; return; }
  if (OPEN_STAGE) closeStage(OPEN_STAGE);
  openStage(key);
}

function openDeepLinkedStage() {
  const h = location.hash;
  if (h.indexOf('#stage-') !== 0) return;
  const key = h.slice(7);
  if (STAGES.indexOf(key) !== -1) toggleStage(key);
}

""" + _minify_lock_js(r"""
// Rail/world cells forward clicks to the header toggle; header hover/focus
// mirrors `.nodehover` onto the paired rail cell (DOM order can't reach it
// via pure-CSS sibling combinator) so its node scales up in CSS.
STAGES.forEach(key => {
  const head = document.getElementById('phead-' + key);
  if (head) head.addEventListener('click', () => toggleStage(key));
  const wrap = document.getElementById('pwrap-' + key);
  if (wrap) wrap.addEventListener('transitionend', e => wrapTransitionEnd(key, e));
  const rail = document.getElementById('rail-' + key);
  const world = document.getElementById('world-' + key);
  const forwardClick = () => toggleStage(key);
  if (rail) { rail.style.cursor = 'pointer'; rail.addEventListener('click', forwardClick); }
  if (world) { world.style.cursor = 'pointer'; world.addEventListener('click', forwardClick); }
  if (head && rail) {
    head.addEventListener('mouseenter', () => rail.classList.add('nodehover'));
    head.addEventListener('mouseleave', () => rail.classList.remove('nodehover'));
    // Keyboard-only, matching .psub's :focus-visible reveal.
    head.addEventListener('focus', () => { if (head.matches(':focus-visible')) rail.classList.add('nodehover'); });
    head.addEventListener('blur', () => rail.classList.remove('nodehover'));
  }
});
""") + r"""

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  const body = e.target.closest && e.target.closest('.pbody');
  if (!body) return;
  const key = body.id.replace('pbody-', '');
  closeStage(key);
  if (OPEN_STAGE === key) OPEN_STAGE = null;
  const head = document.getElementById('phead-' + key);
  if (head) head.focus();
});

const globalHead = document.getElementById('phead-global');
if (globalHead) {
  globalHead.addEventListener('mouseenter', () => {
    const pipeline = document.querySelector('.pipeline');
    if (pipeline) pipeline.classList.add('rail-hi');
  });
  globalHead.addEventListener('mouseleave', () => {
    const pipeline = document.querySelector('.pipeline');
    if (pipeline) pipeline.classList.remove('rail-hi');
  });
}

async function load() {
  // A failed fetch here must not strand the page: on first load it would
  // otherwise leave "Loading..." forever with no deep-link/interaction
  // (INITIALIZED never set); on a post-apply refresh it would leave the
  // last good render in place unexplained. Keep last good render, toast,
  // and always finish initialization regardless of outcome.
  try {
    const r = await fetch('/settings.json');
    const data = await r.json();
    KEYS = data.keys;
    RESTART_PENDING = data.restart_pending || [];
    ADMIN_TOKEN_CONFIGURED = !!data.admin_token_configured;
    if (!STATS) {
      try {
        const rs = await fetch('/stats.json');
        STATS = await rs.json();
      } catch (e) { STATS = null; }
    }
    if (!SOURCES) {
      try {
        const rsrc = await fetch('/sources');
        SOURCES = await rsrc.json();
      } catch (e) { SOURCES = null; }
    }
    renderBanners(data);
    renderLock();
    STAGES.forEach(renderMeta);
    renderFans();
    renderAudit(data);
    applyHealthTints();
    // Unlocking editing (unlockNow() -> load()) changes what inputHtml
    // renders (disabled vs enabled) for EVERY stage, not just the open one
    // -- rows are cached behind wrap.dataset.rendered, so every already-
    // rendered stage body needs its cache invalidated here, or it keeps
    // showing stale disabled inputs until a full page reload. Re-render the
    // currently-open stage immediately (visible); the rest re-render lazily
    // next time they're opened.
    STAGES.forEach(key => {
      const body = document.getElementById('pbody-' + key);
      if (body && body.dataset.rendered) body.dataset.rendered = '';
    });
    if (OPEN_STAGE) renderStage(OPEN_STAGE);
    onDirtyChange();
  } catch (e) {
    toast("Couldn't refresh settings — showing last loaded values");
  } finally {
    if (!INITIALIZED) { INITIALIZED = true; openDeepLinkedStage(); }
  }
}

load();
"""

_JS = _FORM_JS + _PAGE_JS


def _lock_widget_html():
    """REV 3 §A5 -- the topbar lock, replacing the old "reading..." tape via
    shell.py's `header_html(tape_html=...)` parameter. All 3 states (not-
    configured / locked / unlocked) share this one markup; `load()`/
    `renderLock()` in `_PAGE_JS` mutate it in place -- no server round trip
    to render a state, only to VALIDATE a typed token (the existing POST
    /settings contract, see `handle_post`'s empty-change-set guard above).
    The inline SVG carries one <path id="lockshackle"> whose `d` attribute
    JS swaps between a closed and an ajar variant; no icon font/raster."""
    return (
        '<span class="lockwrap" id="lockwrap">'
        '<button class="locktrig" id="locktrig" aria-expanded="false" aria-haspopup="dialog" onclick="toggleLock()">'
        '<svg id="lockicon" width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">'
        '<rect x="2" y="5" width="8" height="5" rx="1" fill="currentColor"/>'
        '<path id="lockshackle" d="M4 5V4a2 2 0 014 0v1" stroke="currentColor" fill="none"/>'
        '</svg>'
        '<span id="locklabel">read-only</span>'
        '</button>'
        '<div class="lockpop" id="lockpop" hidden role="dialog" aria-label="Admin token">'
        '<div id="lockpopbody"></div>'
        '</div>'
        '</span>'
    )


def render_settings_html(app):
    body = f"""
<div id="restartbanner"></div>

{_pipeline_html()}
<div class="pcaption" id="pcaption"></div>

<section id="auditsec">
  <h2 class="section">Recent changes</h2>
  <div id="auditlist"><p class="muted">Loading&hellip;</p></div>
</section>

<div class="applybar" id="applybar"><div class="inner">
  <div class="diff" id="applydiff"></div>
  <button class="btn" onclick="reviewChanges()">Review</button>
  <button class="btn" onclick="discardChanges()">Discard all</button>
  <button class="btn primary" onclick="doApply()">Apply</button>
</div></div>
<div class="toast" id="toast"></div>
<div class="modal-backdrop" id="modalback"><div class="modal">
  <h3>Confirm change</h3>
  <p id="modalbody"></p>
  <div class="btns"><button class="btn" id="modalno">Cancel</button><button class="btn primary" id="modalyes">Apply</button></div>
</div></div>
<footer class="foot">Nuncio &middot; writes require the <code>NUNCIO_ADMIN_TOKEN</code> environment variable to be set (restart to apply)</footer>
"""
    return _page_shell(app, "Nuncio — Settings", body, extra_js=_JS, active="settings",
                        extra_css=_FORM_CSS + _PIPE_CSS, tape_html=_lock_widget_html()).encode()
