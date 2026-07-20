"""Shared row-rendering + edit/apply JavaScript for any settings-shaped
screen (currently the flat `/settings` page; a later vertical pipeline
screen will reuse the same machinery). Same construction rules as the rest
of `nuncio/web/`: a single inline, dependency-free string constant, no
build step.

This module knows how to render one editable key as a `.row` (label, input,
source/restart badges, lock/reset icons) and how to track/apply/confirm a
pending set of edits -- it does NOT know anything about page layout, group
ordering, or how a page wants to react to a dirty-state change. Two hooks
keep it page-agnostic:

- `sendApply(onDone)` posts the pending `DIRTY`/`RESET` state to `/settings`
  and, on a 200 response, clears that state and invokes the caller-supplied
  `onDone()` callback (e.g. to re-render an apply bar and reload data) --
  it does not assume any particular post-apply UI. On a 400 with a
  `data.errors` map it calls `showRowErrors` (below) to mark the offending
  rows inline and, if the page defines `onApplyRejected(firstKey)`, calls
  that too (e.g. to auto-open the stage holding the first bad key). `DIRTY`/
  `RESET` are only cleared on 200 -- a rejected apply leaves pending edits
  in place so nothing the operator typed is lost.
- `onEdit(...)` / `resetKey(...)` mutate `DIRTY`/`RESET` and then call a
  page-supplied `onDirtyChange()` hook to let the page re-render whatever
  it uses to reflect pending-change state (an apply bar today; something
  else in a future layout).
- `showRowErrors(errors)` renders a `{key: message}` map (the shape
  `apply_changes`'s `SettingsValidationError` produces) as inline `.row.err`
  state + a `.rowerr` message under each offending input; it clears any
  previous row errors first and returns the first offending key (or `null`).

Any page embedding `FORM_JS` in its own inline `<script>` MUST define, in
that same script and before a user can interact:

- `onDirtyChange()` -- called by `onEdit`/`resetKey` after every edit;
  `FORM_JS` never defines one.
- `load()` -- called after a successful unlock, to (re-)fetch and re-render
  the page's data. `promptToken()` itself no longer drives an unlock (REV 3
  §A5) -- it only opens the embedding page's `openLock()` UI, which is
  responsible for validating the token and calling `load()` on success.

A page MAY additionally define `lockInvalid()` -- `sendApply`'s 401 branch
(the server rejected the CURRENT token, e.g. it restarted with a new
`NUNCIO_ADMIN_TOKEN` while this tab still held the old one) calls it instead
of `promptToken()` when present, so the page can drop the dead token BEFORE
opening its lock UI -- otherwise the lock renders itself for the token that
was just rejected (still truthy) and lies about being "unlocked" at the
exact moment the server said otherwise. Falls back to `promptToken()` (i.e.
the existing open-on-current-state behavior) if the page doesn't define it,
so this stays backward compatible for any embedding page that hasn't opted
in.

A page MAY additionally define `onApplyRejected(firstKey)` -- `sendApply`
calls it (if present) after a 400 with `data.errors`, so the page can react
(e.g. open the stage containing `firstKey`). Optional: `sendApply` degrades
to a toast-only rejection if the page doesn't define it.

It also assumes the page's markup provides the modal + toast elements these
helpers drive by id: `#modalback`, `#modalbody`, `#modalyes`, `#modalno`
(used by `showModal`), and `#toast` (used by `toast`). The row CSS this
markup depends on lives in `nuncio/web/shell.py`'s `FORM_CSS`.
"""

FORM_JS = r"""
const esc = s => (s==null?'':String(s)).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let TOKEN = sessionStorage.getItem('nuncio_admin_token') || '';
// Set by the embedding page's load() from /settings.json's
// admin_token_configured. Defaults false (fail-closed) so a leftover
// sessionStorage token from another tab/instance can't enable inputs before
// the page has confirmed THIS instance actually has admin editing configured
// -- the server still 403s either way, but the UI shouldn't overpromise.
let ADMIN_TOKEN_CONFIGURED = false;
let KEYS = {};
let DIRTY = {};   // key -> new value (already typed) pending apply
let RESET = {};   // key -> true, pending reset-to-default

function fmtVal(k, spec) {
  if (spec.secret) return spec.value === '«sent»' || spec.value === '«set»' ? spec.value : '«unset»';
  if (spec.type === 'json') return JSON.stringify(spec.value);
  return spec.value == null ? '' : String(spec.value);
}

function inputHtml(k, spec) {
  const disabled = !(ADMIN_TOKEN_CONFIGURED && TOKEN) ? 'disabled' : '';
  if (!spec.editable) return '<span class="muted">' + esc(fmtVal(k, spec)) + '</span>';
  if (spec.type === 'bool') {
    const on = spec.value === true;
    return '<button type="button" class="toggle' + (on?' on':'') + '" ' + disabled +
           ' data-k="' + k + '" onclick="toggleBool(this, \'' + k + '\')"></button>';
  }
  if (spec.type === 'enum') {
    const opts = (spec.allowed||[]).map(o => '<option value="' + esc(o) + '"' +
      (o === spec.value ? ' selected' : '') + '>' + esc(o) + '</option>').join('');
    return '<select ' + disabled + ' data-k="' + k + '" onchange="onEdit(\'' + k + '\', this.value)">' + opts + '</select>';
  }
  if (spec.type === 'json') {
    return '<textarea ' + disabled + ' data-k="' + k + '" onchange="onEdit(\'' + k + '\', this.value, true)">' +
           esc(spec.secret ? '' : JSON.stringify(spec.value)) + '</textarea>';
  }
  const inputType = spec.secret ? 'password' : (spec.type === 'int' || spec.type === 'float' ? 'number' : 'text');
  const placeholder = spec.secret ? fmtVal(k, spec) : '';
  const step = spec.type === 'float' ? 'any' : '1';
  const bounds = (spec.type === 'int' || spec.type === 'float')
    ? ' min="' + (spec.min==null?'':spec.min) + '" max="' + (spec.max==null?'':spec.max) + '" step="' + step + '"' : '';
  return '<input type="' + inputType + '" ' + disabled + bounds +
         ' placeholder="' + esc(placeholder) + '" value="' + esc(spec.secret ? '' : fmtVal(k, spec)) + '"' +
         ' data-k="' + k + '" oninput="onEdit(\'' + k + '\', this.value)">';
}

function toggleBool(btn, k) {
  const now = !btn.classList.contains('on');
  btn.classList.toggle('on', now);
  onEdit(k, now);
}

function onEdit(k, value, isJson) {
  clearRowError(k);
  const spec = KEYS[k];
  if (isJson) {
    try { value = JSON.parse(value || 'null'); } catch (e) { /* left as string; server-side validation will 400 */ }
  } else if (spec.type === 'int') {
    value = value === '' ? '' : parseInt(value, 10);
  } else if (spec.type === 'float') {
    value = value === '' ? '' : parseFloat(value);
  } else if (spec.type === 'bool') {
    // already boolean
  }
  if (spec.secret && value === '') { delete DIRTY[k]; } else { DIRTY[k] = value; }
  delete RESET[k];
  onDirtyChange();
}

function resetKey(k) {
  RESET[k] = true;
  delete DIRTY[k];
  onDirtyChange();
}

function needsConfirm() {
  return Object.keys(DIRTY).some(k => KEYS[k].confirm) || Object.keys(RESET).some(k => KEYS[k] && KEYS[k].confirm);
}

function showModal(msg, onYes) {
  const back = document.getElementById('modalback');
  document.getElementById('modalbody').textContent = msg;
  back.classList.add('show');
  document.getElementById('modalyes').onclick = () => { back.classList.remove('show'); onYes(); };
  document.getElementById('modalno').onclick = () => back.classList.remove('show');
}

function clearRowError(k) {
  const input = document.querySelector('[data-k="' + k + '"]');
  if (!input) return;
  const row = input.closest('.row');
  if (row) row.classList.remove('err');
  const sib = input.nextElementSibling;
  if (sib && sib.classList.contains('rowerr')) sib.remove();
}

function clearRowErrors() {
  document.querySelectorAll('.row.err').forEach(row => {
    row.classList.remove('err');
    row.querySelectorAll('.rowerr').forEach(el => el.remove());
  });
}

function showRowErrors(errors) {
  clearRowErrors();
  let first = null;
  Object.entries(errors || {}).forEach(([k, msg]) => {
    if (first === null) first = k;
    const input = document.querySelector('[data-k="' + k + '"]');
    if (!input) return;
    const row = input.closest('.row');
    if (row) row.classList.add('err');
    const div = document.createElement('div');
    div.className = 'rowerr';
    div.textContent = msg;
    input.insertAdjacentElement('afterend', div);
  });
  return first;
}

async function sendApply(onDone) {
  clearRowErrors();
  const body = { set: DIRTY, reset: Object.keys(RESET) };
  try {
    const r = await fetch('/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Token': TOKEN },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    if (r.status === 200) {
      const applied = data.applied || [];
      const restart = data.restart_required || [];
      let msg;
      if (applied.length) {
        msg = 'Applied: ' + applied.join(', ') + (restart.length ? ' · restart required: ' + restart.join(', ') : '');
      } else if (restart.length) {
        // Everything set this round was restart-category -- "Applied: ·
        // restart required: ..." reads as if nothing happened.
        msg = 'Saved — restart required: ' + restart.join(', ');
      } else {
        msg = 'Saved.';
      }
      toast(msg);
      DIRTY = {}; RESET = {};
      onDone();
    } else if (r.status === 401) {
      toast('Invalid admin token.');
      // C2: drop the just-rejected token before reopening the lock (see docstring).
      if (typeof lockInvalid === 'function') lockInvalid(); else promptToken();
    } else if (data.errors) {
      const firstKey = showRowErrors(data.errors);
      if (typeof onApplyRejected === 'function') onApplyRejected(firstKey);
      if (data.errors['_']) toast(data.errors['_']);  // no row to highlight
      else toast('Some changes were rejected — see the highlighted fields.');
    } else {
      toast('Rejected: ' + (data.error || 'apply failed'));
    }
  } catch (e) {
    toast('Request failed: ' + e);
  }
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 6000);
}

function promptToken() {
  // §A5: delegates to the embedding page's lock UI (settings.py's openLock).
  if (typeof openLock === 'function') { openLock(); return; }
  console.warn('promptToken: no openLock() on this page.');
}

function groupRows(names, data) {
  return names.map(k => {
    const spec = data.keys[k];
    if (!spec) return '';
    const lock = !spec.editable ? '<span class="lock" title="' + esc(spec.reason||'') + '">&#128274;</span>' : '';
    const restartBadge = spec.restart_required ? '<span class="badge-restart">restart</span>' : '';
    const src = spec.source || 'default';
    const resetBtn = (spec.editable && src === 'override')
      ? '<button class="iconbtn" onclick="resetKey(\'' + k + '\')" title="reset to default">&#8630;</button>' : '';
    // Help + (locked) reason share one hover/focus/tap tooltip; the label
    // itself is the keyboard tab stop since locked rows have no input.
    const tipText = [spec.help, !spec.editable ? spec.reason : ''].filter(Boolean).join(' — ');
    const helpAttr = tipText ? ' data-help="' + esc(tipText) + '"' : '';
    const lblFocus = (!spec.editable && tipText) ? ' tabindex="0"' : '';
    return '<div class="row">' +
      '<div class="lbl"' + helpAttr + lblFocus + '>' + esc(spec.label || k) + '<span class="k">' + esc(k) + '</span></div>' +
      '<div>' + inputHtml(k, spec) + '</div>' +
      '<div class="rowbtns"><span class="badge-src ' + src + '">' + src + '</span>' + restartBadge + '</div>' +
      '<div class="rowbtns">' + lock + resetBtn + '</div>' +
      '</div>';
  }).join('');
}

// One delegated click listener drives the tap-to-toggle tooltip for touch
// users (hover/`:focus-within` already cover mouse + keyboard in CSS --
// see nuncio/web/shell.py's FORM_CSS). Tapping a labelled row toggles its
// `.tip` class; tapping anywhere else clears whatever was open.
document.addEventListener('click', function (e) {
  const lbl = e.target.closest && e.target.closest('.lbl[data-help]');
  document.querySelectorAll('.lbl.tip').forEach(el => { if (el !== lbl) el.classList.remove('tip'); });
  if (lbl) lbl.classList.toggle('tip');
});
"""
