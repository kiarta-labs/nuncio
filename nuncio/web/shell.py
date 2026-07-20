"""Shared page shell for the web UI -- inline CSS + header/nav emitted once
and reused by every screen (dashboard, settings) so the whole app reads as
one product rather than a collection of pages. Dependency-free, theme-aware
(`prefers-color-scheme` + an explicit `data-theme` override), no fonts/CDN/
build step -- same construction rules as the rest of nuncio/web/.

Palette concept: "the instrument" -- a petrol/verdigris control-room read,
not a generic SaaS purple. Every color is a *signal*: verdigris (trace) means
enriched/ok/accent, amber (raw) means a fallback/warn, flare (breach) means a
failure. `--accent`/`--amber`/`--red` remain as aliases of `--trace`/`--raw`/
`--breach` so the settings screen's existing CSS below the `/* settings */`
marker retints for free without touching its markup or class names.
"""
import re
from html import escape as _esc

_CSS_SOURCE = """
:root, :root[data-theme="dark"] {
  --bg:#0F1717; --surface:#161F1E; --border:#25322F; --text:#E8EDE9;
  --edge:#22302A; --raise:rgba(255,255,255,.035); --ink2:#8FA39B; --muted:var(--ink2);
  --trace:#45B597; --trace-hi:#6FCDB6; --trace-dim:rgba(69,181,151,.12);
  --raw:#E0A83E; --raw-dim:rgba(224,168,62,.12);
  --breach:#E0604D; --grey:#5E6F6A;
  --accent:var(--trace); --accent-dim:var(--trace-dim);
  --amber:var(--raw); --amber-dim:var(--raw-dim);
  --red:var(--breach);
  --halo:0 0 0 4px var(--trace-dim); --dur:.24s; --dur-fast:.16s;
  --easing:cubic-bezier(.22,.75,.25,1);
  /* REV 3 pipeline-hero additions -- circuit identity + glow, nothing
     decorative. Enrich reuses --trace/--trace-dim (the heart of the run
     wears the brand color); the global/chassis stage reuses --grey, so it
     gets no dedicated token either. See shell.py's PIPE_CSS §A2 plumbing
     (.st-intake/.st-context/.st-enrich/.st-deliver/.st-global) for how
     these become the LOCAL --st/--st-dim/--st-next each diagram rule
     paints with. */
  --st-intake:#4EA0D0; --st-intake-dim:rgba(78,160,208,.14);
  --st-context:#3EC1C9; --st-context-dim:rgba(62,193,201,.14);
  --st-deliver:#86C96B; --st-deliver-dim:rgba(134,201,107,.14);
  --glow:0 0 22px; /* the ONE glow recipe: `var(--glow) var(--st-dim)`,
                      box-shadow only, layered under the resting halo ring --
                      never `filter:`, never on an always-animating element.
                      REV 3 Phase D prominence bump (18px -> 22px, the one
                      token every node's glow is composed from). */
}
:root {
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  --serif:Charter,"Iowan Old Style",Georgia,Cambria,serif;
}
@media (prefers-color-scheme:light) {
  :root { --bg:#F5F7F5; --surface:#FFFFFF; --border:#DCE2DC; --text:#1B2321;
          --edge:#D9E2DD; --raise:rgba(0,0,0,.03); --ink2:#5C6E66; --muted:var(--ink2);
          --trace:#177B66; --trace-hi:#0F5F4E; --trace-dim:rgba(23,123,102,.08);
          --raw:#9A6A08; --raw-dim:rgba(154,106,8,.08);
          --breach:#C13E2C; --grey:#7E8B86;
          --accent:var(--trace); --accent-dim:var(--trace-dim);
          --amber:var(--raw); --amber-dim:var(--raw-dim);
          --red:var(--breach);
          --halo:0 0 0 4px var(--trace-dim); --dur:.24s; --dur-fast:.16s;
          --easing:cubic-bezier(.22,.75,.25,1);
          --st-intake:#20719F; --st-intake-dim:rgba(32,113,159,.09);
          --st-context:#0F7E86; --st-context-dim:rgba(15,126,134,.09);
          --st-deliver:#52803D; --st-deliver-dim:rgba(82,128,61,.09);
          --glow:0 0 22px; }
}
:root[data-theme="light"] {
  --bg:#F5F7F5; --surface:#FFFFFF; --border:#DCE2DC; --text:#1B2321;
  --edge:#D9E2DD; --raise:rgba(0,0,0,.03); --ink2:#5C6E66; --muted:var(--ink2);
  --trace:#177B66; --trace-hi:#0F5F4E; --trace-dim:rgba(23,123,102,.08);
  --raw:#9A6A08; --raw-dim:rgba(154,106,8,.08);
  --breach:#C13E2C; --grey:#7E8B86;
  --accent:var(--trace); --accent-dim:var(--trace-dim);
  --amber:var(--raw); --amber-dim:var(--raw-dim);
  --red:var(--breach);
  --halo:0 0 0 4px var(--trace-dim); --dur:.24s; --dur-fast:.16s;
  --easing:cubic-bezier(.22,.75,.25,1);
  --st-intake:#20719F; --st-intake-dim:rgba(32,113,159,.09);
  --st-context:#0F7E86; --st-context-dim:rgba(15,126,134,.09);
  --st-deliver:#52803D; --st-deliver-dim:rgba(82,128,61,.09);
  --glow:0 0 22px;
}
* { box-sizing:border-box; }
html,body { background:var(--bg); color:var(--text); font-family:var(--sans); margin:0; }
body { padding:0 0 48px; font-size:13.5px; line-height:1.5; font-weight:400; }
a { color:var(--trace); }
a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible,
textarea:focus-visible, summary:focus-visible, .toggle:focus-visible {
  outline:2px solid var(--trace); outline-offset:2px;
}
.wrap { max-width:1180px; margin:0 auto; padding:0 20px; }
.topbar { border-bottom:1px solid var(--edge); background:var(--bg); position:sticky; top:0; z-index:5; }
.topbar .row { display:flex; align-items:center; height:52px; }
.mark { flex:none; display:block; width:24px; height:24px; border-radius:50%; object-fit:contain; background:#fff; box-sizing:border-box; }
.mark path { stroke-linecap:round; }
.mark circle { fill:var(--trace); }
.wordmark { font-family:var(--serif); font-weight:700; font-size:19px; margin-left:10px; color:var(--text); }
.rule { width:1px; height:20px; background:var(--edge); margin:0 16px; flex:none; }
.tape { font-family:var(--mono); font-size:11px; letter-spacing:.04em; color:var(--ink2);
  text-transform:uppercase; white-space:nowrap; overflow:hidden; }
.tape b { color:var(--text); font-weight:400; text-transform:none; }
.tape .bad { color:var(--breach); font-weight:700; }
.tape .warn { color:var(--raw); }
nav.mainnav { margin-left:auto; display:flex; gap:24px; height:100%; }
nav.mainnav a { display:flex; align-items:center; height:100%; color:var(--ink2); text-decoration:none;
  font-family:var(--mono); text-transform:uppercase; font-size:11px; letter-spacing:.08em;
  border-bottom:2px solid transparent; }
nav.mainnav a.active, nav.mainnav a:hover { color:var(--text); }
nav.mainnav a.active { border-bottom-color:var(--trace); }
nav.mainnav a.disabled { opacity:.35; pointer-events:none; }

h2.section { font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.12em;
  color:var(--text); margin:40px 0 12px; font-weight:600; display:flex; align-items:center; }
h2.section::before { content:""; width:14px; height:2px; background:var(--trace); display:inline-block;
  margin-right:8px; vertical-align:middle; flex:none; }
h2.section .q { color:var(--ink2); font-weight:400; margin-left:5px; }
.rule-full { border:none; border-top:1px solid var(--edge); margin:72px 0 0; }

/* verdict */
.verdict { font-family:var(--serif); font-size:clamp(24px,3.2vw,36px); line-height:1.25;
  margin:18px 0 26px; max-width:900px; font-weight:400; }
.verdict strong { color:var(--trace-hi); font-weight:600; }
.verdict .bad { color:var(--breach); font-weight:600; }
.verdict .nw { white-space:nowrap; }

/* signal path -- a continuous spine (svg) under a row of stage labels, with
   a diverging/rejoining amber fallback rail and a dead-end shed stub;
   geometry drawn by layoutSigPath() in the page JS so nodes always land
   exactly under their labels (see nuncio/web/dashboard.py). */
.sigpath { position:relative; padding:14px 0 8px; min-height:100px; }
.sigpath .stagerow { display:grid; grid-template-columns:repeat(4,1fr); gap:0; position:relative; z-index:1; }
.sigpath .stage { padding:0 14px 0 0; font-size:12.5px; }
.sigpath .n { font-family:var(--mono); font-size:10px; color:var(--trace); display:block; margin-bottom:4px; }
.sigpath .stage b { font-family:var(--mono); font-variant-numeric:tabular-nums; font-size:14px; }
.sigpath .muted { color:var(--muted); font-size:12px; }
.sigpath-svg { display:block; width:100%; height:58px; overflow:visible; }
.sigpath-svg .spine, .sigpath-svg .conn, .sigpath-svg .node { stroke:var(--trace); fill:var(--trace); }
.sigpath-svg .spine { stroke-width:2; }
.sigpath-svg .conn { opacity:.4; }
.sigpath-svg .junction { fill:var(--bg); stroke:var(--raw); stroke-width:1.5; }
.sigpath-svg .rail, .sigpath-svg .merge { stroke:var(--raw); fill:var(--raw); }
.sigpath-svg .rail { fill:none; stroke-width:2; }
.sigpath-svg .stub { fill:none; stroke:var(--muted); stroke-width:2; }
.sigpath-tag { position:absolute; font-family:var(--mono); font-size:11px; color:var(--muted); white-space:nowrap; }
.sigpath-tag.raw { color:var(--raw); transform:translateX(-50%); }

/* invariant chips */
.chips { display:flex; flex-wrap:wrap; gap:10px; }
.chip { font-family:var(--mono); font-size:12.5px; padding:8px 14px; background:var(--surface);
  border:1px solid var(--border); border-left:3px solid var(--grey); border-radius:8px; min-width:120px; }
.chip .label { display:block; color:var(--muted); text-transform:uppercase; font-size:10.5px;
  letter-spacing:.06em; margin-bottom:3px; }
.chip .val { font-size:15px; font-variant-numeric:tabular-nums; }
.chip.ok { border-left-color:var(--trace); }
.chip.ok .val { color:var(--trace-hi); }
.chip.warn { border-left-color:var(--raw); }
.chip.warn .val { color:var(--raw); }
.chip.bad { border-left-color:var(--breach); }
.chip.bad .val { color:var(--breach); }

/* strip chart */
.stripchart { width:100%; height:72px; display:block; }
.axis { display:flex; justify-content:space-between; font-family:var(--mono); font-size:10.5px; color:var(--muted); }
.stormcap { fill:var(--breach); }

.rail { display:flex; border-top:1px solid var(--edge); border-bottom:1px solid var(--edge); margin-top:12px; }
.rail .c3 { flex:1; min-width:0; padding:12px 16px; border-left:1px solid var(--edge); }
.rail .c3:first-child { border-left:none; }
.rail .c3 .label { font-size:10px; text-transform:uppercase; letter-spacing:.07em; color:var(--ink2); }
.rail .c3 .value { font-family:var(--mono); font-size:22px; font-weight:700; margin-top:5px;
  font-variant-numeric:tabular-nums; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.rail .c3 .sub { font-size:11px; color:var(--ink2); margin-top:4px; font-family:var(--mono); }
.rail .c3 .delta { font-family:var(--mono); font-size:11px; margin-top:4px; }
.rail .delta.up-good, .rail .delta.down-good { color:var(--trace-hi); }
.rail .delta.up-bad, .rail .delta.down-bad { color:var(--raw); }
.rail .c3.twn .value { color:var(--raw); }
.counters { font-family:var(--mono); font-size:11px; color:var(--ink2); margin-top:10px; }
.counters .amber { color:var(--raw); }

.strip { display:flex; flex-wrap:wrap; gap:8px; }
.pill { display:inline-flex; align-items:center; padding:4px 10px; font-size:12px; font-family:var(--mono);
  border:1px solid var(--edge); box-shadow:inset 3px 0 0 var(--ink2); }
.pill.enriched { color:var(--trace); box-shadow:inset 3px 0 0 var(--trace); }
.pill.raw { color:var(--raw); box-shadow:inset 3px 0 0 var(--raw); }
.pill.fail { color:var(--breach); box-shadow:inset 3px 0 0 var(--breach); }
.pill.null, .pill.off { color:var(--ink2); opacity:.45; }

/* bar-list breakdowns */
.barlist { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:6px 14px; }
.barlist .barrow { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:10px; align-items:center;
  padding:8px 0; border-bottom:1px solid var(--border); }
.barlist .barrow:last-child { border-bottom:none; }
.barlist .barlabel { font-family:var(--mono); font-size:12.5px; overflow:hidden; text-overflow:ellipsis;
  white-space:nowrap; }
.barlist .barcount { font-family:var(--mono); font-size:12.5px; font-variant-numeric:tabular-nums;
  color:var(--muted); text-align:right; }
.barlist .bar { grid-column:1/-1; height:3px; background:var(--trace); border-radius:2px; opacity:.55;
  margin-top:2px; }
.barlist .barrow.fail .bar { background:var(--breach); opacity:.7; }
.barlist .barrow.sev-critical .bar { background:var(--breach); }
.barlist .barrow.sev-warning .bar { background:var(--raw); }
.barlist .barrow.sev-info .bar { background:var(--muted); }
.barlist .empty { padding:12px 0; color:var(--muted); font-size:12.5px; }

/* recurring signatures */
.sigrow { display:flex; align-items:baseline; gap:10px; padding:8px 0; border-bottom:1px solid var(--border);
  font-size:12.5px; }
.sigrow:last-child { border-bottom:none; }
.sigrow .sigcount { font-family:var(--mono); color:var(--trace-hi); font-weight:600; flex:none; }
.sigrow .sigsummary { font-family:var(--mono); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; }
.sigrow .sigmeta { color:var(--muted); font-size:11px; flex:none; }

.label { font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
.grid2 { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }

/* subjects (24h) */
.sjb { display:grid; grid-template-columns:3fr 2fr; gap:24px; margin-top:6px; }
@media (max-width:860px) { .sjb { grid-template-columns:1fr; } }
.sl { font-size:10px; color:var(--ink2); margin-bottom:6px; }
.nsb { color:var(--raw); font-weight:700; }
.hr { display:grid; grid-template-columns:110px 36px 44px 120px 66px 60px; gap:10px;
  align-items:center; height:34px; border-bottom:1px solid var(--edge); }
.hr:last-child { border-bottom:none; }
.hr>span { font-family:var(--mono); }
.hr .hh { font-size:13px; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.hr .hn { font-size:15px; font-weight:700; text-align:right; }
.hr .htr { font-size:10px; text-align:right; color:var(--ink2); }
.hr .htr.up { color:var(--raw); }
.hr .htr.down { color:var(--trace); }
.hr .htr.new { color:var(--raw); font-weight:700; }
.hr .hmx { font-size:10px; color:var(--ink2); white-space:nowrap; }
.hr .hen { font-size:11px; text-align:right; color:var(--trace); }
.hr .hen.low { color:var(--raw); }
.sg { margin-top:20px; }
.sg .row, .sg .axisrow { display:flex; align-items:center; gap:8px; height:14px; margin-bottom:4px; }
.sg .sr { font-family:var(--mono); font-size:11px; color:var(--ink2); width:110px; flex:none;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.sg .chart { flex:1; min-width:0; }
.sg .chart svg { display:block; width:100%; height:10px; }
.sg .axisrow { margin-top:6px; }
.sg .axisrow .axis { flex:1; }

table { width:100%; border-collapse:collapse; font-size:13px; font-variant-numeric:tabular-nums; }
th { text-align:left; color:var(--ink2); font-weight:500; text-transform:uppercase; font-size:10px;
  letter-spacing:.1em; padding:8px 12px; border-bottom:1px solid var(--edge); }
td { padding:10px 12px; border-bottom:1px solid var(--edge); font-family:var(--mono); font-size:12.5px; }
th.num, td.num { font-variant-numeric:tabular-nums; white-space:nowrap; text-align:right; }
.tablewrap { background:var(--surface); border:1px solid var(--edge); overflow:auto; }
.tablewrap.wide table { min-width:760px; }
tr.dv td { padding:16px 12px 6px; border-bottom:none; display:flex; align-items:center; gap:10px;
  font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.12em; color:var(--ink2); }
tr.dv .dvr { flex:1; height:1px; background:var(--edge); }
tr.arow { cursor:pointer; --sc:var(--ink2); box-shadow:inset 2px 0 0 color-mix(in srgb,var(--sc) 45%,transparent); }
tr.arow.sev-crit { --sc:var(--breach); }
tr.arow.sev-warn { --sc:var(--raw); }
tr.arow:hover, tr.arow:focus-visible { background:var(--raise); box-shadow:inset 2px 0 0 var(--sc); outline:none; }
tr.arow:focus-visible { outline:1px solid var(--trace); outline-offset:-1px; }
td.sj b { color:var(--text); font-weight:700; }
td.sev.crit { color:var(--breach); }
td.sev.warn { color:var(--raw); }
td.sev.info { color:var(--ink2); }
td.oc .enr { color:var(--trace); text-transform:lowercase; }
td.oc .rwc { text-transform:uppercase; font-size:10px; color:var(--raw);
  border:1px solid color-mix(in srgb,var(--raw) 30%,transparent); padding:1px 6px; }
td.lat.slow { color:var(--raw); }
@media (max-width:860px) { .c2 { display:none; } }
@media (max-width:700px) {
  .cs { display:none; }
  td.sj { max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
}
.muted { color:var(--muted); }
footer.foot { color:var(--muted); font-size:11px; margin-top:40px; text-align:center; }

"""

# Alert-detail-page-only rules (the /alert/<key> drill-down), kept out of the
# shared CSS above and injected via page_shell(extra_css=DETAIL_CSS) only on
# that screen -- the dashboard never references these classes (it uses .rail
# instead of .card, has no <pre>/kv/stageblock at all), so shipping them
# there would be dead weight against its byte budget. Same technique as
# SETTINGS_CSS below.
_DETAIL_CSS_SOURCE = """
.card { background:var(--surface); border:1px solid var(--edge); padding:12px 14px; min-width:0; }
.kv { display:grid; grid-template-columns:max-content 1fr; gap:6px 14px; font-family:var(--mono); font-size:13px; }
.kv dt { color:var(--muted); text-transform:uppercase; font-size:10.5px; letter-spacing:.05em; align-self:center; }
pre.block { background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:14px 16px; font-family:var(--mono); font-size:12.5px; white-space:pre-wrap;
  word-break:break-word; max-height:480px; overflow:auto; }
.stageblock .n { font-family:var(--mono); font-size:10px; color:var(--trace); }
.back { display:inline-block; margin-bottom:16px; font-size:13px; }
.headline { font-family:var(--serif); font-size:20px; line-height:1.3; }
"""

# Row-level form rules, shared by any settings-shaped screen (currently the
# flat /settings page; a later vertical pipeline screen reuses the same
# `.row`/input/badge/modal markup emitted by nuncio/web/forms.py's FORM_JS).
# Kept out of the shared _CSS_SOURCE above and injected via
# page_shell(extra_css=FORM_CSS + ...) only on screens that embed FORM_JS --
# the dashboard and alert-detail screens never reference these classes, so
# shipping them there would just be dead weight against the size budget.
_FORM_CSS_SOURCE = """
.banner { border:1px solid var(--border); border-radius:10px; padding:12px 16px; margin:16px 0;
  font-size:13px; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.banner.warn { border-color:var(--amber); background:var(--amber-dim); color:var(--text); }
.banner.info { border-color:var(--accent); background:var(--accent-dim); color:var(--text); }
.banner code, .lockpop code { font-family:var(--mono); background:var(--surface); padding:1px 6px; border-radius:5px; }
.row { display:grid; grid-template-columns:1fr 1.4fr auto auto; gap:10px 14px; align-items:center;
  padding:11px 16px; border-bottom:1px solid var(--border); }
.row:last-child { border-bottom:none; }
.row .lbl { font-size:12.5px; }
.row .lbl .k { display:block; font-family:var(--mono); font-size:10.5px; color:var(--muted); margin-top:2px;
  text-decoration:none; }
.row .lbl[data-help] { position:relative; cursor:help; text-decoration:underline dotted;
  text-decoration-color:var(--edge); text-decoration-thickness:1px; text-underline-offset:3px; }
.row .lbl[data-help]:hover, .row:focus-within .lbl[data-help], .row .lbl[data-help].tip {
  text-decoration-style:solid; text-decoration-color:var(--muted); }
.row .lbl[data-help]:hover::after, .row:focus-within .lbl[data-help]::after,
.row .lbl[data-help]:focus-visible::after, .row .lbl[data-help].tip::after {
  content:attr(data-help); position:absolute; left:-2px; bottom:calc(100% + 6px); z-index:5;
  background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:8px 10px;
  font-size:12px; line-height:1.4; color:var(--text); width:max-content; max-width:320px;
  white-space:normal; box-shadow:0 8px 24px rgba(0,0,0,.25); pointer-events:none; }
/* §4b: locked labels are a brand-new tab stop (no wrapping input for
   :focus-within to key off) -- give it a visible keyboard-only ring. */
.row .lbl[data-help]:focus-visible { outline:1px solid var(--muted); outline-offset:3px; }
.row input[type=text], .row input[type=password], .row input[type=number], .row select, .row textarea {
  width:100%; background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:7px;
  padding:7px 9px; font-family:var(--mono); font-size:12.5px; }
.row textarea { min-height:52px; resize:vertical; }
.row input:disabled, .row select:disabled, .row textarea:disabled { opacity:.55; cursor:not-allowed; }
.row.err { box-shadow:inset 3px 0 0 var(--breach); }
.rowerr { color:var(--breach); font-size:11px; margin-top:4px; }
.toggle { position:relative; width:38px; height:21px; border-radius:11px; background:var(--border);
  border:none; cursor:pointer; flex:none; }
.toggle::after { content:""; position:absolute; top:2px; left:2px; width:17px; height:17px; border-radius:50%;
  background:var(--surface); transition:left .15s; }
.toggle.on { background:var(--accent); }
.toggle.on::after { left:19px; background:#fff; }
.badge-src { font-size:10px; font-family:var(--mono); padding:2px 7px; border-radius:999px; border:1px solid var(--border); }
.badge-src.default { color:var(--grey); border-color:var(--grey); }
.badge-src.env { color:var(--accent); border-color:var(--accent); }
.badge-src.override { color:var(--amber); border-color:var(--amber); }
.badge-restart { font-size:10px; font-family:var(--mono); padding:2px 7px; border-radius:999px;
  color:var(--red); border:1px solid var(--red); margin-left:6px; }
.rowbtns { display:flex; align-items:center; gap:8px; }
.iconbtn { background:none; border:1px solid var(--border); color:var(--muted); border-radius:6px;
  padding:5px 8px; font-size:11px; cursor:pointer; font-family:var(--mono); }
.iconbtn:hover { color:var(--text); border-color:var(--accent); }
.btn { border:1px solid var(--border); background:var(--bg); color:var(--text); border-radius:7px;
  padding:8px 16px; font-size:13px; cursor:pointer; font-family:var(--sans); }
.btn.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
.btn:disabled { opacity:.5; cursor:not-allowed; }
.toast { position:fixed; right:20px; bottom:70px; z-index:9; background:var(--surface);
  border:1px solid var(--border); border-radius:10px; padding:12px 16px; font-size:12.5px;
  max-width:360px; box-shadow:0 8px 24px rgba(0,0,0,.25); display:none; }
.toast.show { display:block; }
.modal-backdrop { position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:10; display:none;
  align-items:center; justify-content:center; }
.modal-backdrop.show { display:flex; }
.modal { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:20px;
  max-width:420px; width:90%; }
.modal h3 { margin:0 0 10px; font-size:14px; }
.modal p { font-size:13px; color:var(--muted); line-height:1.5; }
.modal .btns { display:flex; justify-content:flex-end; gap:10px; margin-top:16px; }
.applybar { position:fixed; left:0; right:0; bottom:0; z-index:8; background:var(--surface);
  border-top:1px solid var(--border); padding:12px 20px; display:none; }
.applybar.show { display:block; }
.applybar .inner { max-width:1180px; margin:0 auto; display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
.applybar .diff { flex:1; font-size:12px; color:var(--muted); font-family:var(--mono); }

/* §A5 topbar lock -- .lockpop's own z-index:8 is academic in practice: it
   lives inside .topbar's sticky stacking context (z-index:5), so toast(9)/
   applybar(8)/modal(10) all paint above it regardless of this value (M7) --
   no overlap occurs today since the popover is
   top-anchored and those three are all bottom-fixed, but don't read this
   number as "the popover out-ranks applybar/toast site-wide". */
.lockwrap { position:relative; }
.locktrig { display:flex; align-items:center; gap:6px; background:none; border:none;
  color:var(--ink2); font-family:var(--mono); font-size:11px; cursor:pointer; padding:4px 8px; }
.locktrig:hover, .locktrig:focus-visible { background:var(--raise); color:var(--text); }
.locktrig.unlocked { color:var(--trace); box-shadow:0 0 0 3px var(--trace-dim); }
.lockpop { position:absolute; top:calc(100% + 10px); left:0; z-index:8; width:260px;
  background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:14px 16px; font-size:12.5px; box-shadow:0 8px 24px rgba(0,0,0,.25); }
.lockpop[hidden] { display:none; }
.lockpop input { width:100%; background:var(--bg); color:var(--text); border:1px solid var(--border);
  padding:7px 9px; font-family:var(--mono); font-size:12.5px; margin-bottom:10px; }
.pcaption { font-family:var(--mono); font-size:12px; color:var(--ink2); margin:10px 0 28px; }
"""

# The vertical settings pipeline (nuncio/web/settings.py's render_settings_html):
# a CSS-grid "wiring run" down the left edge of the page -- .prail is the
# spine+node column, .pstage is the per-stage header+body column. Structural
# only in this phase (no expand/collapse transition -- that's a later phase;
# see the .pbody-wrap/.open comment below); hover/focus states ARE included
# here since they're pure :hover/:focus-visible CSS, not JS-driven interaction.
# Injected via page_shell(extra_css=FORM_CSS + PIPE_CSS) only on the settings
# page -- FORM_CSS still supplies the shared .row/banner/badge/modal/toast
# chrome a stage body renders into once Phase 3 fills it.
_PIPE_CSS_SOURCE = """
/* REV 3 hero grid (supersedes the flat 44px rail): four tracks, three of
   them populated per stage row (.pworld/.prail/.pstage -- see
   _pipeline_html() in settings.py), the fourth ("void") deliberately left
   empty -- honest empty space, not a fake fourth column of content. Cells
   are pinned to an explicit `grid-column` (below) rather than relying on
   auto-flow, because auto-flow would walk all four tracks in DOM order and
   misalign every stage after the first the moment a row supplies fewer
   items than there are tracks. */
.pipeline { display:grid;
  grid-template-columns:[world] minmax(48px,15%) [rail] 128px [main] minmax(0,660px) [void] 1fr; }
.pworld { grid-column:1; position:relative; min-height:1px; }
.prail { grid-column:2; position:relative; }
.pstage { grid-column:3; }
/* Phase E fan-in/fan-out SVG (renderFans() in settings.py) -- viewBox-scaled
   to the cell width; pointer-events:none keeps the .pworld click-forward
   listener working; fixed height (not 100%) since .pworld spans the row's
   full open-body height, not just the header band. */
.pworld svg { position:absolute; top:0; left:0; width:calc(100% + 48px); height:60px; overflow:visible; pointer-events:none; }
/* §6b: adapter/channel labels are positioned HTML, not SVG <text> (SVG text
   under the viewBox's non-uniform scale stretched ~1.5x horizontally) --
   quiet, small, grey furniture subordinate to the glowing nodes; only the
   highlighted default source brightens to its own stage color. */
.fanlbl { position:absolute; left:2px; max-width:90%; font-family:var(--mono); font-size:9px; line-height:1;
  color:var(--ink2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; pointer-events:none;
  background:var(--bg); padding:0 2px; }
.pmeta .fanchip { color:var(--ink2); }

/* Conductor -- a per-segment graded loom: each .prail paints its OWN
   `--st -> --st-next` gradient (set by the st-* plumbing classes below), so
   the run reads as one continuous blue-to-leaf gradient rather than flat
   per-stage stripes. §1(c) twin-hairline bus: the box-shadow is TWO more
   copies of the 3px core (negative-spread, +-5px) plus the ambient glow --
   a three-strand loom from one element, no new DOM/gradient banding. Core
   stays 3px (A8: a fatter core reads cable-TV, not instrument). */
.prail::before { content:""; position:absolute; left:50%; top:0; bottom:0; width:3px;
  background-image:linear-gradient(180deg,var(--st),var(--st-next)); transform:translateX(-50%);
  box-shadow:5px 0 0 -1px var(--st-dim), -5px 0 0 -1px var(--st-dim), 0 0 10px var(--st-dim); }
.pipeline>.prail:first-child::before { top:34px; }
/* The terminal (global) stage's rail cell is NOT the grid's last child --
   .pipeline is a flat pworld/prail/pstage/... sequence, so a plain
   `:last-child` selector on .prail never matches it. `.prail-term` is
   applied explicitly (in _pipeline_html()) instead, so the spine truncates
   at the terminal square's midline (the same 34px offset the intake rail's
   `:first-child` rule truncates FROM) rather than running the row's full
   height past it. */
.prail-term::before { bottom:auto; height:34px; }
/* §1(b) junction take-off stub -- the classic schematic "this conductor
   feeds that device" tap, node east edge toward the stage nameplate. `top`
   is the SAME node-center offset as .pnode/:first-child/.prail-term above
   (locked together, §4); `left` starts just outside the §1(a) echo ring
   (32px node -> `+32px`); `right:6px` stops short of the main-column seam
   so the stub points at the title without touching it. Runs on the
   terminal row too -- `--st` there is chassis grey via .st-global, so the
   stub is grey there for free, zero extra rule. */
.prail::after { content:""; position:absolute; top:34px; left:calc(50% + 32px); right:6px;
  height:2px; background:var(--st); opacity:.4; transform:translateY(-50%); }

/* Node -- 32px ring (2.5px --st border, --bg fill) + a 10px solid --st
   center dot (::after), resting in its own quiet pool of light: a tight
   halo ring plus the one glow recipe (--glow), both keyed off --st-dim so a
   sick node glows breach/amber, never the circuit hue, for free. §4
   prominence bump: 28px->32px node, 9px->10px dot, 3px->4px resting halo
   (open state below goes 4px->5px) -- .ptitle stays 20px, the core stays
   3px (A8 ceiling). The terminal stays a plain square outline (14px,
   --grey, no center dot -- the chassis mark). */
.pnode { position:absolute; left:50%; top:34px; width:32px; height:32px; border-radius:50%;
  border:2.5px solid var(--st); background:var(--bg); transform:translate(-50%,-50%);
  box-shadow:0 0 0 4px var(--st-dim), var(--glow) var(--st-dim);
  display:flex; align-items:center; justify-content:center; }
/* §1(a) radar echo -- the brand motif: one faint concentric ring on every
   STAGE node (not the terminal chassis square), echoing the radar/bird
   logo. Paints with the node's own --st, so health overrides and the
   .nodehover scale carry through for free -- it's a pseudo of the element
   that scales. Solid, not dashed (a dashed circle at this radius reads as
   perforation, not radar). */
.pnode::before { content:""; position:absolute; inset:-10px; border-radius:50%;
  border:1px solid var(--st); opacity:.22; }
.pnode::after { content:""; width:10px; height:10px; border-radius:50%; background:var(--st); }
.pnode.pterm { border-radius:2px; width:14px; height:14px; border-color:var(--grey); box-shadow:none; }
.pnode.pterm::before { content:none; }
.pnode.pterm::after { content:none; }

/* §A2 plumbing: each stage's .pworld/.prail/.pstage carries one of these --
   they set LOCAL --st/--st-dim/--st-next, and every diagram/open-state rule
   above and below paints with var(--st)/var(--st-dim)/var(--st-next) alone.
   This is the one place stage identity color is chosen; nothing else in
   this file names a color literal. `--i` is the run-order index (0-4) the
   Phase D power-on cascade below staggers off -- one number per circuit,
   set here rather than inline, since the run order is static markup, not
   per-row server data (contrast the `--i` the row stagger sets inline). */
.st-intake  { --st:var(--st-intake);  --st-dim:var(--st-intake-dim);  --st-next:var(--st-context); --i:0; }
.st-context { --st:var(--st-context); --st-dim:var(--st-context-dim); --st-next:var(--trace);      --i:1; }
.st-enrich  { --st:var(--trace);      --st-dim:var(--trace-dim);      --st-next:var(--st-deliver); --i:2; }
.st-deliver { --st:var(--st-deliver); --st-dim:var(--st-deliver-dim); --st-next:var(--grey);       --i:3; }
.st-global  { --st:var(--grey);       --st-dim:rgba(94,111,106,.14);  --st-next:var(--grey);       --i:4; }

/* Health tint = a property override, not a per-selector patch. nodebad/
   nodewarn simply overwrite --st/--st-dim on whichever element carries the
   class (tintNode() in settings.py's _PAGE_JS mirrors the class onto the
   rail node, the header ordinal, AND the header button itself) -- every
   rule above/below that paints with var(--st)/var(--st-dim) picks up the
   sick color automatically, in every state (hover, open, rest) at once.
   This RETIRES the four hand-patched specificity-tie rule blocks that used
   to live in this file (`.phead .n.nodebad`, `.pstage.open .phead
   .n.nodebad`, `.phead.nodebad:hover`, `.phead:hover .n.nodebad`, and their
   nodewarn twins): "hover/open never lies about state" is now a property of
   the plumbing, not per-selector vigilance. Placed AFTER the st-* rules so
   the cascade resolves the override with zero specificity games. `nodering`
   is a distinct ADDITIVE ring (queue-depth warning), not a --st override --
   it keeps its own rule below, unchanged. */
.nodebad { --st:var(--breach); --st-dim:rgba(224,96,77,.16); }
.nodewarn { --st:var(--raw); --st-dim:var(--raw-dim); }
/* I1 fix: nodering used to REPLACE the resting
   halo+glow outright (reading dimmer than a healthy node) and lost outright
   to `.prail.open .pnode`/`.pipeline.rail-hi .pnode` on specificity (their
   0,2,1 beats this rule's 0,1,1) -- opening the intake stage, or merely
   hovering the Global header, erased the queue warning ring. Now additive
   (the halo+glow survive, the raw-dim ring layers on as a third shadow) and
   state-proof: the compound selector below matches the SAME element under
   BOTH interaction states at specificity 0,3,1, out-ranking them so the
   ring survives instead of losing the cascade. */
.pnode.nodering { box-shadow:0 0 0 4px var(--st-dim), var(--glow) var(--st-dim), 0 0 0 7px var(--raw-dim); }
.prail.open .pnode.nodering, .pipeline.rail-hi .pnode.nodering {
  box-shadow:0 0 0 5px var(--st-dim), var(--glow) var(--st-dim), 0 0 0 8px var(--raw-dim); }
.phead .n.nodering { text-decoration:underline; text-decoration-color:var(--raw); }

/* Phase 3 contract carried over: when a stage opens, the JS toggles `.open`
   on BOTH the `.pstage` AND its paired `.prail` cell (and removes it on
   close) -- the rail node lives in the sibling `.prail` column, not inside
   `.pstage`, so the open-state paint below is keyed off `.prail.open` alone
   (no relational-selector CSS anywhere in this file). */
.prail::before, .pnode {
  transition:background var(--dur-fast) var(--easing), border-color var(--dur-fast) var(--easing),
    box-shadow var(--dur-fast) var(--easing), transform var(--dur-fast) var(--easing);
  /* Power-on cascade (plan §A3.1): the diagram energizes top-to-bottom,
     once per page load -- 60ms per stage (`--i` above), `--dur` (240ms)
     fade each, so the last node settles at ~4*60+240=480ms, inside the
     500ms ceiling. `both` fill-mode, no repeat -- see the reduced-motion
     kill block, which removes this and nothing else about the rule. */
  animation:pipein var(--dur) var(--easing) both; animation-delay:calc(var(--i, 0) * 60ms); }
@keyframes pipein { from { opacity:0; } }
.prail.open .pnode { border-width:3px; box-shadow:0 0 0 5px var(--st-dim), var(--glow) var(--st-dim);
  /* Open bloom (plan §A3.2): the node's glow blooms once into the open
     halo/glow set on this very rule -- keyframe supplies only the `from`,
     the `to` is this rule's own box-shadow (the established one-shot
     pattern, see @keyframes rowin below). One-shot, `both`, no repeat.
     C1 fix: `pipein` stays FIRST in this rule's
     animation list, same name/position as the base `.prail::before,
     .pnode` rule above -- so the computed animation-name for pipein never
     changes on open OR close. Before this fix, the open state replaced the
     whole `animation` shorthand with just `bloom`, so CLOSING a stage
     flipped animation-name bloom->pipein and RESTARTED the power-on fade
     on every single close (node blinks out, cascades back in). Only
     `bloom` (this rule's second slot) starts/stops with `.prail.open`. */
  animation:pipein var(--dur) var(--easing) both, bloom .3s var(--easing) both;
  animation-delay:calc(var(--i, 0) * 60ms), 0s; }
@keyframes bloom { from { box-shadow:0 0 0 4px var(--st-dim), 0 0 2px var(--st-dim); } }
.prail.open::before { box-shadow:5px 0 0 -1px var(--st-dim), -5px 0 0 -1px var(--st-dim), 0 0 14px var(--st-dim); }
/* Whole-rail highlight (hovering the chassis/global header, wired in
   settings.py's _PAGE_JS): every segment glows brighter in ITS OWN circuit
   color -- "governs all of it" reads as the whole loom lighting up, not one
   flat accent replacing four identities. */
.pipeline.rail-hi .prail::before { box-shadow:5px 0 0 -1px var(--st-dim), -5px 0 0 -1px var(--st-dim), 0 0 14px var(--st-dim); }
.pipeline.rail-hi .pnode { box-shadow:0 0 0 5px var(--st-dim), var(--glow) var(--st-dim); }
/* Node hover scale (ask #3): the diagram acknowledges the pointer even
   though the header lives in a different grid column. `.prail`/`.pstage`
   are ADJACENT siblings (no `.pworld`/`.pstage` combinator would work
   backwards), so a pure-CSS `.prail:hover + .pstage` reads header->rail,
   never rail<-header -- settings.py's _PAGE_JS mirrors header
   hover/focus onto a `.nodehover` class on the paired `.prail` instead,
   the same forwarding pattern the rail-hi listener already uses. */
.prail.nodehover .pnode { transform:translate(-50%,-50%) scale(1.12); }

.pstage { border-bottom:1px solid var(--border); }
.pstage h2 { margin:0; font-size:inherit; font-weight:inherit; }
.phead { display:flex; align-items:center; gap:12px; width:100%; padding:14px 4px;
  background:none; border:0; font:inherit; color:inherit; text-align:left; cursor:pointer;
  box-shadow:inset 2px 0 0 transparent;
  transition:background var(--dur-fast) var(--easing), box-shadow var(--dur-fast), color var(--dur-fast); }
/* Live-feedback fix (§5b): the old hard `0 0 0 4px` halo-shaped ring read
   boxy against the hairline+glow language. Replaced with a faint stage-
   color ROW WASH (--st-dim background) plus the existing thin inset left
   accent (--st) -- no outer ring, no lift; hovering a SICK stage washes
   breach/amber for free via the --st override above. */
.phead:hover, .phead:focus-visible {
  background:var(--st-dim); box-shadow:inset 2px 0 0 var(--st); }
/* Ordinal + title -- nameplate scale. Only the mono ordinal takes the
   circuit color; the title stays --text (A8: four colored serif headlines
   is a carnival, four colored 01-04 ticks is a legend). */
.phead .n { font-family:var(--mono); font-size:12px; color:var(--st); flex:none; width:22px; }
.phead .ptitle { font-family:var(--serif); font-size:20px; flex:none; padding-bottom:1px;
  border-bottom:2px solid transparent; }
.pstage.open .phead .ptitle { border-bottom-color:var(--st); }
/* Summary-on-hover: hidden at rest, settles in on header hover/focus and
   whenever the stage is open (open panels keep their own caption -- no
   hover needed on touch, opening IS the reveal). Reduced motion: appears
   without the settle (this rule is in the reduced-motion kill list below,
   the show/hide states themselves are untouched by it). */
.phead .psub { color:var(--muted); font-size:12px; flex:1; min-width:0; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap; opacity:0; transform:translateX(-4px);
  transition:opacity var(--dur-fast) var(--easing), transform var(--dur-fast) var(--easing); }
.phead:hover .psub, .phead:focus-visible .psub, .pstage.open .phead .psub { opacity:1; transform:none; }
.phead .pmeta { margin-left:auto; display:flex; align-items:center; gap:10px; font-family:var(--mono);
  font-size:11px; color:var(--muted); flex:none; white-space:nowrap; }
.pmeta .dirty { color:var(--raw); }
.phead .pchev { flex:none; color:var(--muted); transition:transform var(--dur) var(--easing); }
.pstage.open .phead .pchev { transform:rotate(180deg); }
/* Expand/collapse -- the core motion. `grid-template-rows:0fr -> 1fr`
   animates TRUE content height (unlike `max-height`, which either clips a
   tall body like Delivery or, set generously, finishes its visible motion
   early and reads the easing wrong). Expand runs at `--dur`; collapse is
   faster and gets there via a transient `.closing` class (added by
   closeStage() in settings.py for the duration of the collapse only) that
   overrides just `transition-duration`, not the whole `.pbody-wrap` rule --
   the `settings.py` JS coordinates `hidden`/`overflow` off this element's
   `transitionend`, see that module's comment on `wrapTransitionEnd`. */
.pbody-wrap { display:grid; grid-template-rows:0fr; transition:grid-template-rows var(--dur) var(--easing); }
.pbody-wrap.open { grid-template-rows:1fr; }
.pbody-wrap.closing { transition-duration:var(--dur-fast); }
/* The inner body settles into place (opacity+translateY) rather than merely
   unclipping -- compositor-only properties, the wrapper above is the only
   layout-affecting animation. `overflow:hidden` clips during the transition
   only; JS releases it to `visible` at rest (post-expand transitionend) so
   focus rings/tooltips/long selects are never truncated, and re-clips
   before the next collapse starts (see closeStage()/wrapTransitionEnd()). */
.pbody { min-height:0; overflow:hidden; padding:0 4px; opacity:0; transform:translateY(-6px);
  transition:opacity var(--dur) var(--easing), transform var(--dur) var(--easing); }
.pbody-wrap.open .pbody { opacity:1; transform:none; }
/* §A3 wants opacity to LEAD the collapse, not run in lockstep with the
   wrapper's grid-rows -- a shorter duration on just the fade (still the same
   easing) gets it fully transparent before the height finishes closing. */
.pbody-wrap.closing .pbody { transition-duration:calc(var(--dur-fast) * .6); }

/* Capped "panel powering up" row reveal -- the one craft flourish. Only the
   first 6 rows stagger (`--i` set 0-5 inline by renderStage() in
   settings.py; rows 7+ share `--i:5` so a 20-row Delivery body adds zero
   extra wait). One-shot (`both` fill-mode, never a repeating animation) and
   compositor-only (opacity+translateY). Replays every time a stage opens --
   `.row`s persist hidden-not-destroyed across a collapse, and the animation
   naturally restarts when `.pbody-wrap.open .row` starts matching again. */
/* `both` fill-mode, no repeat count of any kind -- this animation runs
   exactly once per open and stops. */
@keyframes rowin { from { opacity:0; transform:translateY(4px); } }
.pbody-wrap.open .row { animation:rowin var(--dur-fast) var(--easing) both; animation-delay:calc(var(--i, 0) * 22ms); }

.pdiv { font-family:var(--mono); font-size:10px; text-transform:uppercase; letter-spacing:.12em;
  color:var(--ink2); border-top:1px solid var(--edge); padding:10px 16px 0; margin:14px 0 6px; }

/* Responsive (§A6): the world column collapses first (700-900px keeps the
   full 128px rail), the rail itself only narrows past 700px, where the
   diagram band folds down to a thin accent and the form goes full-width.
   Cells are re-pinned to the narrower template's own column count -- the
   fixed grid-column indices above (1/2/3) only apply to the 4-track
   desktop template. */
@media (max-width:900px) {
  .pipeline { grid-template-columns:[rail] 128px [main] minmax(0,660px) [void] 1fr; }
  .pworld { display:none; }
  .prail { grid-column:1; }
  .pstage { grid-column:2; }
}
@media (max-width:700px) {
  .pipeline { grid-template-columns:40px 1fr; margin:0 -20px; }
  .prail { grid-column:1; }
  .pstage { grid-column:2; }
  .phead { flex-wrap:wrap; }
  .phead .pmeta { margin-left:0; flex-basis:100%; white-space:normal; }
  /* §1 mobile guard: the 40px rail has no room for the echo ring, the
     junction stub, or the twin-hairline bus -- revert to a plain line. */
  .pnode::before { content:none; }
  .prail::after { content:none; }
  .prail::before { box-shadow:0 0 10px var(--st-dim); }
}
/* Kills every transition/animation added above (and the pre-existing
   header/chevron/node ones) -- expand/collapse becomes instant and the row
   stagger never runs; `hidden`/`overflow` are then set synchronously by the
   JS (settings.py checks this same media query) since no `transitionend`
   will ever fire to gate them. Deliberately narrow: only `transition`/
   `animation` declarations live in this block -- every state/color rule
   (open-node fill, rail brighten, health tints, chevron's rotated
   end-state, title underline, summary show/hide) sits outside it and so
   survives untouched, per the addendum ("states, not motion") -- a
   reduced-motion reader still gets the summary the instant a header is
   hovered/focused/opened, just without the settle. */
@media (prefers-reduced-motion:reduce) {
  .phead, .pnode, .pchev, .phead .ptitle, .phead .psub, .prail::before, .pbody-wrap, .pbody { transition:none; animation:none; }
  .row { animation:none; }
  /* `.prail.open .pnode`'s bloom is a MORE specific selector than the plain
     `.pnode` above, so it needs its own kill -- an end state (the open
     halo/glow) still applies, just without the one-shot bloom. */
  .prail.open .pnode { animation:none; }
}
"""


def _minify_css(css):
    """Whitespace/comment compaction only -- never rewrites a selector or
    value, so the source above stays the single source of truth and this is
    safe to apply unconditionally. Keeps the shipped page comfortably under
    its size budget without giving up a readable, commented source."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    css = re.sub(r"\s+", " ", css)
    css = re.sub(r"\s*([{}:;,])\s*", r"\1", css)
    css = css.replace(";}", "}")  # trailing semicolon before a close-brace is redundant
    return css.strip()


CSS = _minify_css(_CSS_SOURCE)
FORM_CSS = _minify_css(_FORM_CSS_SOURCE)
PIPE_CSS = _minify_css(_PIPE_CSS_SOURCE)
DETAIL_CSS = _minify_css(_DETAIL_CSS_SOURCE)


def nav_html(active):
    def link(href, label, key):
        cls = "active" if key == active else ""
        return f'<a href="{href}" class="{cls}">{label}</a>'
    return (
        '<nav class="mainnav">'
        + link("/", "Overview", "overview")
        + link("/settings", "Settings", "settings")
        + '</nav>'
    )


# The brand bird (GET /logo.png) is the header mark. The inline trace glyph
# below is kept only as an onerror fallback (hidden until the raster fails to
# load) so the nameplate degrades gracefully without ever inlining raster bytes.
_LOGO_IMG = (
    '<img class="mark" src="/logo.png" width="22" height="22" alt="Nuncio" '
    "onerror=\"this.style.display='none';"
    "var s=this.parentNode.querySelector('svg.mark');if(s)s.style.display='block'\">"
)

_MARK_SVG = (
    '<svg class="mark" style="display:none" width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M2 12H22" stroke="var(--trace)" stroke-width="2"/>'
    '<path d="M7 12C9 5.5 15 5.5 17 12" stroke="var(--raw)" stroke-width="1.5" fill="none"/>'
    '<circle cx="2" cy="12" r="1.8"/><circle cx="22" cy="12" r="1.8"/>'
    '</svg>'
)


def header_html(active="overview", tape_html=None):
    """`tape_html=None` (the default) emits the dashboard's telemetry tape
    span byte-for-byte, exactly as shipped -- the dashboard NEVER passes
    this parameter, so its render stays untouched by REV 3 Phase C. The
    settings page passes its lock widget markup instead (nuncio/web/
    settings.py) -- the tape means nothing there (it never updates)."""
    if tape_html is None:
        tape_html = '<span class="tape" id="tape">reading&hellip;</span>'
    return (
        '<div class="topbar"><div class="wrap row">'
        + _LOGO_IMG + _MARK_SVG +
        '<span class="wordmark">Nuncio</span>'
        '<span class="rule"></span>'
        + tape_html +
        nav_html(active) +
        '</div></div>'
    )


def page_shell(app, title, body_html, extra_js="", active="overview", extra_css="", tape_html=None):
    favicon = app.favicon_data_uri or ""
    favicon_tag = f'<link rel="icon" href="{_esc(favicon)}">' if favicon else ""
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title>{favicon_tag}<style>{CSS}{extra_css}</style></head>"
        f"<body>{header_html(active, tape_html)}<div class=\"wrap\">{body_html}</div>"
        f"<script>{extra_js}</script></body></html>"
    )
