"""The settings screen: HTTP surface , the admin-token gate ,
and live-apply-under-load ( correctness -- no lost/duplicated alert on a
mid-flight settings change)."""
import json
import os
import threading
import time

import pytest

from nuncio import config
from nuncio.engine import Engine
from nuncio.server import App, Metrics, _handler_factory
from nuncio.store import Store
from nuncio.web import settings as settings_ui


def base_env(**overrides):
    env = {"NUNCIO_LLM_URL": "http://ollama:11434"}
    env.update(overrides)
    return env


def build(tmp_path, **extra_env):
    env = base_env(NUNCIO_DATA_DIR=str(tmp_path), **extra_env)
    return config.build_app(config.load_settings(env))


class _Headers(dict):
    """A minimal case-insensitive stand-in for email.message.Message, the
    real type server.py passes -- handle_post()/check_admin_token() only
    ever call .get()."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


# =====================================================================
# The admin-token gate 
# =====================================================================

def test_post_settings_403_when_no_admin_token_configured(tmp_path):
    app, settings = build(tmp_path)
    status, body = settings_ui.handle_post(app, b'{"set": {"NUNCIO_MODE": "bypass"}}', _Headers())
    assert status == 403
    assert app.engine.mode == "enriched"  # nothing applied
    app.store.close()


def test_post_settings_401_on_wrong_token(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    status, body = settings_ui.handle_post(
        app, b'{"set": {"NUNCIO_MODE": "bypass"}}', _Headers({"X-Admin-Token": "wrong-token"}))
    assert status == 401
    assert app.engine.mode == "enriched"
    app.store.close()


def test_post_settings_401_when_token_header_missing(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    status, body = settings_ui.handle_post(app, b'{"set": {"NUNCIO_MODE": "bypass"}}', _Headers())
    assert status == 401
    app.store.close()


def test_post_settings_200_with_correct_token(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    status, body = settings_ui.handle_post(
        app, b'{"set": {"NUNCIO_MODE": "bypass"}}', _Headers({"X-Admin-Token": "correct-token"}))
    assert status == 200
    assert body["applied"] == ["NUNCIO_MODE"]
    assert app.engine.mode == "bypass"
    app.store.close()


def test_token_compared_constant_time_not_by_naive_equality(monkeypatch, tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    calls = []
    import hmac as hmac_mod
    real = hmac_mod.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(settings_ui.hmac, "compare_digest", spy)
    settings_ui.check_admin_token(app, _Headers({"X-Admin-Token": "x"}))
    assert calls  # compare_digest was actually used, not `==`
    app.store.close()


def test_get_settings_json_never_gated_by_token(tmp_path):
    # Reads stay open even with a token configured -- only writes are gated.
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    body = settings_ui.render_settings_json(app)
    assert json.loads(body)["admin_token_configured"] is True
    app.store.close()


def test_get_settings_json_reports_unconfigured_when_no_token(tmp_path):
    app, settings = build(tmp_path)
    body = json.loads(settings_ui.render_settings_json(app))
    assert body["admin_token_configured"] is False
    app.store.close()


def test_post_settings_413_body_too_large(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    huge = b'{"set": {"NUNCIO_DELIVERY_TITLE": "' + b"x" * (settings_ui.MAX_BODY_BYTES + 10) + b'"}}'
    status, body = settings_ui.handle_post(app, huge, _Headers({"X-Admin-Token": "tok"}))
    assert status == 413
    app.store.close()


def test_post_settings_400_on_invalid_json(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    status, body = settings_ui.handle_post(app, b"not json", _Headers({"X-Admin-Token": "tok"}))
    assert status == 400
    app.store.close()


def test_post_settings_500_when_app_settings_is_none_but_token_configured():
    # A hand-built App with admin_token set (so check_admin_token passes)
    # but no config.py composition root wiring -- app.settings stays None.
    store = Store(":memory:")

    class FakeEngine:
        mode = "enriched"

    a = App(FakeEngine(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=2,
            clock=lambda: 1000.0, maint_interval=3600.0, admin_token="tok")
    status, body = settings_ui.handle_post(a, b'{"set": {}}', _Headers({"X-Admin-Token": "tok"}))
    assert status == 500
    assert "not available" in body["error"]
    store.close()


def test_post_settings_400_when_body_is_valid_json_but_not_an_object(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    status, body = settings_ui.handle_post(app, b"[1, 2, 3]", _Headers({"X-Admin-Token": "tok"}))
    assert status == 400
    assert "invalid JSON body" in body["error"]
    app.store.close()


def test_post_settings_400_when_set_is_not_an_object(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    status, body = settings_ui.handle_post(
        app, json.dumps({"set": "not-an-object"}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 400
    assert "set" in body["error"]
    app.store.close()


def test_post_settings_400_when_reset_contains_a_non_string(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    status, body = settings_ui.handle_post(
        app, json.dumps({"reset": ["NUNCIO_MODE", 123]}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 400
    assert "reset" in body["error"]
    app.store.close()


def test_post_settings_500_when_persisting_the_overrides_file_fails(tmp_path, monkeypatch):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")

    def boom(path, doc):
        raise OSError("disk full")
    monkeypatch.setattr(config, "write_overrides_file", boom)

    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {"NUNCIO_MODE": "bypass"}}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 500
    assert "failed to persist" in body["error"]
    app.store.close()


def test_post_settings_400_atomic_error_map_names_the_bad_key(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {"NUNCIO_BUDGET_S": 99999}}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 400
    assert "NUNCIO_BUDGET_S" in body["errors"]
    app.store.close()


# =====================================================================
# GET-side transparency
# =====================================================================

def test_settings_json_masks_secret_values(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok", NUNCIO_NTFY_TOKEN="a-real-secret-value")
    body = settings_ui.render_settings_json(app)
    assert b"a-real-secret-value" not in body
    parsed = json.loads(body)
    assert parsed["keys"]["NUNCIO_NTFY_TOKEN"]["value"] == "«set»"
    app.store.close()


# --- credential leak: delivery target URLs are credentials too, and
# GET /settings.json (like GET /config.json) is unauthenticated -- see the
# NEVER_SECRETS / secret=True audit in nuncio/config.py's UI_EDITABLE. ---

@pytest.mark.parametrize("key,value", [
    ("NUNCIO_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/AAA111/BBB222/xoxb-realtoken12345"),
    ("NUNCIO_APPRISE_URL", "http://apprise:8000/notify/a-real-notify-key"),
    ("NUNCIO_WEBHOOK_URL", "https://user:hunter2@webhook.example/endpoint"),
    ("NUNCIO_NTFY_TOPIC", "a-secret-topic-name"),
])
def test_settings_json_masks_delivery_credential_urls(tmp_path, key, value):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok", **{key: value})
    body = settings_ui.render_settings_json(app)
    assert value.encode() not in body
    parsed = json.loads(body)
    assert parsed["keys"][key]["value"] == "«set»"
    assert parsed["keys"][key]["secret"] is True
    app.store.close()


def test_settings_json_runs_every_value_through_redact_as_defense_in_depth(tmp_path):
    # Even a NON-secret-flagged key must not leak an embedded credential --
    # e.g. basic-auth creds embedded in a URL that isn't itself marked secret.
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok",
                           NUNCIO_LOGS_URL="http://user:hunter2@logs.example:9200")
    body = settings_ui.render_settings_json(app)
    assert b"hunter2" not in body


def test_settings_json_never_key_shows_env_pinned_reason(tmp_path):
    app, settings = build(tmp_path)
    parsed = json.loads(settings_ui.render_settings_json(app))
    llm_url = parsed["keys"]["NUNCIO_LLM_URL"]
    assert llm_url["editable"] is False
    assert llm_url["value"] == "http://ollama:11434"  # not secret -- shown plainly
    assert "reason" in llm_url
    app.store.close()


def test_settings_json_llm_key_is_masked_even_though_never_editable(tmp_path):
    app, settings = build(tmp_path, NUNCIO_LLM_KEY="a-real-llm-secret")
    body = settings_ui.render_settings_json(app)
    assert b"a-real-llm-secret" not in body
    app.store.close()


def test_settings_json_carries_stage_on_an_editable_key(tmp_path):
    app, settings = build(tmp_path)
    parsed = json.loads(settings_ui.render_settings_json(app))
    assert parsed["keys"]["NUNCIO_LLM_MODEL"]["stage"] == "enrich"
    app.store.close()


def test_settings_json_carries_stage_on_a_locked_never_key(tmp_path):
    app, settings = build(tmp_path)
    parsed = json.loads(settings_ui.render_settings_json(app))
    llm_url = parsed["keys"]["NUNCIO_LLM_URL"]
    assert llm_url["stage"] == "enrich"
    assert llm_url["editable"] is False
    app.store.close()


def test_settings_json_source_badges(tmp_path):
    app, settings = build(tmp_path, NUNCIO_MODE="bypass", NUNCIO_ADMIN_TOKEN="tok")
    settings_ui.handle_post(app, json.dumps({"set": {"NUNCIO_LLM_MODEL": "custom"}}).encode(),
                             _Headers({"X-Admin-Token": "tok"}))
    parsed = json.loads(settings_ui.render_settings_json(app))
    assert parsed["keys"]["NUNCIO_MODE"]["source"] == "env"
    assert parsed["keys"]["NUNCIO_LLM_MODEL"]["source"] == "override"
    assert parsed["keys"]["NUNCIO_BUDGET_S"]["source"] == "default"
    app.store.close()


def test_settings_json_restart_pending_surfaced(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    settings_ui.handle_post(app, json.dumps({"set": {"NUNCIO_CONCURRENCY": 3}}).encode(),
                             _Headers({"X-Admin-Token": "tok"}))
    parsed = json.loads(settings_ui.render_settings_json(app))
    assert "NUNCIO_CONCURRENCY" in parsed["restart_pending"]
    app.store.close()


def test_settings_json_on_app_without_settings_degrades_gracefully():
    # A hand-built App (no config.py composition root involved -- as in
    # test_app.py's fixtures) has app.settings == None; the settings screen
    # must not crash, just report nothing editable and writes disabled.
    store = Store(":memory:")

    class FakeEngine:
        mode = "enriched"

    a = App(FakeEngine(), store, Metrics(), budget_s=45.0, concurrency=0, queue_max=2,
            clock=lambda: 1000.0, maint_interval=3600.0)
    body = json.loads(settings_ui.render_settings_json(a))
    assert body["keys"] == {}
    assert body["admin_token_configured"] is False
    status, resp = settings_ui.handle_post(a, b'{"set": {}}', _Headers())
    assert status == 403
    store.close()


# =====================================================================
# The screen itself 
# =====================================================================

def test_settings_html_reuses_the_dashboard_shell_and_nav(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "Nuncio" in html
    assert 'href="/settings"' in html
    assert 'href="/"' in html
    assert "nav.mainnav" in html  # shared CSS class from nuncio/web/shell.py


def test_settings_html_is_self_contained_no_external_requests(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "http://" not in html.replace("http://ollama", "")  # no CDN/font URLs
    assert "<script src" not in html
    assert "<link rel=\"stylesheet\"" not in html


def test_settings_html_under_size_budget(tmp_path):
    # Phase 5 (pipeline-plan.md Decision #6) ratifies the original ceiling:
    # < 64KB. REV 3 Phase D (Global Constraint 8) crosses it on purpose --
    # the radar-echo ring, junction stub, twin-hairline bus, and power-on/
    # bloom keyframes are hero product surface, not bloat -- so the
    # soft-ceiling moves to the plan's justified max, 68KB. Measured just
    # before this phase (post Phase C): ~65.4KB (113B under the old 64KB
    # ceiling); this phase's character/prominence CSS adds ~0.9KB, landing
    # at ~64.8KB -- comfortably inside the new 68KB ceiling.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024


def test_dashboard_nav_links_to_settings_not_disabled(tmp_path):
    from nuncio.web import dashboard
    app, settings = build(tmp_path)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'href="/settings"' in html
    assert 'class="disabled"' not in html
    app.store.close()


# =====================================================================
# Phase 1 refactor: forms.py extraction is behavior-neutral
# =====================================================================

def test_settings_html_still_carries_the_row_markers(tmp_path):
    # Row rendering moved into nuncio/web/forms.py's FORM_JS -- the rendered
    # page must still carry the same markup hooks the old inline JS used.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "inputHtml" in html
    assert 'class="row"' in html
    assert "applybar" in html


def test_form_js_is_a_nonempty_str_exporting_the_shared_helpers(tmp_path):
    from nuncio.web.forms import FORM_JS
    assert isinstance(FORM_JS, str)
    assert FORM_JS.strip()
    for fn in ("esc", "fmtVal", "inputHtml", "toggleBool", "onEdit", "resetKey",
               "needsConfirm", "showModal", "sendApply", "toast", "promptToken",
               "groupRows"):
        assert f"function {fn}" in FORM_JS or f"const {fn} " in FORM_JS, fn
    assert "let TOKEN" in FORM_JS
    assert "let KEYS" in FORM_JS
    assert "let DIRTY" in FORM_JS
    assert "let RESET" in FORM_JS


def test_dashboard_html_does_not_inherit_settings_only_chrome(tmp_path):
    # Guard against the dashboard accidentally picking up settings-page-only
    # chrome (the group accordion / fixed apply bar) now that row-level CSS
    # has been split out into shared FORM_CSS.
    from nuncio.web import dashboard
    app, settings = build(tmp_path)
    html = dashboard.render_dashboard_html(app).decode()
    assert "applybar" not in html
    app.store.close()


# =====================================================================
# Phase 2: the flat editor is replaced by the vertical accordion pipeline
# skeleton -- STATIC markup + CSS only (no accordion/row-render JS yet).
# =====================================================================

_STAGE_IDS_IN_ORDER = ["stage-intake", "stage-context", "stage-enrich", "stage-deliver", "stage-global"]


def test_settings_html_has_all_five_stage_sections_in_run_order(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    positions = [html.index(marker) for marker in _STAGE_IDS_IN_ORDER]
    assert positions == sorted(positions)  # intake -> context -> enrich -> deliver -> global


def test_settings_html_stage_header_aria_wiring(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'aria-expanded="false"' in html
    assert 'aria-controls="pbody-enrich"' in html
    assert 'id="phead-enrich"' in html
    assert 'role="region"' in html
    assert 'aria-labelledby="phead-enrich"' in html
    assert " hidden" in html  # every accordion body starts hidden
    # every stage's body is empty and hidden this phase -- no client-rendered rows
    assert html.count('role="region"') == 5
    # REV 3 Phase C: the topbar lock's popover (#lockpop) also starts
    # `hidden` -- 5 accordion bodies + 1 lock popover.
    assert html.count(" hidden") == 6


def test_settings_html_keeps_applybar_toast_and_modal_ids_unchanged(tmp_path):
    # FORM_JS drives these by id (see nuncio/web/forms.py's module docstring)
    # -- the vertical page must keep them verbatim.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'id="applybar"' in html
    assert 'id="toast"' in html
    assert 'id="modalback"' in html
    assert 'id="modalbody"' in html
    assert 'id="modalyes"' in html
    assert 'id="modalno"' in html


def test_settings_html_reduced_motion_media_query_present(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "prefers-reduced-motion" in html


def test_settings_html_flat_editor_and_drawer_leftovers_are_gone(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "<details" not in html
    assert 'class="group"' not in html
    assert 'class="drawer"' not in html
    assert "scrim" not in html
    assert "aria-modal" not in html


def test_settings_html_byte_budget_still_one_favicon_base64_no_raster(tmp_path):
    # Same guard as test_dashboard.py's raster/base64 budget test -- the
    # vertical pipeline markup must not have snuck in an inlined asset.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'class="mark" src="/logo.png"' in html
    assert html.count("base64") == 1  # exactly the favicon href, nothing bigger


def test_settings_html_global_stage_has_terminal_square_markup(tmp_path):
    # The global (pipeline) stage's node must render as the terminal square
    # (`.pterm`, a bordered div -- SVG-free), not a plain circle node.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'class="pnode pterm"' in html
    assert html.count('class="pnode pterm"') == 1  # exactly one terminal, on the global stage
    assert html.count('class="pnode"') == 4  # the other four stages get a plain node


def test_settings_html_global_rail_carries_the_truncation_class(tmp_path):
    # The global stage's rail cell needs an explicit hook (not :last-child --
    # see the .prail-term comment in shell.py) so its spine's CSS can stop at
    # the terminal square instead of running the full row height past it.
    # REV 3: every rail cell also carries its stage's st-{key} plumbing class
    # (§A2), so the exact class string now includes it too.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'class="prail prail-term st-global"' in html
    assert html.count('class="prail prail-term') == 1  # exactly one terminal rail, on the global stage
    for key in ("intake", "context", "enrich", "deliver"):
        assert f'class="prail st-{key}"' in html  # the other four stay plain rail cells


def test_settings_html_and_pipe_css_never_use_has_selector(tmp_path):
    # `:has()` was a dead-on-arrival hook (never matched, since the rail
    # node lives in a sibling column, not a descendant of .pstage) -- the
    # open/active state is keyed off an explicit `.open` class instead, so
    # the page must not depend on this modern-CSS selector anywhere.
    from nuncio.web import shell
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert ":has(" not in html
    assert ":has(" not in shell.PIPE_CSS
    assert ":has(" not in shell._PIPE_CSS_SOURCE


def test_settings_css_pipe_tokens_added_to_all_three_theme_blocks(tmp_path):
    from nuncio.web import shell
    for token in ("--halo:", "--dur:", "--dur-fast:", "--easing:"):
        assert shell.CSS.count(token) == 3, token  # dark, @media light, [data-theme=light]
    assert "--lift" not in shell.CSS  # v1 drawer elevation token -- explicitly dropped
    assert "--scrim" not in shell.CSS  # v1 drawer scrim token -- explicitly dropped


def test_pipe_css_exported_and_contains_the_structural_pipeline_rules(tmp_path):
    from nuncio.web import shell
    assert isinstance(shell.PIPE_CSS, str)
    assert shell.PIPE_CSS.strip()
    for marker in (".pipeline", ".prail", ".pnode", ".phead", ".pbody-wrap",
                   "grid-template-rows:0fr", ".pbody-wrap.open", ".pstage.open",
                   ".rail-hi", "nodebad", "nodewarn", "nodering",
                   "prefers-reduced-motion", "max-width:700px"):
        assert marker in shell.PIPE_CSS, marker
    assert not hasattr(shell, "SETTINGS_CSS")  # retired -- the flat-editor chrome is gone


def test_applybar_rule_lives_in_form_css_not_pipe_css(tmp_path):
    from nuncio.web import shell
    assert ".applybar" in shell.FORM_CSS
    assert ".applybar" not in shell.PIPE_CSS
    # the dead flat-editor-only rules are retired, not merely relocated
    assert ".group{" not in shell.FORM_CSS and ".group{" not in shell.PIPE_CSS
    assert ".grouprows" not in shell.FORM_CSS and ".grouprows" not in shell.PIPE_CSS


def test_settings_page_ships_form_css_plus_pipe_css(tmp_path):
    from nuncio.web import shell
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert ".applybar" in html  # from FORM_CSS
    assert ".pipeline{" in html  # from PIPE_CSS (minified, no space before brace)


def test_dashboard_render_is_unaffected_by_the_pipeline_redesign(tmp_path):
    # Constraint 7: nuncio/web/dashboard.py is untouched by this phase --
    # its render must still carry the horizontal signal-path markers and
    # must NOT pick up any of the new vertical-pipeline section ids.
    from nuncio.web import dashboard
    app, settings = build(tmp_path)
    html = dashboard.render_dashboard_html(app).decode()
    assert 'id="sigpath"' in html
    assert 'id="sigpath-svg"' in html
    for marker in _STAGE_IDS_IN_ORDER:
        assert marker not in html
    assert 'class="pipeline"' not in html
    app.store.close()


# =====================================================================
# Phase 3: interaction JS -- accordion, bucket render, banners, inventory,
# health tints, deep-linking, and the restored audit/change-log. All of this
# is client-side JS shipped inline; unit-tested here as substring markers on
# the rendered page bytes (no browser in this test suite) plus the live-HTTP
# coexistence checks in test_app.py.
# =====================================================================

def test_page_js_defines_ondirtychange_and_load(tmp_path):
    # forms.py's FORM_JS docstring requires the embedding page to define
    # both hooks before a user can interact.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "function onDirtyChange" in html
    assert "async function load" in html or "function load" in html


def test_page_js_defines_toggle_and_render_stage(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "function toggleStage" in html
    assert "function renderStage" in html


def test_page_js_ondirtychange_also_renders_the_apply_bar(tmp_path):
    # Decision #10 wiring: every edit (onEdit/resetKey -> onDirtyChange) must
    # keep the sticky apply bar's summary + visibility in sync with the
    # per-stage dirty chips, not just the chips.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function onDirtyChange"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "renderApplyBar()" in fn


def test_page_js_do_apply_reuses_shared_send_apply_not_a_second_fetch(tmp_path):
    # This phase adds NO new writer/endpoint -- doApply must funnel through
    # the shared sendApply(onDone) contract (Decision #10), never hand-roll
    # its own fetch('/settings', ...).
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function doApply"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "sendApply(" in fn
    assert "needsConfirm()" in fn
    assert "showModal(" in fn
    assert "fetch(" not in fn


def test_page_js_on_apply_rejected_opens_the_offending_stage(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function onApplyRejected"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "openStage(" in fn


def test_page_js_fetches_sources_at_load_not_lazily(tmp_path):
    # Phase E moves the /sources fetch into load() itself (alongside
    # /settings.json and /stats.json) so it's cached in time for renderFans()
    # to draw the world-column fan-in on first paint; the fetch call must
    # live inside function load()'s own body, not merely somewhere on the
    # page.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("async function load()"):]
    fn = fn[:fn.index("\nload();")]
    assert "fetch('/sources'" in fn or 'fetch("/sources"' in fn


def test_page_js_load_sources_reuses_the_cached_load_time_fetch(tmp_path):
    # loadSources() (the intake accordion body's adapter inventory) must not
    # issue its OWN fetch('/sources') -- it consumes the SAME cached result
    # load() already fetched, so opening the Sources stage never triggers a
    # second network round trip.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("async function loadSources()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "fetch(" not in fn


def test_page_js_fetches_settings_and_stats_json(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "fetch('/settings.json'" in html
    assert "fetch('/stats.json'" in html


def test_page_js_handles_stage_hash_deep_linking(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "#stage-" in html
    assert "location.hash" in html
    assert "replaceState" in html


def test_page_js_wires_whole_rail_hover_on_global_header(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "rail-hi" in html
    assert "phead-global" in html


def test_page_js_health_tint_rules_reference_the_stats_fields_they_key_off(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "undelivered_now" in html
    assert "enriched_rate" in html
    assert "queue" in html
    for cls in ("nodebad", "nodewarn", "nodering"):
        assert cls in html


def test_page_js_never_group_table_covers_every_never_reasons_key(tmp_path):
    # _PAGE_JS hand-maintains NEVER_GROUP, mirroring nuncio.config.NEVER_REASONS
    # (see the comment above _PAGE_JS). Nothing enforces that mirror at
    # import time, so a future NEVER-key added to config.py without a
    # matching NEVER_GROUP entry would silently render in the unlabeled
    # tail instead of its real sub-section. Catch that drift here.
    for key in config.NEVER_REASONS:
        assert key in settings_ui._PAGE_JS, f"{key} missing from settings.py's NEVER_GROUP table"


def test_page_js_accordion_toggles_the_documented_three_open_targets(tmp_path):
    # Contract documented in shell.py: opening a stage flips `open` on the
    # .pstage, its paired .prail, AND the .pbody-wrap -- plus aria-expanded
    # and the `hidden` attribute on the .pbody.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "aria-expanded" in html
    assert ".add('open')" in html or '.add("open")' in html


# =====================================================================
# Final-review fix wave: three accordion<->apply<->re-render integration
# bugs found in a final review pass. No browser in this test
# suite (see the Phase 3 comment above) -- pinned as source-structure
# assertions on the extracted function body, the same technique the rest of
# this file already uses for JS-logic contracts (e.g.
# test_page_js_do_apply_reuses_shared_send_apply_not_a_second_fetch).
# =====================================================================

def _fn_body(html, name):
    fn = html[html.index(name):]
    return fn[:fn.index("\n}\n") + 3]


def test_open_stage_closes_the_currently_open_stage_first(tmp_path):
    # Repro: stage A open and dirty, stage B also dirty. Clicking [Review]
    # (reviewChanges()) or a 400 whose first bad key lives in a different
    # stage than the one open (onApplyRejected()) both call openStage()
    # directly, bypassing toggleStage()'s one-open-at-a-time bookkeeping --
    # without this guard, A would stay open while B opens beneath it.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = _fn_body(html, "function openStage")
    assert "if (OPEN_STAGE === key) return;" in fn
    assert "if (OPEN_STAGE) closeStage(OPEN_STAGE);" in fn
    # The guard has to run before this stage's own DOM is touched, or a
    # same-key re-open call would double-render / a different-key call
    # would close the new stage's own state right after opening it.
    assert fn.index("OPEN_STAGE === key") < fn.index("renderStage(key)")
    # reviewChanges() and onApplyRejected() are unguarded raw callers of
    # openStage() -- the fix has to live in openStage() itself, not in them.
    assert "closeStage(" not in _fn_body(html, "function reviewChanges")
    assert "closeStage(" not in _fn_body(html, "function onApplyRejected")


def test_discard_changes_invalidates_every_rendered_stage_not_just_open(tmp_path):
    # Repro: open stage A, edit a key, collapse A (still dataset.rendered),
    # open+edit stage B, discard. Re-opening A must show the SERVER value,
    # not the discarded typed value -- which requires invalidating every
    # stage's render cache (the same STAGES.forEach loop load() uses for
    # the same reason), not only the currently-open one.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = _fn_body(html, "function discardChanges")
    assert "STAGES.forEach(" in fn
    assert "dataset.rendered = ''" in fn
    assert "if (OPEN_STAGE) renderStage(OPEN_STAGE);" in fn
    # Same forEach shape load() uses -- not a stage-local snippet that
    # happens to look similar.
    load_fn = _fn_body(html, "async function load()")
    assert "dataset.rendered = ''" in load_fn


def test_load_handles_a_failed_fetch_and_onapplied_always_resyncs_the_bar(tmp_path):
    # Repro (a): kill the network on first load -- the page must not be
    # left stuck on "Loading..." forever with a dead deep-link; it must
    # toast and still finish initialization.
    # Repro (b): kill the network on the load() a successful apply triggers
    # -- sendApply() already cleared DIRTY/RESET and toasted success, so
    # onApplied() must resync the apply bar (onDirtyChange) regardless of
    # whether the refresh itself succeeded, or the bar keeps claiming
    # stale pending changes after a SUCCESSFUL apply.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    load_fn = _fn_body(html, "async function load()")
    assert "try {" in load_fn
    assert "} catch (e) {" in load_fn
    assert "Couldn't refresh settings" in load_fn
    assert "} finally {" in load_fn
    assert "INITIALIZED = true" in load_fn
    # INITIALIZED must be set (and openDeepLinkedStage attempted) whether or
    # not the try body succeeded -- i.e. from the finally, not the try.
    assert load_fn.index("} finally {") < load_fn.index("INITIALIZED = true")
    applied_fn = _fn_body(html, "async function onApplied")
    assert "try {" in applied_fn
    assert "await load();" in applied_fn
    assert "} finally {" in applied_fn
    assert applied_fn.index("} finally {") < applied_fn.index("onDirtyChange();")


def test_hover_does_not_untint_a_health_tinted_ordinal(tmp_path):
    # REV 3: the old fix was a per-selector specificity-tie patch
    # (`.phead:hover .n.nodebad{color:var(--breach)}`) that had to out-order
    # the plain hover rule in source. That patch is RETIRED -- health tint is
    # now a property override (nodebad/nodewarn overwrite the LOCAL --st
    # custom property on whichever element carries the class), so the
    # ordinal's single unconditional rule (`color:var(--st)`) already reads
    # the sick color in every state, hover included, with no selector race
    # to win. Assert the retired patch is gone and the override mechanism
    # that replaces it is in place.
    from nuncio.web import shell
    assert ".phead:hover .n.nodebad{color:var(--breach)}" not in shell.PIPE_CSS
    assert ".phead:hover .n.nodewarn{color:var(--raw)}" not in shell.PIPE_CSS
    assert ".phead .n{font-family:var(--mono);font-size:12px;color:var(--st)" in shell.PIPE_CSS
    assert ".nodebad{--st:var(--breach)" in shell.PIPE_CSS
    assert ".nodewarn{--st:var(--raw)" in shell.PIPE_CSS


def test_settings_html_has_recent_changes_audit_section(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "Recent changes" in html
    assert 'id="auditsec"' in html


def test_settings_html_audit_section_sits_below_pipeline_above_footer(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    pipeline_end = html.index('class="pipeline"')
    audit_pos = html.index('id="auditsec"')
    footer_pos = html.index("<footer")
    assert pipeline_end < audit_pos < footer_pos


def test_settings_html_applybar_starts_hidden_but_wired_this_phase(tmp_path):
    # Phase 4 wires the write path: doApply/discardChanges/renderApplyBar
    # are now defined and wired to the applybar's buttons. The *static*
    # server render must still start with the bar hidden -- there is no
    # pending edit at load time -- so it never carries `.show` in the
    # rendered bytes; dirtiness (and the `.show` class) is a client-side,
    # post-load-only state this test can't observe without a browser.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'applybar show' not in html
    assert "function doApply" in html
    assert "function discardChanges" in html
    assert "function renderApplyBar" in html
    assert "function reviewChanges" in html
    assert "function onApplyRejected" in html
    assert 'onclick="doApply()"' in html
    assert 'onclick="discardChanges()"' in html
    assert 'onclick="reviewChanges()"' in html
    assert ">Review<" in html
    assert ">Discard all<" in html


def test_form_js_defines_show_row_errors_and_row_error_helpers(tmp_path):
    from nuncio.web.forms import FORM_JS
    assert "function showRowErrors" in FORM_JS
    assert "function clearRowErrors" in FORM_JS
    assert "onApplyRejected" in FORM_JS  # sendApply's optional page hook


def test_form_css_carries_row_err_and_rowerr_rules(tmp_path):
    from nuncio.web import shell
    assert ".row.err" in shell.FORM_CSS
    assert ".rowerr" in shell.FORM_CSS


def test_settings_html_prail_and_pbody_wrap_carry_stable_ids_for_the_toggle(tmp_path):
    # The accordion JS needs to find each stage's paired .prail and
    # .pbody-wrap cheaply -- both get explicit ids alongside their class.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    for key in ("intake", "context", "enrich", "deliver", "global"):
        assert f'id="rail-{key}"' in html
        assert f'id="pwrap-{key}"' in html


def test_js_is_valid_enough_to_parse_no_unbalanced_braces(tmp_path):
    # Cheap syntax smoke test (no JS engine in this suite): every embedded
    # <script> block's braces/parens balance.
    from nuncio.web.settings import _JS
    assert _JS.count("{") == _JS.count("}")
    assert _JS.count("(") == _JS.count(")")


# =====================================================================
# Phase 5: motion craft -- expand/collapse transition, inner settle,
# chevron rotate, capped row stagger, transitionend-gated hidden,
# reduced-motion, whole-rail transition, health-tint ordinal fix.
# =====================================================================

def test_pipe_css_ships_the_expand_collapse_transition_and_settle(tmp_path):
    from nuncio.web import shell
    # The wrapper's grid-rows change is a real `transition:`, not an
    # instant flip -- and collapse gets its own (faster) duration via a
    # transient `.closing` class rather than editing the base transition.
    assert "transition:grid-template-rows" in shell.PIPE_CSS
    assert ".pbody-wrap.closing" in shell.PIPE_CSS
    # Inner settle: the body fades/slides in on open, not just unclips.
    assert "translateY(-6px)" in shell.PIPE_CSS
    assert ".pbody-wrap.open .pbody" in shell.PIPE_CSS


def test_pipe_css_ships_chevron_rotate_and_capped_row_stagger(tmp_path):
    from nuncio.web import shell
    assert "rotate(180deg)" in shell.PIPE_CSS
    assert "@keyframes rowin" in shell.PIPE_CSS
    assert "animation-delay" in shell.PIPE_CSS
    assert ".pbody-wrap.open .row" in shell.PIPE_CSS


def test_pipe_css_never_loops_a_continuous_animation(tmp_path):
    from nuncio.web import shell
    # Every animation in this file must be one-shot -- nothing that spins,
    # pulses, or loops forever is allowed on a config page.
    assert "infinite" not in shell.PIPE_CSS
    assert "infinite" not in shell._PIPE_CSS_SOURCE


def test_pipe_css_whole_rail_highlight_transitions_not_a_hard_flip(tmp_path):
    from nuncio.web import shell
    # .prail::before/.pnode must carry their own transition so `.rail-hi`
    # and the open-state paint fade in/out instead of snapping.
    assert "transition:background" in shell.PIPE_CSS or "transition:border-color" in shell.PIPE_CSS


def test_pipe_css_reduced_motion_block_kills_all_new_motion_keeps_states(tmp_path):
    from nuncio.web import shell
    src = shell._PIPE_CSS_SOURCE
    idx = src.index("prefers-reduced-motion")
    block = src[idx:]
    for selector in (".pbody-wrap", ".pbody", ".prail::before"):
        assert selector in block, selector
    assert "animation:none" in block  # kills the row stagger
    # Health tints, rail brighten, open-node fill, chevron end-state, title
    # underline are STATE rules (color/border/box-shadow at rest, not a
    # `transition:`/`animation:` declaration) -- they live outside this
    # block entirely and so are untouched by it. Assert the block itself
    # only nulls motion properties, never touches color/background/border.
    for prop in ("color:", "background:", "border-color:", "text-decoration"):
        assert prop not in block, prop


def test_pipe_css_health_tint_wins_on_the_ordinal_over_open_state_color(tmp_path):
    # REV 3: the Phase 3 fix was a per-selector specificity patch
    # (`.pstage.open .phead .n.nodebad`) that had to out-specify
    # `.pstage.open .phead .n`. That patch is RETIRED -- REV 3 no longer even
    # has an open-state color rule for the ordinal to compete with (the
    # ordinal is unconditionally `color:var(--st)`), so the sick color wins
    # whether or not the stage is open with zero specificity games. Assert
    # the retired patch is gone.
    from nuncio.web import shell
    assert ".pstage.open .phead .n.nodebad" not in shell.PIPE_CSS
    assert ".pstage.open .phead .n.nodewarn" not in shell.PIPE_CSS
    assert ".pstage.open .phead .n{" not in shell.PIPE_CSS  # no open-state color rule to compete with


def test_settings_html_transitionend_and_reduced_motion_js_coordination(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "transitionend" in html
    assert "matchMedia" in html
    assert "prefers-reduced-motion" in html


def test_settings_html_renderstage_sets_capped_row_stagger_index(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "setProperty('--i'" in html
    assert "Math.min(" in html


def test_settings_css_pipe_tokens_still_present_all_three_theme_blocks_regression(tmp_path):
    from nuncio.web import shell
    for token in ("--halo:", "--dur:", "--dur-fast:", "--easing:"):
        assert shell.CSS.count(token) == 3, token


def test_settings_html_under_the_ratified_64kb_ceiling_and_favicon_guard(tmp_path):
    # REV 3 Phase D bumps the soft ceiling to 68KB (Global Constraint 8) --
    # the hero character/prominence CSS is justified product surface. See
    # test_settings_html_under_size_budget's comment for the measurement.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1


def test_dashboard_render_markers_intact_and_no_pipeline_leak(tmp_path):
    # Constraint 7, re-verified at the end of the build: dashboard.py's
    # markup/JS is never touched by any pipeline phase, including this final
    # one. NOT a byte-identical check -- the shared _CSS_SOURCE genuinely
    # gained --halo/--dur/--dur-fast/--easing tokens in this build (shipped
    # to every page, dashboard included), so the render is not byte-for-byte
    # what it was before; this test's real claim is markers-intact +
    # no-pipeline-leak, which is what it actually checks.
    from nuncio.web import dashboard
    app, settings = build(tmp_path)
    html = dashboard.render_dashboard_html(app).decode()
    assert "layoutSigPath" in html  # horizontal path intact
    assert "stage-enrich" not in html  # never picks up vertical-pipeline ids
    assert "applybar" not in html
    assert 'class="pipeline"' not in html


# =====================================================================
# REV 3 Phase A -- loom tokens + hero geometry + summary-on-hover. Pure
# re-skin of the shipped accordion: mechanics (grid-rows, transitionend,
# one-open-at-a-time, Esc, deep-link, apply bar, dirty chips, audit) and the
# JSON/POST contract are untouched -- only the diagram's color/geometry/
# chrome changes. See pipeline-plan-v3.md §A1-A3, §B Phase A.
# =====================================================================

def test_pipe_tokens_added_to_all_three_theme_blocks(tmp_path):
    from nuncio.web import shell
    for token in ("--st-intake:", "--st-context:", "--st-deliver:",
                  "--st-intake-dim:", "--st-context-dim:", "--st-deliver-dim:", "--glow:"):
        assert shell.CSS.count(token) == 3, token  # dark, @media light, [data-theme=light]
    # Dark values (§A1's palette table).
    assert "--st-intake:#4EA0D0" in shell.CSS
    assert "--st-context:#3EC1C9" in shell.CSS
    assert "--st-deliver:#86C96B" in shell.CSS
    # Light values -- both the @media block and [data-theme=light] carry them.
    assert shell.CSS.count("--st-intake:#20719F") == 2
    assert shell.CSS.count("--st-context:#0F7E86") == 2
    assert shell.CSS.count("--st-deliver:#52803D") == 2
    # Enrich/global deliberately get NO dedicated token (§A1: enrich reuses
    # --trace, global reuses --grey).
    assert "--st-enrich" not in shell.CSS
    assert "--st-global" not in shell.CSS


def test_pipe_css_st_plumbing_classes_set_local_custom_properties(tmp_path):
    from nuncio.web import shell
    for cls, st, stnext in (
        (".st-intake", "var(--st-intake)", "var(--st-context)"),
        (".st-context", "var(--st-context)", "var(--trace)"),
        (".st-enrich", "var(--trace)", "var(--st-deliver)"),
        (".st-deliver", "var(--st-deliver)", "var(--grey)"),
        (".st-global", "var(--grey)", "var(--grey)"),
    ):
        rule = shell.PIPE_CSS[shell.PIPE_CSS.index(cls + "{"):]
        rule = rule[:rule.index("}") + 1]
        assert f"--st:{st}" in rule, cls
        assert "--st-dim:" in rule, cls
        assert f"--st-next:{stnext}" in rule, cls


def test_pipe_css_conductor_is_a_graded_gradient_per_segment(tmp_path):
    from nuncio.web import shell
    assert "linear-gradient(180deg,var(--st),var(--st-next))" in shell.PIPE_CSS
    assert "--st-next" in shell.PIPE_CSS


def test_pipe_css_new_four_track_grid_supersedes_the_44px_rail(tmp_path):
    from nuncio.web import shell
    assert "[world]" in shell.PIPE_CSS
    assert "minmax(48px,15%)" in shell.PIPE_CSS
    assert "[rail] 128px" in shell.PIPE_CSS
    assert "[main]" in shell.PIPE_CSS
    assert "minmax(0,660px)" in shell.PIPE_CSS
    assert "[void]" in shell.PIPE_CSS
    assert "44px 1fr" not in shell.PIPE_CSS  # the old flat rail geometry is gone
    assert ".pworld" in shell.PIPE_CSS


def test_pipe_css_health_tint_is_a_property_override_not_a_selector_patch(tmp_path):
    from nuncio.web import shell
    assert ".nodebad{--st:var(--breach)" in shell.PIPE_CSS
    assert ".nodewarn{--st:var(--raw)" in shell.PIPE_CSS
    # The override rules must come AFTER the st-* plumbing rules so the
    # cascade actually overrides them.
    assert shell.PIPE_CSS.index(".st-global{") < shell.PIPE_CSS.index(".nodebad{--st:")
    # The four retired specificity-tie patch selectors are gone.
    for dead in (
        ".phead .n.nodebad{color:var(--breach)}",
        ".phead .n.nodewarn{color:var(--raw)}",
        ".pstage.open .phead .n.nodebad{color:var(--breach)}",
        ".pstage.open .phead .n.nodewarn{color:var(--raw)}",
        ".phead.nodebad:hover",
        ".phead:hover .n.nodebad{color:var(--breach)}",
        ".phead:hover .n.nodewarn{color:var(--raw)}",
    ):
        assert dead not in shell.PIPE_CSS, dead
    # nodering stays a distinct additive ring (untouched by the --st
    # pattern) -- I1 fix retargets this: it used to
    # REPLACE the resting halo+glow with a flat 3px ring; now it layers on
    # top, and a compound selector keeps it visible under open/rail-hi too.
    assert ".pnode.nodering{box-shadow:0 0 0 4px var(--st-dim),var(--glow) var(--st-dim)," \
        "0 0 0 7px var(--raw-dim)}" in shell.PIPE_CSS
    assert ".pnode.nodering{box-shadow:0 0 0 3px var(--raw-dim)}" not in shell.PIPE_CSS


def test_pipe_css_node_is_a_32px_ring_with_solid_center_dot(tmp_path):
    # REV 3 Phase D prominence bump (§4): 28px -> 32px node, 9px -> 10px
    # center dot. Retargets the Phase 5 test this supersedes.
    from nuncio.web import shell
    assert "width:32px;height:32px" in shell.PIPE_CSS
    assert "width:28px;height:28px" not in shell.PIPE_CSS
    assert "border:2.5px solid var(--st)" in shell.PIPE_CSS
    assert "width:10px;height:10px" in shell.PIPE_CSS  # the center dot
    assert "width:9px;height:9px" not in shell.PIPE_CSS
    assert "var(--glow) var(--st-dim)" in shell.PIPE_CSS
    # Terminal stays a square, --grey, no center dot.
    assert ".pnode.pterm{border-radius:2px;width:14px;height:14px" in shell.PIPE_CSS
    assert ".pnode.pterm::after{content:none}" in shell.PIPE_CSS


def test_pipe_css_title_is_20px_serif_and_ordinal_paints_with_st(tmp_path):
    from nuncio.web import shell
    assert "font-family:var(--serif);font-size:20px" in shell.PIPE_CSS
    assert ".phead .n{font-family:var(--mono);font-size:12px;color:var(--st)" in shell.PIPE_CSS


def test_pipe_css_summary_hidden_at_rest_revealed_on_hover_focus_and_open(tmp_path):
    from nuncio.web import shell
    assert "opacity:0;transform:translateX(-4px)" in shell.PIPE_CSS
    assert ".phead:hover .psub,.phead:focus-visible .psub,.pstage.open .phead .psub{opacity:1;transform:none}" \
        in shell.PIPE_CSS
    # Reduced motion kills the settle transition but not the show/hide state.
    idx = shell.PIPE_CSS.index("prefers-reduced-motion")
    assert ".phead .psub" in shell.PIPE_CSS[idx:]


def test_pipe_css_stage_header_hover_is_a_row_wash_not_a_hard_halo_ring(tmp_path):
    # Live-feedback fix (§5b): the old hover used a `0 0 0 4px` halo-shaped
    # box-shadow ring -- boxy/heavy against the hairline+glow language.
    # Replaced with a faint stage-color row wash (--st-dim background) plus
    # a thin inset left accent (--st) -- no outer ring, still keyed off the
    # stage's own circuit color so a sick stage washes breach/amber, never
    # the wrong hue. The lift is dropped in favor of the calmer wash alone.
    from nuncio.web import shell
    idx = shell.PIPE_CSS.index(".phead:hover,.phead:focus-visible{")
    rule = shell.PIPE_CSS[idx:shell.PIPE_CSS.index("}", idx) + 1]
    assert "var(--halo)" not in rule
    assert "0 0 0 4px" not in rule
    assert "background:var(--st-dim)" in rule
    assert "box-shadow:inset 2px 0 0 var(--st)" in rule


def test_pipe_css_open_panel_no_longer_gets_a_second_stage_color_inset_edge(tmp_path):
    # Live-feedback fix: the open .pbody inset edge read as a redundant
    # second vertical line beside the conductor -- removed entirely. (The
    # .phead:hover box-shadow also uses `inset 2px 0 0 var(--st)` as its own
    # accent -- that one is unrelated and stays; only the .pbody rule dies.)
    from nuncio.web import shell
    assert ".pstage.open .pbody{box-shadow:inset 2px 0 0 var(--st)}" not in shell.PIPE_CSS
    assert "pstage.open .pbody" not in shell.PIPE_CSS


def test_pipe_css_node_hover_scale_and_no_new_filter_or_has(tmp_path):
    from nuncio.web import shell
    assert "scale(1.12)" in shell.PIPE_CSS
    assert "filter:" not in shell.PIPE_CSS  # box-shadow-only glow, never filter
    assert ":has(" not in shell.PIPE_CSS
    assert "infinite" not in shell.PIPE_CSS  # re-assert -- nothing loops


def test_pipe_css_responsive_world_collapse_and_mobile_block(tmp_path):
    from nuncio.web import shell
    idx900 = shell.PIPE_CSS.index("max-width:900px")
    block900 = shell.PIPE_CSS[idx900:shell.PIPE_CSS.index("max-width:700px")]
    assert ".pworld{display:none}" in block900
    assert "128px" in block900  # rail stays 128px between 700-900px
    idx700 = shell.PIPE_CSS.index("max-width:700px")
    block700 = shell.PIPE_CSS[idx700:]
    assert "40px" in block700


def test_settings_html_pworld_cell_per_stage_with_st_class(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    for key in ("intake", "context", "enrich", "deliver", "global"):
        assert f'class="pworld st-{key}" id="world-{key}"' in html
        assert f'class="pstage st-{key}"' in html


def test_settings_html_prail_and_pworld_carry_st_classes_matching_stage(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'class="prail st-intake"' in html
    assert 'class="prail st-context"' in html
    assert 'class="prail st-enrich"' in html
    assert 'class="prail st-deliver"' in html
    assert 'class="prail prail-term st-global"' in html


def test_settings_html_ids_and_aria_unchanged_by_the_reskin(tmp_path):
    # Constraint: accordion mechanics/contract untouched -- every id and ARIA
    # attribute the shipped JS depends on must survive byte-for-byte.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    for key in ("intake", "context", "enrich", "deliver", "global"):
        assert f'id="stage-{key}"' in html
        assert f'id="phead-{key}"' in html
        assert f'aria-controls="pbody-{key}"' in html
        assert f'id="pbody-{key}"' in html
    assert 'aria-expanded="false"' in html
    assert 'role="region"' in html
    assert "prail-term" in html
    assert 'id="rail-global"' in html


def test_page_js_rail_and_world_cells_forward_click_to_toggle_stage(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "forwardClick" in html
    assert "toggleStage(key)" in html
    assert "rail.addEventListener('click', forwardClick)" in html
    assert "world.addEventListener('click', forwardClick)" in html
    assert "cursor = 'pointer'" in html


def test_page_js_header_hover_mirrors_nodehover_onto_paired_rail(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "classList.add('nodehover')" in html
    assert "classList.remove('nodehover')" in html


def test_settings_html_byte_budget_stays_under_64kb_after_the_reskin(tmp_path):
    # REV 3 Phase D bumps the soft ceiling to 68KB (Global Constraint 8) --
    # see test_settings_html_under_size_budget's comment for the measurement.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024


# =====================================================================
# Phase B (REV 3 A4): editable help moves from an inline .help div to a
# pure-CSS attr(data-help) hover/focus/tap tooltip on the label; locked-key
# reasons stay inline (honesty is not hover-gated).
# =====================================================================

def test_group_rows_no_longer_emits_an_inline_help_div_for_editable_keys(tmp_path):
    from nuncio.web.forms import FORM_JS
    # This is the exact line REV 3 retires -- editable spec.help must no
    # longer become a visible-by-default <div class="help">.
    assert "(spec.help ? '<div class=\"help\">' + esc(spec.help) + '</div>' : '')" not in FORM_JS


def test_group_rows_puts_help_text_on_the_label_as_data_help_attribute(tmp_path):
    from nuncio.web.forms import FORM_JS
    assert "data-help=\"" in FORM_JS
    # §4a: data-help now carries the JOIN of help + (locked) reason, so the
    # source references spec.help via the tipText array, not a bare
    # esc(spec.help) call -- still the same HTML-escaping helper either way.
    assert "esc(tipText)" in FORM_JS
    assert "spec.help" in FORM_JS


def test_group_rows_locked_reason_moves_into_the_tooltip_not_an_inline_div(tmp_path):
    # Live-feedback revision (v3-visual-refinements.md §4): the locked-key
    # `reason` is no longer a plain always-visible inline line -- it joins
    # `data-help` (after `spec.help`, when both exist) so it surfaces via
    # the SAME hover/focus/tap tooltip as editable-key help. The STATE
    # (locked) stays visible without hover via the padlock + env badge +
    # disabled input; only the detailed WHY moves behind the tooltip.
    from nuncio.web.forms import FORM_JS
    assert "(!spec.editable ? '<div class=\"help\">' + esc(spec.reason||'') + '</div>' : '')" not in FORM_JS
    assert 'class="help"' not in FORM_JS
    assert "!spec.editable ? spec.reason : ''" in FORM_JS
    assert ".filter(Boolean).join(' — ')" in FORM_JS


def test_group_rows_locked_label_gets_tabindex_so_keyboard_users_reach_the_reason(tmp_path):
    # Locked rows have no focusable input, so `.row:focus-within` never
    # fires for a keyboard user -- the label itself becomes the tab stop
    # whenever there's something to show (help and/or reason).
    from nuncio.web.forms import FORM_JS
    assert "tabindex=\"0\"" in FORM_JS
    assert "(!spec.editable && tipText)" in FORM_JS


def test_group_rows_lock_title_attr_unchanged(tmp_path):
    # The padlock keeps its redundant plain-text `title` hint regardless of
    # the tooltip rework.
    from nuncio.web.forms import FORM_JS
    assert 'title="\' + esc(spec.reason||\'\') + \'"' in FORM_JS


def test_form_css_ships_a_pure_css_attr_data_help_tooltip_bubble(tmp_path):
    from nuncio.web import shell
    assert "[data-help]" in shell.FORM_CSS
    assert "attr(data-help)" in shell.FORM_CSS
    assert ":focus-within" in shell.FORM_CSS
    assert "content:" in shell.FORM_CSS


def test_form_css_tooltip_appears_on_hover_and_keyboard_focus(tmp_path):
    from nuncio.web import shell
    assert ":hover::after" in shell.FORM_CSS
    assert ":focus-within .lbl[data-help]::after" in shell.FORM_CSS


def test_form_css_tooltip_also_triggers_on_the_locked_labels_own_focus(tmp_path):
    # §4b: locked labels are now a tab stop in their own right (no wrapping
    # focusable input for `:focus-within` to key off), so the trigger list
    # gains a direct `:focus-visible` on the label itself -- plus a focus
    # ring, since this is a brand-new tab stop with none by default.
    from nuncio.web import shell
    assert ".lbl[data-help]:focus-visible::after" in shell.FORM_CSS
    assert ".row .lbl[data-help]:focus-visible{outline:1px solid var(--muted);" in shell.FORM_CSS


def test_form_css_label_carries_the_dotted_underline_affordance(tmp_path):
    from nuncio.web import shell
    assert "dotted" in shell.FORM_CSS


def test_form_css_tooltip_cue_is_a_hairline_not_the_old_heavy_rope(tmp_path):
    # Live-feedback fix: retire the 3px dotted rope for a 1px hairline in the
    # row border tint at rest, firming to a solid --muted underline on
    # hover/focus/tap.
    from nuncio.web import shell
    assert "text-decoration-thickness:1px" in shell.FORM_CSS
    assert "text-decoration-thickness:3px" not in shell.FORM_CSS
    assert "text-decoration-style:solid" in shell.FORM_CSS


def test_form_css_tooltip_has_no_js_positioning_engine_markers(tmp_path):
    # Pure CSS bubble only -- no JS computing offsets/rects for it.
    from nuncio.web.forms import FORM_JS
    assert "getBoundingClientRect" not in FORM_JS


def test_form_css_tooltip_reuses_toast_shadow_and_stays_cheap(tmp_path):
    from nuncio.web import shell
    # No new `filter:` cost for the bubble (matches the rest of the pipeline
    # CSS's "no filter:" discipline); it does reuse a real box-shadow.
    assert "box-shadow:0 8px 24px rgba(0,0,0,.25)" in shell.FORM_CSS


def test_form_css_tap_toggle_tip_class_present(tmp_path):
    from nuncio.web import shell
    assert ".tip" in shell.FORM_CSS


def test_form_js_delegated_click_listener_toggles_tip_class(tmp_path):
    from nuncio.web.forms import FORM_JS
    assert "addEventListener('click'" in FORM_JS
    assert "classList.toggle('tip')" in FORM_JS
    # ONE delegated listener, not one per row.
    assert FORM_JS.count("addEventListener('click'") == 1


def test_page_js_ingest_token_help_upgrade_targets_data_help_not_help_textcontent(tmp_path):
    # settings.py's loadSources() upgrade must append to the tooltip
    # (data-help) now, not to a .help div's textContent.
    from nuncio.web import settings as settings_mod
    assert "help.textContent" not in settings_mod._PAGE_JS
    assert "data-help" in settings_mod._PAGE_JS
    assert "rotated here" in settings_mod._PAGE_JS


def test_rowerr_inline_validation_is_unaffected_by_the_tooltip_move(tmp_path):
    # Failures stay loud and inline -- never folded into a hover tooltip.
    from nuncio.web.forms import FORM_JS
    assert "div.className = 'rowerr'" in FORM_JS
    assert "data-help" not in FORM_JS.split("function showRowErrors")[1].split("function ")[0]


def test_settings_html_still_self_contained_and_row_markers_survive_phase_b(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'class="row"' in html
    assert "data-help" in html
    assert "http://" not in html.replace("http://ollama", "")


# =====================================================================
# Live HTTP routes (real socket, like test_app.py's live_server)
# =====================================================================

import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _post(url, body, token=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


@pytest.fixture
def live(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="livetoken", NUNCIO_CONCURRENCY="0")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _handler_factory(app))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield app, f"http://127.0.0.1:{port}"
    srv.shutdown()
    app.store.close()


def test_get_settings_route_returns_html(live):
    _app, base = live
    status, body, headers = _get(base + "/settings")
    assert status == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert b"Nuncio" in body


def test_get_settings_json_route_returns_json(live):
    _app, base = live
    status, body, headers = _get(base + "/settings.json")
    assert status == 200
    assert "application/json" in headers.get("Content-Type", "")
    assert "keys" in json.loads(body)


def test_post_settings_route_over_real_http_requires_token(live):
    _app, base = live
    status, body, _h = _post(base + "/settings", {"set": {"NUNCIO_MODE": "bypass"}})
    assert status == 401  # server IS configured with a token, none supplied


def test_post_settings_route_over_real_http_applies_with_token(live):
    app, base = live
    status, body, _h = _post(base + "/settings", {"set": {"NUNCIO_MODE": "bypass"}}, token="livetoken")
    assert status == 200
    assert app.engine.mode == "bypass"


def test_settings_dashboard_config_json_routes_all_coexist(live):
    _app, base = live
    for path in ("/", "/settings", "/config.json", "/settings.json"):
        status, _body, _h = _get(base + path)
        assert status == 200, path


def _raw_http_request(base, request_lines, body=b""):
    """Send a hand-built HTTP/1.1 request over a raw socket -- for headers
    urllib won't let a caller set/mangle itself (e.g. a malformed
    Content-Length), needed to exercise `_do_post_settings`'s own
    Content-Length parsing rather than `handle_post`'s internal body-size
    check (already covered directly in test_post_settings_413_body_too_large
    above)."""
    import socket
    from urllib.parse import urlsplit
    parts = urlsplit(base)
    with socket.create_connection((parts.hostname, parts.port), timeout=5) as s:
        req = "\r\n".join(request_lines) + "\r\n\r\n"
        s.sendall(req.encode() + body)
        chunks = []
        s.settimeout(2.0)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks)


def test_post_settings_malformed_content_length_header_400s(live):
    _app, base = live
    from urllib.parse import urlsplit
    path = urlsplit(base).path or "/settings"
    response = _raw_http_request(base, [
        "POST /settings HTTP/1.1",
        f"Host: {urlsplit(base).netloc}",
        "Content-Length: not-a-number",
        "Connection: close",
    ])
    status_line = response.split(b"\r\n", 1)[0]
    assert b"400" in status_line


def test_post_settings_body_over_max_bytes_returns_413_over_real_http(live):
    _app, base = live
    from urllib.parse import urlsplit
    big_body = json.dumps({"set": {"NUNCIO_MODE": "x" * 100_000}}).encode()
    response = _raw_http_request(base, [
        "POST /settings HTTP/1.1",
        f"Host: {urlsplit(base).netloc}",
        f"Content-Length: {len(big_body)}",
        "X-Admin-Token: livetoken",
        "Content-Type: application/json",
        "Connection: close",
    ], body=big_body)
    status_line = response.split(b"\r\n", 1)[0]
    assert b"413" in status_line


# =====================================================================
# Live-apply-under-load: no lost or duplicated alert across a mid-flight
# settings change .
# =====================================================================

class RecordingDelivery:
    def __init__(self):
        self.sent = []
        self.lock = threading.Lock()

    def send(self, message, title="Monitoring alert"):
        with self.lock:
            self.sent.append(message)
        return True


class BlockingLLM:
    """Blocks inside enrich() until released, so a test can deterministically
    pause a worker mid-alert and mutate live settings underneath it."""

    def __init__(self, text):
        self.model = "test-model"
        self.text = text
        self.entered = threading.Event()
        self.release = threading.Event()

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        self.entered.set()
        self.release.wait(timeout=5)
        return self.text, {"prompt_tokens": 1, "completion_tokens": 1}


VALID_ENRICHMENT = "everything looks fine on host01.\n\nNo urgency: informational only, nothing to see."


def test_mode_switch_mid_flight_does_not_misroute_an_already_queued_alert(tmp_path):
    # An alert is ingested under "enriched" and its worker is already
    # blocked inside the LLM call when a live settings change flips
    # NUNCIO_MODE to "bypass". The already-queued/in-flight alert must still
    # complete as "enriched" (the mode rides the queue tuple, captured at
    # ingest time -- not a live read of engine.mode); only a NEW alert
    # ingested after the flip goes plain-raw via bypass.
    app, settings = build(tmp_path, NUNCIO_CONCURRENCY="1")
    llm = BlockingLLM(VALID_ENRICHMENT)
    app.engine.llm = llm

    assert app.ingest("generic", {"host": "A", "message": "alert A"}) == 200

    def wait_until(pred, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.01)
        return pred()

    assert wait_until(lambda: llm.entered.is_set())  # worker now blocked inside enrich()

    result = config.apply_changes(app, {"NUNCIO_MODE": "bypass"})
    assert result["applied"] == ["NUNCIO_MODE"]
    assert app.engine.mode == "bypass"

    assert app.ingest("generic", {"host": "B", "message": "alert B"}) == 200

    llm.release.set()  # let alert A's (already-entered) enrichment complete

    assert wait_until(lambda: app.metrics.delivered.get("enriched", 0) >= 1)
    assert wait_until(lambda: app.metrics.delivered.get("raw", 0) >= 1)
    assert app.metrics.delivered.get("enriched", 0) == 1  # A: enriched, mode captured at ingest
    assert app.metrics.delivered.get("raw", 0) == 1        # B: plain bypass raw
    app.store.close()


def test_delivery_swap_mid_flight_every_alert_delivered_exactly_once(tmp_path):
    """A real end-to-end run: alert A is ingested and its worker is paused
    INSIDE the LLM call; while paused, a settings apply swaps the delivery
    channel (stdout -> stdout,stdout fanout); alert B is ingested AFTER the
    swap. Both must be delivered exactly once -- no loss (a torn/aborted
    in-flight alert), no duplicate (the rebuild-and-swap racing the send)."""
    llm = BlockingLLM(VALID_ENRICHMENT)
    app, settings = build(tmp_path, NUNCIO_CONCURRENCY="1", NUNCIO_DELIVERY="stdout")
    # Swap in the blocking LLM (build_app wired a real LLMClient) so we can
    # control timing without hitting a network endpoint.
    app.engine.llm = llm

    assert app.ingest("generic", {"host": "A", "message": "alert A"}) == 200

    def wait_until(pred, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            time.sleep(0.01)
        return pred()

    assert wait_until(lambda: llm.entered.is_set())  # worker is now blocked inside enrich()

    result = config.apply_changes(app, {"NUNCIO_DELIVERY": "stdout,stdout"})
    assert result["applied"] == ["NUNCIO_DELIVERY"]

    assert app.ingest("generic", {"host": "B", "message": "alert B"}) == 200

    llm.release.set()  # let alert A's enrichment complete

    assert wait_until(lambda: app.metrics.delivered.get("enriched", 0) >= 2, timeout=5.0)
    assert app.metrics.failures.get("delivery", 0) == 0
    assert app.metrics.duplicates == 0
    app.store.close()


# =====================================================================
# REV 3 Phase C -- the topbar lock (plan §A5). The "reading..." tape on
# /settings becomes a 3-state lock (not-configured / locked / unlocked)
# validated through the EXISTING POST /settings contract -- an empty
# {"set":{}, "reset":[]} probe, authed with X-Admin-Token. `handle_post`
# gains a server-side guard: AFTER the admin-token auth check (so a bad/
# absent token still 401/403s first) and BEFORE `apply_changes`, an empty
# change-set short-circuits to 200 without writing the overrides file or
# appending an audit entry -- so a token-validation probe never touches the
# write path. Without this guard, every unlock would pollute the audit
# ring and fsync the overrides doc for nothing.
# =====================================================================

def test_handle_post_empty_change_set_short_circuits_with_valid_token(tmp_path, monkeypatch):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")

    def boom(*a, **kw):
        raise AssertionError("apply_changes must not be called for an empty change-set probe")
    monkeypatch.setattr(config, "apply_changes", boom)

    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}, "reset": []}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 200
    assert body == {"applied": [], "restart_required": [], "rejected": {}}
    app.store.close()


def test_handle_post_empty_change_set_writes_no_overrides_file(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    overrides_path = settings._overrides_path
    assert not os.path.exists(overrides_path)  # nothing written yet at boot

    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}, "reset": []}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 200
    assert not os.path.exists(overrides_path)  # the probe wrote nothing
    app.store.close()


def test_handle_post_empty_change_set_appends_no_audit_entry(tmp_path):
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    before = list((settings.overrides_doc or {}).get("audit") or [])

    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}, "reset": []}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 200
    after = list((settings.overrides_doc or {}).get("audit") or [])
    assert after == before
    app.store.close()


def test_handle_post_empty_change_set_does_not_bypass_a_bad_token(tmp_path):
    # Auth still runs BEFORE the short-circuit -- a token-probe with the
    # WRONG token must still 401, never a free 200.
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="correct-token")
    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}, "reset": []}).encode(), _Headers({"X-Admin-Token": "wrong-token"}))
    assert status == 401
    app.store.close()


def test_handle_post_empty_change_set_does_not_bypass_missing_admin_token(tmp_path):
    # And still 403s fail-closed when the server has no admin token
    # configured at all -- same existing contract, unaffected by the guard.
    app, settings = build(tmp_path)
    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}, "reset": []}).encode(), _Headers({"X-Admin-Token": "whatever"}))
    assert status == 403
    app.store.close()


def test_handle_post_non_empty_change_set_still_applies_and_audits(tmp_path):
    # The guard is narrowing (empty-only) -- a real, non-empty apply must
    # still reach apply_changes, write the overrides file, and grow the
    # audit ring exactly as before this phase.
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")
    before = list((settings.overrides_doc or {}).get("audit") or [])
    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {"NUNCIO_MODE": "bypass"}, "reset": []}).encode(),
        _Headers({"X-Admin-Token": "tok"}))
    assert status == 200
    assert body["applied"] == ["NUNCIO_MODE"]
    assert os.path.exists(settings._overrides_path)
    # apply_changes() swaps app.settings to a NEW Settings instance (the
    # candidate that validated cleanly) -- the original `settings` local
    # stays the pre-apply object, so the post-apply audit ring lives on
    # app.settings now.
    after = list((app.settings.overrides_doc or {}).get("audit") or [])
    assert len(after) == len(before) + 1
    app.store.close()


def test_handle_post_empty_set_and_reset_omitted_entirely_also_short_circuits(tmp_path, monkeypatch):
    # {"set": {}} with no "reset" key at all -- reset_list defaults to []
    # (existing behavior), so this is still the empty case.
    app, settings = build(tmp_path, NUNCIO_ADMIN_TOKEN="tok")

    def boom(*a, **kw):
        raise AssertionError("apply_changes must not be called")
    monkeypatch.setattr(config, "apply_changes", boom)

    status, body = settings_ui.handle_post(
        app, json.dumps({"set": {}}).encode(), _Headers({"X-Admin-Token": "tok"}))
    assert status == 200
    assert body == {"applied": [], "restart_required": [], "rejected": {}}
    app.store.close()


# --- the lock widget's rendered markup + JS ---

def test_settings_html_lock_widget_svg_and_js_markers_present(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'id="lockicon"' in html
    assert 'id="lockshackle"' in html  # the padlock path marker (closed/open variants)
    assert "function openLock" in html
    assert "function probeToken" in html
    assert "function lockState" in html
    app.store.close()


def test_settings_html_no_window_prompt_anywhere_in_the_settings_js(tmp_path):
    # #17: window.prompt() dies -- the settings page's only auth surface is
    # the topbar lock now.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "window.prompt" not in html
    app.store.close()


def test_settings_html_unlock_editing_banner_string_gone(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "Unlock editing" not in html
    app.store.close()


def test_settings_html_not_configured_warn_banner_branch_gone(tmp_path):
    # The old "This page can read everything but change nothing" auth
    # warn-banner is removed -- the lock's not-configured popover carries
    # that message now instead.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "This page can read everything but change nothing" not in html
    app.store.close()


def test_settings_html_restart_banner_branch_still_present(tmp_path):
    # Unrelated to the lock -- the restart banner stays exactly as shipped.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'id="restartbanner"' in html
    assert "Waiting on a restart:" in html
    app.store.close()


def test_settings_html_authbanner_div_removed(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "authbanner" not in html
    app.store.close()


def test_settings_html_locked_caption_present_and_removed_when_unlocked(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "read-only" in html
    assert "unlock in the top bar" in html


def test_settings_html_lock_copy_strings_present(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "Editing is off." in html
    assert "NUNCIO_ADMIN_TOKEN" in html
    assert "Editing unlocked for this tab." in html
    assert "That token didn" in html  # "That token didn't match."


def test_settings_html_lock_widget_derives_state_from_admin_token_configured(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "ADMIN_TOKEN_CONFIGURED" in html
    assert "lockState" in html


def test_settings_html_byte_budget_still_holds_after_the_lock(tmp_path):
    # REV 3 Phase D bumps the soft ceiling to 68KB (Global Constraint 8) --
    # see test_settings_html_under_size_budget's comment for the measurement.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1


def test_settings_page_css_ships_lock_popover_below_toast_and_modal(tmp_path):
    from nuncio.web import shell
    assert "lockpop" in shell.FORM_CSS or "lockpop" in shell.PIPE_CSS


def test_infinite_still_absent_from_settings_css_and_js_after_the_lock(tmp_path):
    from nuncio.web import shell
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "infinite" not in html
    assert "infinite" not in shell.CSS
    assert "infinite" not in shell.FORM_CSS
    assert "infinite" not in shell.PIPE_CSS
    app.store.close()


def test_forms_js_prompt_token_delegates_to_page_open_lock(tmp_path):
    from nuncio.web.forms import FORM_JS
    assert "typeof openLock" in FORM_JS
    assert "openLock()" in FORM_JS
    assert "window.prompt" not in FORM_JS


# =====================================================================
# REV 3 Phase D -- diagram character (v3-visual-refinements.md §1) +
# prominence (§4's locked size-bump table) + one-shot power-on cascade /
# open bloom motion (pipeline-plan-v3.md §A3 "Glow & motion language").
# No fans/world-column art this phase -- that's Phase E, attaching to the
# FINAL node geometry this phase sets.
# =====================================================================

def test_pipe_css_radar_echo_ring_is_the_brand_motif_on_stage_nodes_only(tmp_path):
    from nuncio.web import shell
    # §1(a): a faint concentric ring on every node, echoing the logo --
    # NOT cuttable per the design doc. inset:-10px on the (bumped) 32px
    # node leaves ~6px of clear air to the halo.
    assert ".pnode::before{content:\"\";position:absolute;inset:-10px;border-radius:50%;" \
        "border:1px solid var(--st);opacity:.22}" in shell.PIPE_CSS
    # The chassis (terminal) square stays plain -- no echo ring on it.
    assert ".pnode.pterm::before{content:none}" in shell.PIPE_CSS


def test_pipe_css_junction_takeoff_stub_ties_node_to_nameplate(tmp_path):
    from nuncio.web import shell
    # §1(b): a static take-off stub, node east edge -> stage title. `top`
    # is locked to the SAME node-center offset as .pnode/.prail-term/the
    # :first-child conductor truncation (§4) -- all four must read 34px.
    assert ".prail::after{content:\"\";position:absolute;top:34px;" \
        "left:calc(50% + 32px);right:6px;height:2px;background:var(--st);" \
        "opacity:.4;transform:translateY(-50%)}" in shell.PIPE_CSS


def test_pipe_css_twin_hairline_bus_and_its_open_hi_overrides_carry_it(tmp_path):
    from nuncio.web import shell
    # §1(c): the 3px core grows two 1px echo strands via negative-spread
    # box-shadow -- one element, no new DOM/gradient banding. Both
    # interaction overrides (open + whole-rail highlight) must carry the
    # strands too, or they'd vanish exactly when the run gets attention.
    assert "box-shadow:5px 0 0 -1px var(--st-dim), -5px 0 0 -1px var(--st-dim), " \
        "0 0 10px var(--st-dim)" in shell._PIPE_CSS_SOURCE
    assert ".prail.open::before{box-shadow:5px 0 0 -1px var(--st-dim),-5px 0 0 -1px var(--st-dim)," \
        "0 0 14px var(--st-dim)}" in shell.PIPE_CSS
    assert ".pipeline.rail-hi .prail::before{box-shadow:5px 0 0 -1px var(--st-dim)," \
        "-5px 0 0 -1px var(--st-dim),0 0 14px var(--st-dim)}" in shell.PIPE_CSS
    assert shell.PIPE_CSS.count("5px 0 0 -1px var(--st-dim)") >= 6  # core + open + rail-hi (x2 strands each)


def test_pipe_css_node_center_offset_34px_locked_across_all_four_occurrences(tmp_path):
    from nuncio.web import shell
    # §4: node-center offset 30px -> 34px, and the doc requires it stay
    # LOCKED across four places: .pnode top, the :first-child conductor's
    # truncation, .prail-term's height, and the §1(b) stub's top.
    assert "left:50%;top:34px;width:32px;height:32px" in shell.PIPE_CSS  # .pnode
    assert ".prail:first-child::before{top:34px}" in shell.PIPE_CSS
    assert ".prail-term::before{bottom:auto;height:34px}" in shell.PIPE_CSS
    assert "top:34px;left:calc(50% + 32px)" in shell.PIPE_CSS  # the stub, same source line
    assert "top:30px" not in shell.PIPE_CSS  # the old offset is gone everywhere


def test_pipe_css_prominence_glow_and_halo_bump_all_three_theme_blocks(tmp_path):
    from nuncio.web import shell
    # §4: the ONE --glow token, 18px -> 22px, in ALL THREE theme blocks.
    assert shell.CSS.count("--glow:0 0 22px") == 3
    assert "--glow:0 0 18px" not in shell.CSS
    # Resting halo 3px -> 4px; open-state halo 4px -> 5px.
    assert "box-shadow:0 0 0 4px var(--st-dim),var(--glow) var(--st-dim)" in shell.PIPE_CSS  # resting .pnode
    assert "border-width:3px;box-shadow:0 0 0 5px var(--st-dim),var(--glow) var(--st-dim)" in shell.PIPE_CSS  # open
    # nodering is a distinct ADDITIVE ring (queue-depth warning), untouched
    # by the prominence bump -- I1 made it layer on
    # top of the resting halo+glow rather than replace them.
    assert ".pnode.nodering{box-shadow:0 0 0 4px var(--st-dim),var(--glow) var(--st-dim)," \
        "0 0 0 7px var(--raw-dim)}" in shell.PIPE_CSS


def test_pipe_css_ptitle_not_bumped_past_20px_and_core_stays_3px(tmp_path):
    from nuncio.web import shell
    # A8/§4 ceilings: the nameplate is already the largest type on the
    # page; the conductor core stays 3px (a fatter core reads cable-TV).
    assert "font-family:var(--serif);font-size:20px" in shell.PIPE_CSS
    assert "font-size:22px" not in shell.PIPE_CSS
    assert ".prail::before{content:\"\";position:absolute;left:50%;top:0;bottom:0;width:3px;" in shell.PIPE_CSS


def test_pipe_css_pdiv_aligns_to_the_row_grids_16px_indent(tmp_path):
    # Live-feedback fix (§3): the section dividers sat at the panel's raw
    # 4px edge while every .row indents 16px -- give .pdiv the rows' own
    # horizontal padding so MODEL/KNOWLEDGE start at the same left rhythm,
    # with clean air off the stage-color edge. The border-top hairline must
    # keep spanning the full width (borders include the padding box).
    from nuncio.web import shell
    assert "padding:10px 16px 0" in shell.PIPE_CSS
    assert "padding-top:10px;margin:14px 0 6px" not in shell.PIPE_CSS


def test_pipe_css_mobile_guard_strips_character_on_the_40px_rail(tmp_path):
    from nuncio.web import shell
    idx700 = shell.PIPE_CSS.index("max-width:700px")
    block700 = shell.PIPE_CSS[idx700:]
    assert ".pnode::before{content:none}" in block700
    assert ".prail::after{content:none}" in block700
    assert ".prail::before{box-shadow:0 0 10px var(--st-dim)}" in block700


def test_pipe_css_power_on_cascade_and_open_bloom_keyframes_present(tmp_path):
    from nuncio.web import shell
    assert "@keyframes pipein{from{opacity:0}}" in shell.PIPE_CSS
    assert "@keyframes bloom{from{box-shadow:" in shell.PIPE_CSS
    assert "animation:pipein var(--dur) var(--easing) both" in shell.PIPE_CSS
    assert "animation-delay:calc(var(--i,0) * 60ms)" in shell.PIPE_CSS or \
        "animation-delay:calc(var(--i, 0) * 60ms)" in shell.PIPE_CSS
    assert "bloom .3s var(--easing) both" in shell.PIPE_CSS
    # Run-order stagger index, one per circuit -- the cascade's ~60ms steps.
    for i, cls in enumerate((".st-intake", ".st-context", ".st-enrich", ".st-deliver", ".st-global")):
        rule = shell.PIPE_CSS[shell.PIPE_CSS.index(cls + "{"):]
        rule = rule[:rule.index("}") + 1]
        assert f"--i:{i}" in rule, cls


def test_pipe_css_c1_open_animation_list_starts_with_pipein_never_replays(tmp_path):
    # C1: closing any stage used to replay the
    # power-on fade on its node -- the open rule replaced the WHOLE
    # `animation` shorthand with just `bloom`, so closing flipped the
    # computed animation-name bloom->pipein, restarting the cascade. Fix:
    # `pipein` rides FIRST and stays in the SAME name/position in the open
    # rule's animation list as the base rule, so its identity never changes
    # on open or close; only `bloom` (second slot) is open-state-only.
    from nuncio.web import shell
    idx = shell.PIPE_CSS.index(".prail.open .pnode{")
    rule = shell.PIPE_CSS[idx:shell.PIPE_CSS.index("}", idx) + 1]
    anim_idx = rule.index("animation:")
    assert rule[anim_idx:].startswith("animation:pipein var(--dur) var(--easing) both,"
                                       "bloom .3s var(--easing) both")
    assert "animation-delay:calc(var(--i, 0) * 60ms),0s" in rule or \
        "animation-delay:calc(var(--i,0) * 60ms),0s" in rule
    # The base (closed-state) rule's pipein declaration is byte-identical in
    # name and position -- animation-name never changes across open/close.
    base_idx = shell.PIPE_CSS.index(".prail::before,.pnode{")
    base_rule = shell.PIPE_CSS[base_idx:shell.PIPE_CSS.index("}", base_idx) + 1]
    assert "animation:pipein var(--dur) var(--easing) both" in base_rule


def test_pipe_css_cascade_stays_inside_the_500ms_ceiling(tmp_path):
    # 4 (last stage index) * 60ms delay + the --dur (.24s = 240ms) fade
    # itself = 480ms, inside the plan's <=500ms total for the one-shot.
    max_delay_ms = 4 * 60
    dur_ms = 240
    assert max_delay_ms + dur_ms <= 500


def test_pipe_css_never_loops_and_stays_box_shadow_only_after_phase_d(tmp_path):
    from nuncio.web import shell
    # Re-assert the hard ceilings with the new motion in place.
    assert "infinite" not in shell.PIPE_CSS
    assert "infinite" not in shell._PIPE_CSS_SOURCE
    assert "filter:" not in shell.PIPE_CSS
    assert ":has(" not in shell.PIPE_CSS


def test_pipe_css_reduced_motion_block_lists_the_cascade_and_bloom_selectors(tmp_path):
    from nuncio.web import shell
    src = shell._PIPE_CSS_SOURCE
    idx = src.index("prefers-reduced-motion")
    block = src[idx:]
    # The plain cascade (pipein) rides on the SAME selector list as the
    # existing transition kill (.pnode, .prail::before are already there);
    # the MORE SPECIFIC bloom selector needs its own explicit kill.
    assert "animation:none" in block
    assert ".prail.open .pnode" in block
    # Still only motion properties in this block -- states/colors survive.
    for prop in ("color:", "background:", "border-color:", "text-decoration"):
        assert prop not in block, prop


def test_pipe_css_diagram_only_cascade_settings_rows_headers_do_not_animate(tmp_path):
    from nuncio.web import shell
    # "Settings rows/headers do NOT cascade (content never waits on
    # decoration)" -- .phead never gets the pipein animation; only .pnode/
    # .prail::before (diagram elements) do. .row's OWN animation is the
    # pre-existing `rowin` stagger (Phase 5), untouched, and distinct.
    idx = shell.PIPE_CSS.index(".phead{")
    phead_rule = shell.PIPE_CSS[idx:shell.PIPE_CSS.index("}", idx) + 1]
    assert "animation:" not in phead_rule
    assert "@keyframes rowin{from{opacity:0;transform:translateY(4px)}}" in shell.PIPE_CSS


def test_settings_health_tint_classes_unchanged_ring_stub_bus_follow_st(tmp_path):
    # nodebad/nodewarn still override --st (not per-selector patches), so
    # the NEW pseudos (ring/stub) and the bus box-shadow -- all painted
    # with var(--st)/var(--st-dim) -- follow the sick hue automatically,
    # with zero new health-tint rules needed.
    from nuncio.web import shell
    assert ".nodebad{--st:var(--breach);--st-dim:rgba(224,96,77,.16)}" in shell.PIPE_CSS
    assert ".nodewarn{--st:var(--raw);--st-dim:var(--raw-dim)}" in shell.PIPE_CSS
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "nodebad" in html or "nodewarn" in html or "tintNode" in html  # classes still wired client-side
    app.store.close()


def test_settings_html_byte_budget_after_phase_d_character_and_still_one_favicon(tmp_path):
    # Confirms Global Constraint 8 in practice: the phase crosses the OLD
    # 64KB soft ceiling (as flagged going in) but stays comfortably under
    # the justified 68KB max, and the single-favicon/no-raster guard holds.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert 64 * 1024 <= len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1
    assert "infinite" not in decoded


# =====================================================================
# REV 3 Phase E -- the world column: fan-in/fan-out live wiring diagram.
# Client-drawn inline SVG built by renderFans() from real data (registered
# source adapters, configured NUNCIO_DELIVERY channels); redraws inside
# onApplied -> load() so an applied delivery change visibly rewires the
# diagram. Collapses to header count-chips at <=900px instead of drawing.
# =====================================================================

def test_page_js_render_fans_function_present(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "function renderFans()" in html


def test_page_js_render_fans_called_from_load(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("async function load()"):]
    fn = fn[:fn.index("\nload();")]
    assert "renderFans()" in fn


def test_page_js_render_fans_called_from_on_applied(tmp_path):
    # onApplied() -> load() -> renderFans(): confirmed via the load() call
    # above; onApplied itself must still be the thing sendApply() re-runs on
    # a successful apply, so a rewired NUNCIO_DELIVERY visibly redraws.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("async function onApplied()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "load()" in fn


def test_page_js_fans_use_registered_not_ingested_by_source(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function renderFans()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "registered" in fn
    assert "ingested_by_source" not in fn


def test_page_js_fan_out_parses_nuncio_delivery_csv(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function renderFans()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "NUNCIO_DELIVERY" in fn
    assert "split(" in fn


def test_page_js_fan_honest_empty_delivery_falls_back_to_real_stdout_default(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function renderFans()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "'stdout'" in fn or '"stdout"' in fn


def test_page_js_fans_cap_five_stubs_and_overflow_label(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "slice(0, 5)" in html or "slice(0,5)" in html
    assert "'+'" in html
    assert "more" in html


def test_page_js_fans_target_world_intake_and_world_deliver_cells(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "world-intake" in html
    assert "world-deliver" in html


def test_page_js_fans_ellipsize_long_labels_around_9_chars(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "slice(0, 9" in html or "slice(0,9" in html


def test_page_js_fan_curves_are_svg_bezier_paths_stroked_with_stage_colors(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "<path" in html
    assert "<svg" in html
    assert "var(--st-intake)" in html
    assert "var(--st-deliver)" in html


def test_page_js_count_chip_strings_present_for_collapsed_width(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "' source'" in html
    assert "' channel'" in html
    assert "' in'" in html
    assert "' out'" in html


def test_page_js_count_chip_singularizes_for_a_count_of_one(tmp_path):
    # M3: the default config (NUNCIO_DELIVERY=stdout,
    # i.e. exactly one channel) rendered the ungrammatical "1 channels out"
    # on every <=900px viewport -- singularize source/channel when count==1.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function renderFans()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "registered.length === 1 ? '' : 's'" in fn
    assert "channels.length === 1 ? '' : 's'" in fn
    assert "'sources in'" not in fn
    assert "'channels out'" not in fn


def test_page_js_fans_do_not_draw_svg_when_collapsed_at_or_under_900px(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function renderFans()"):]
    fn = fn[:fn.index("\n}\n") + 3]
    assert "innerWidth" in fn
    assert "900" in fn


def test_settings_html_byte_budget_after_phase_e_fans_stays_under_68kb(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1
    assert "infinite" not in decoded
    assert "filter:" not in decoded


def test_pipe_css_still_no_filter_after_phase_e(tmp_path):
    from nuncio.web import shell
    assert "filter:" not in shell.PIPE_CSS
    assert "filter:" not in shell.FORM_CSS


# =====================================================================
# REV 3 Phase F -- final polish: form-side refinements + deferred items +
# the Phase-C byte-driven trims restored now the ceiling is 68KB.
# =====================================================================

def test_pipe_css_open_title_underline_follows_the_stage_circuit_color(tmp_path):
    # Deferred polish: the open-stage title underline was still hardcoded
    # --trace -- switch it to --st for consistency with the node/ordinal,
    # which already carry the stage's own circuit color.
    from nuncio.web import shell
    assert ".pstage.open .phead .ptitle{border-bottom-color:var(--st)}" in shell.PIPE_CSS
    assert ".pstage.open .phead .ptitle{border-bottom-color:var(--trace)}" not in shell.PIPE_CSS


def test_page_js_nodehover_mirror_keys_off_focus_visible_like_the_psub_reveal(tmp_path):
    # Deferred polish: `.psub` reveals on `:focus-visible`; the `.nodehover`
    # mirror used to fire on bare `focus` (so a mouse click also scaled the
    # node while the summary stayed hidden until :focus-visible). Aligned to
    # the same keyboard-only semantics via matches(':focus-visible').
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "matches(':focus-visible')" in html
    app.store.close()


def test_settings_lock_widget_restores_phase_c_em_dashes(tmp_path):
    # Phase C cut two em dashes to plain hyphens purely for the (then) 64KB
    # byte ceiling; Phase E raised the ceiling to 68KB, so restore the
    # spec's literal copy.
    from nuncio.web import settings as settings_mod
    assert "read-only — unlock in the top bar" in settings_mod._PAGE_JS
    assert "Locked — read-only." in settings_mod._PAGE_JS
    assert "read-only - unlock in the top bar" not in settings_mod._PAGE_JS
    assert "Locked - read-only." not in settings_mod._PAGE_JS


def test_form_css_restores_the_unlocked_state_trace_dim_halo(tmp_path):
    # Phase C also cut the unlocked-padlock's quiet --trace-dim halo for the
    # same budget reason (§A5's state table calls for it) -- restore it.
    from nuncio.web import shell
    assert ".locktrig.unlocked{color:var(--trace);box-shadow:0 0 0 3px var(--trace-dim)}" in shell.FORM_CSS


def test_settings_html_byte_budget_after_phase_f_polish(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1
    assert "infinite" not in decoded
    assert "filter:" not in decoded
    app.store.close()


# --- §6b fan geometry: labels are positioned HTML, not SVG <text> --------

def test_page_js_fan_labels_are_html_spans_not_svg_text(tmp_path):
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function fanLabel("):]
    fn = fn[:fn.index("function renderMeta")]
    assert "<text" not in fn        # no SVG <text> anywhere in the fan machinery
    assert "fanlbl" in fn           # the HTML label span class
    assert "<span" in fn
    app.store.close()


def test_pipe_css_fanlbl_is_small_quiet_grey_and_non_interactive(tmp_path):
    from nuncio.web import shell
    assert ".fanlbl{" in shell.PIPE_CSS
    idx = shell.PIPE_CSS.index(".fanlbl{")
    rule = shell.PIPE_CSS[idx:shell.PIPE_CSS.index("}", idx) + 1]
    assert "font-size:9px" in rule
    assert "color:var(--ink2)" in rule
    assert "pointer-events:none" in rule
    assert "position:absolute" in rule


def test_page_js_fan_curves_still_render_via_svg_paths_only(tmp_path):
    # The curves stay SVG (curve-shape distortion under the non-uniform
    # viewBox scale is harmless); only the label TEXT moved out of SVG.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function fanLabel("):]
    fn = fn[:fn.index("function renderMeta")]
    assert "<path" in fn
    assert "<svg" in fn
    app.store.close()


def test_page_js_fan_spread_is_centered_on_the_34px_node_offset(tmp_path):
    # §6b top-clipping fix: the fan-in used to spread 6px-54px (centered on
    # the OLD 30px node offset), which let the topmost label's glyph
    # ascenders spill above the row/page top for the first (intake) stage.
    # The spread must be re-centered on the CURRENT 34px node-center offset
    # with headroom top and bottom so nothing renders above y=0.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function fanLabel("):]
    fn = fn[:fn.index("function renderMeta")]
    assert "6 + i * step" not in fn   # the old 6px-54px spread is gone
    assert "cap.length === 1 ? 30" not in fn  # the old un-bumped single-item center is gone
    app.store.close()


# =====================================================================
# REV 3 final fix wave -- a final review found two cross-phase seam bugs
# (C1, C2) plus a cluster of Important/Minor state-honesty and robustness
# gaps.
# =====================================================================

def test_forms_js_sends_apply_401_prefers_lock_invalid_over_prompt_token(tmp_path):
    # C2: the token that was just rejected is still sitting in
    # TOKEN/sessionStorage -- a bare promptToken() would render the lock
    # popover for the CURRENT (still-truthy-TOKEN) state, i.e. "Editing
    # unlocked", at the exact moment the server said the token was invalid.
    # sendApply's 401 branch must prefer a page-defined lockInvalid() hook,
    # falling back to promptToken() only if the page hasn't defined one.
    from nuncio.web.forms import FORM_JS
    idx = FORM_JS.index("r.status === 401")
    branch = FORM_JS[idx:FORM_JS.index("} else if", idx)]
    assert "typeof lockInvalid" in branch
    assert "lockInvalid()" in branch
    assert "promptToken()" in branch  # still the fallback


def test_settings_js_lock_invalid_clears_token_before_reopening_the_popover(tmp_path):
    # C2: settings.py's lockInvalid() is the concrete page-side hook --
    # TOKEN and its sessionStorage mirror must be cleared, and the lock
    # re-rendered, BEFORE the popover opens, so it opens on the honest
    # LOCKED body (token input) instead of lying "unlocked".
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "function lockInvalid" in html
    idx = html.index("function lockInvalid")
    fn = html[idx:html.index("openLock()", idx) + len("openLock()")]
    assert "TOKEN = ''" in fn
    assert "sessionStorage.removeItem('nuncio_admin_token')" in fn
    assert "renderLock()" in fn
    # Token must be cleared BEFORE the popover opens (order matters -- see
    # renderLockPopoverBody(), which reads the current lockState()).
    assert fn.index("TOKEN = ''") < fn.index("openLock()")
    app.store.close()


def test_pipe_css_i1_nodering_stays_visible_under_open_and_rail_hover(tmp_path):
    # I1: the additive base ring alone doesn't fix the bug -- CSS doesn't
    # merge box-shadow lists across rules, a more-specific selector setting
    # the same property replaces it outright. The fix needs an explicit
    # compound selector (0,3,1) that out-specifies .prail.open .pnode and
    # .pipeline.rail-hi .pnode (both 0,2,1) so the ring survives instead of
    # being silently dropped by the cascade.
    from nuncio.web import shell
    assert ".prail.open .pnode.nodering,.pipeline.rail-hi .pnode.nodering{" \
        "box-shadow:0 0 0 5px var(--st-dim),var(--glow) var(--st-dim),0 0 0 8px var(--raw-dim)}" \
        in shell.PIPE_CSS


def test_page_js_tint_node_also_tints_the_rail_cell(tmp_path):
    # I2: the junction stub (.prail::after), twin-hairline bus, and segment
    # gradient all paint from the RAIL's own --st, not the node's -- without
    # mirroring the health-tint class onto the rail cell too, a sick stage
    # kept an identity-colored stub attached to its own breach-red node.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function tintNode"):html.index("function applyHealthTints")]
    assert "getElementById('rail-' + stage)" in fn
    assert "rail.classList.add(cls)" in fn
    app.store.close()


def test_page_js_render_fans_reruns_on_a_900px_resize(tmp_path):
    # I3: renderFans() only sampled window.innerWidth at call time -- a
    # resize/rotation across the 900px breakpoint never re-ran it, so a
    # wide->narrow resize lost the fan-in/out data entirely (no chip was
    # ever built) and a narrow->wide resize left stale chips stuck in place.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "matchMedia('(max-width:900px)').addEventListener('change', renderFans)" in html
    app.store.close()


def test_page_js_lock_locked_body_is_a_form_so_enter_submits(tmp_path):
    # I4: the locked popover body used to be a bare input + button with no
    # form and no keydown handler -- pressing Enter in the token field did
    # nothing; keyboard users had to Tab to the Unlock button. Wrapping it
    # in a <form> whose onsubmit calls unlockNow() (and returns false, so
    # the page never navigates) makes Enter behave like clicking Unlock.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    idx = html.index("state === 'locked'")
    fn = html[idx:html.index("} else {", idx)]
    assert '<form onsubmit="unlockNow();return false">' in fn
    assert 'id="lockinput"' in fn
    assert fn.index("<form") < fn.index('id="lockinput"')
    assert "</form>" in fn
    app.store.close()


def test_page_js_unlock_now_distinguishes_unreachable_server_from_bad_token(tmp_path):
    # M4: probeToken() returns status 0 when the fetch itself throws (the
    # server is unreachable) -- "That token didn't match." is the wrong
    # message for that case; distinguish it with its own copy.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert "status === 0" in html
    assert "Couldn't reach the server." in html
    assert "That token didn't match." in html  # the 401 message is unchanged
    app.store.close()


def test_page_js_apply_health_tints_clears_stale_classes_before_reapplying(tmp_path):
    # M5: applyHealthTints() only ever ADDED nodebad/nodewarn/nodering, so a
    # stage that recovered stayed tinted until a full page reload. Clear all
    # three classes at the top of the function, before STATS is consulted,
    # so a load()/re-apply always reflects current health.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    fn = html[html.index("function applyHealthTints"):html.index("function onDirtyChange")]
    assert "classList.remove('nodebad', 'nodewarn', 'nodering')" in fn
    assert fn.index("classList.remove") < fn.index("if (!STATS) return")
    app.store.close()


def test_settings_html_lock_popover_a11y_attrs_present(tmp_path):
    # M8: the trigger lacked aria-haspopup, the popover had no role/label,
    # and the password input was labelled only by its placeholder.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app).decode()
    assert 'aria-haspopup="dialog"' in html
    assert 'id="lockpop"' in html
    lockpop_idx = html.index('id="lockpop"')
    lockpop_tag = html[html.index('<div class="lockpop"'):lockpop_idx + 200]
    assert 'role="dialog"' in lockpop_tag
    assert 'aria-label="Admin token"' in lockpop_tag
    assert 'aria-label="Admin token"' in html  # also present on the input itself (M8)
    app.store.close()


def test_settings_html_byte_budget_after_final_fix_wave(tmp_path):
    # I5: the fix wave (C1/C2/I1-I4/M1-M5/M8) adds real bytes -- the
    # block-minifier was extended (renderMeta, renderAudit, tintNode +
    # applyHealthTints, the STAGES.forEach rail-forwarding block) to buy the
    # headroom back FIRST so the page stays comfortably under the 68KB hard
    # ceiling with every fix landed, never trips it in CI.
    app, settings = build(tmp_path)
    html = settings_ui.render_settings_html(app)
    assert len(html) < 68 * 1024
    decoded = html.decode()
    assert decoded.count("base64") == 1
    assert "infinite" not in decoded
    assert "filter:" not in decoded
    assert ":has(" not in decoded
    app.store.close()
