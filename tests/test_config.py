"""Configuration + composition root."""
import json
import os

import pytest

from nuncio import config
from nuncio.engine import Engine
from nuncio.envelope import Envelope
from nuncio.server import App


def _envelope(text="a message"):
    return Envelope(severity="unknown", host="", service="", headline="? — alert",
                     summary=text, detail=text, detail_html=None, notify_type="3", marker=False)


def base_env(**overrides):
    env = {"NUNCIO_LLM_URL": "http://ollama:11434"}
    env.update(overrides)
    return env


# --- required/optional settings, defaults ---

def test_llm_url_is_the_only_required_setting():
    with pytest.raises(config.ConfigError):
        config.load_settings({})


def test_defaults_have_no_personal_infra_residue():
    s = config.load_settings(base_env())
    text = json.dumps(s.as_dict())
    for banned in ("kirits.net", "svr", "photon", "/mnt/photon", "ollama-enrich",
                   "homelab", "checkmk-only"):
        assert banned not in text, banned


def test_default_model_is_generic_not_ollama_enrich():
    s = config.load_settings(base_env())
    assert s.NUNCIO_LLM_MODEL == "default"


def test_default_delivery_is_stdout():
    s = config.load_settings(base_env())
    assert s.delivery_names == ["stdout"]


def test_default_source_is_generic():
    s = config.load_settings(base_env())
    assert s.NUNCIO_DEFAULT_SOURCE == "generic"


def test_llm_key_optional_empty_string_default():
    s = config.load_settings(base_env())
    assert s.NUNCIO_LLM_KEY == ""


def test_unknown_env_var_does_not_raise(caplog):
    # typo detection is a warning, not a fatal error
    config.load_settings(base_env(NUNCIO_LML_URL="oops"))


def test_knowledge_enabled_is_the_default():
    # Phase C: the knowledge plane is ON by default -- it shares the
    # enrichment plane's endpoint/model/key via inheritance, so a default
    # install has a working knowledge plane with zero extra config.
    s = config.load_settings(base_env())
    assert s.NUNCIO_KNOWLEDGE_ENABLED is True


def test_knowledge_enabled_without_url_inherits_llm_url():
    # The old "NUNCIO_KNOWLEDGE_ENABLED=true requires NUNCIO_KNOWLEDGE_URL"
    # ConfigError is gone -- an empty NUNCIO_KNOWLEDGE_URL now always
    # resolves to a usable value (the already-required NUNCIO_LLM_URL), so
    # enabling with no knowledge URL configured can never be fatal.
    s = config.load_settings(base_env(NUNCIO_KNOWLEDGE_ENABLED="true"))
    assert s.NUNCIO_KNOWLEDGE_ENABLED is True
    assert s.knowledge_url == s.NUNCIO_LLM_URL


def test_knowledge_enabled_with_explicit_url_is_accepted():
    s = config.load_settings(base_env(NUNCIO_KNOWLEDGE_ENABLED="true",
                                       NUNCIO_KNOWLEDGE_URL="http://gw:4000"))
    assert s.NUNCIO_KNOWLEDGE_ENABLED is True
    assert s.knowledge_url == "http://gw:4000"


def test_knowledge_model_and_key_inherit_when_empty():
    s = config.load_settings(base_env(NUNCIO_LLM_KEY="secret-key", NUNCIO_LLM_MODEL="private-alias"))
    assert s.knowledge_model == "private-alias"
    assert s.knowledge_key == "secret-key"


def test_knowledge_model_and_key_override_when_explicitly_set():
    s = config.load_settings(base_env(
        NUNCIO_LLM_KEY="secret-key", NUNCIO_LLM_MODEL="private-alias",
        NUNCIO_KNOWLEDGE_MODEL="k-alias", NUNCIO_KNOWLEDGE_KEY="k-key",
    ))
    assert s.knowledge_model == "k-alias"
    assert s.knowledge_key == "k-key"


# --- MUST-FIX 2: the private-plane key/model must never be inherited to a
# DISTINCT knowledge endpoint -- only a SHARED (inherited-URL) endpoint may
# ever see the private-plane credential. ---

def test_knowledge_key_not_inherited_when_url_is_distinct_and_key_empty():
    # An operator who points NUNCIO_KNOWLEDGE_URL at a genuinely different
    # host but leaves NUNCIO_KNOWLEDGE_KEY empty must NOT have the private
    # plane's key silently sent to that foreign host as a Bearer token.
    s = config.load_settings(base_env(
        NUNCIO_LLM_KEY="secret-key", NUNCIO_LLM_MODEL="private-alias",
        NUNCIO_KNOWLEDGE_URL="http://distinct-gw:5000",
    ))
    assert s.knowledge_url == "http://distinct-gw:5000"
    assert s.knowledge_key == ""
    assert s.knowledge_key != "secret-key"


def test_knowledge_model_not_inherited_when_url_is_distinct_and_model_empty():
    s = config.load_settings(base_env(
        NUNCIO_LLM_MODEL="private-alias", NUNCIO_KNOWLEDGE_URL="http://distinct-gw:5000",
    ))
    assert s.knowledge_model == ""


def test_knowledge_key_uses_explicit_key_when_url_is_distinct():
    s = config.load_settings(base_env(
        NUNCIO_LLM_KEY="secret-key", NUNCIO_KNOWLEDGE_URL="http://distinct-gw:5000",
        NUNCIO_KNOWLEDGE_KEY="k-key",
    ))
    assert s.knowledge_key == "k-key"


def test_knowledge_key_still_inherits_when_url_is_shared():
    # Unchanged behavior: an empty NUNCIO_KNOWLEDGE_URL means the knowledge
    # plane shares the private plane's endpoint, so inheriting the key/model
    # too is safe (same endpoint the key was already authorized against).
    s = config.load_settings(base_env(NUNCIO_LLM_KEY="secret-key", NUNCIO_LLM_MODEL="private-alias"))
    assert s.knowledge_url == s.NUNCIO_LLM_URL
    assert s.knowledge_key == "secret-key"
    assert s.knowledge_model == "private-alias"


def test_knowledge_distinct_url_empty_key_logs_a_warning(caplog):
    with caplog.at_level("WARNING"):
        config.load_settings(base_env(
            NUNCIO_KNOWLEDGE_ENABLED="true", NUNCIO_KNOWLEDGE_URL="http://distinct-gw:5000",
        ))
    assert any("NUNCIO_KNOWLEDGE_KEY" in r.message for r in caplog.records)


def test_knowledge_distinct_url_explicit_key_no_warning(caplog):
    with caplog.at_level("WARNING"):
        config.load_settings(base_env(
            NUNCIO_KNOWLEDGE_ENABLED="true", NUNCIO_KNOWLEDGE_URL="http://distinct-gw:5000",
            NUNCIO_KNOWLEDGE_KEY="k-key",
        ))
    assert not any("NUNCIO_KNOWLEDGE_KEY" in r.message for r in caplog.records)


def test_knowledge_shared_url_no_warning_even_with_empty_key(caplog):
    with caplog.at_level("WARNING"):
        config.load_settings(base_env(NUNCIO_KNOWLEDGE_ENABLED="true"))
    assert not any("NUNCIO_KNOWLEDGE_KEY" in r.message for r in caplog.records)


def test_invalid_llm_headers_json_is_fatal():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_LLM_HEADERS="not json"))


def test_bad_integer_setting_is_fatal():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_PORT="not-a-number"))


# --- NUNCIO_MODE ---

def test_nuncio_mode_defaults_to_enriched():
    s = config.load_settings(base_env())
    assert s.NUNCIO_MODE == "enriched"


def test_nuncio_mode_accepts_bypass():
    s = config.load_settings(base_env(NUNCIO_MODE="bypass"))
    assert s.NUNCIO_MODE == "bypass"


def test_nuncio_mode_rejects_unknown_value():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_MODE="bogus"))


def test_nuncio_mode_rejects_retired_raw_first():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_MODE="raw_first"))


def test_nuncio_mode_rejects_retired_enriched_only():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_MODE="enriched_only"))


def test_build_app_wires_mode_into_engine(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_MODE="bypass")
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.mode == "bypass"
    app.store.close()


def test_build_app_default_mode_is_enriched_zero_behavior_change(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.mode == "enriched"
    app.store.close()


# --- NUNCIO_ENRICH_FORMAT (Phase A) ---

def test_nuncio_enrich_format_defaults_to_auto():
    s = config.load_settings(base_env())
    assert s.NUNCIO_ENRICH_FORMAT == "auto"


def test_nuncio_enrich_format_accepts_text():
    s = config.load_settings(base_env(NUNCIO_ENRICH_FORMAT="text"))
    assert s.NUNCIO_ENRICH_FORMAT == "text"


def test_nuncio_enrich_format_is_ui_editable_pipeline_group():
    spec = config.UI_EDITABLE["NUNCIO_ENRICH_FORMAT"]
    assert spec.category == "live"
    assert spec.type == "enum"
    assert set(spec.allowed) == {"auto", "text"}
    assert spec.group == "pipeline"


def test_nuncio_enrich_format_is_in_llm_router_keys():
    # A text->auto (or auto->text) flip must rebuild the LLM client so a
    # stale capability cache (llm._json_object_supported) can never survive
    # a mode change.
    assert "NUNCIO_ENRICH_FORMAT" in config._LLM_ROUTER_KEYS


def test_build_app_wires_enrich_format_into_engine(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_ENRICH_FORMAT="text")
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.enrich_format == "text"
    app.store.close()


def test_build_app_default_enrich_format_is_auto(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.enrich_format == "auto"
    app.store.close()


# --- Phase B: NUNCIO_ENRICH_DEPTH + NUNCIO_FULL_BUDGET_S ---

def test_nuncio_enrich_depth_defaults_to_full():
    s = config.load_settings(base_env())
    assert s.NUNCIO_ENRICH_DEPTH == "full"


def test_nuncio_enrich_depth_accepts_low():
    s = config.load_settings(base_env(NUNCIO_ENRICH_DEPTH="low"))
    assert s.NUNCIO_ENRICH_DEPTH == "low"


def test_nuncio_enrich_depth_rejects_unknown_value():
    with pytest.raises(config.ConfigError):
        config.load_settings(base_env(NUNCIO_ENRICH_DEPTH="bogus"))


def test_nuncio_full_budget_s_defaults_to_60():
    s = config.load_settings(base_env())
    assert s.NUNCIO_FULL_BUDGET_S == 60.0
    assert s.effective_full_budget_s == 60.0


def test_nuncio_enrich_depth_is_ui_editable_pipeline_group():
    spec = config.UI_EDITABLE["NUNCIO_ENRICH_DEPTH"]
    assert spec.category == "live"
    assert spec.type == "enum"
    assert set(spec.allowed) == {"full", "low"}
    assert spec.group == "pipeline"


def test_nuncio_full_budget_s_is_ui_editable_pipeline_group():
    spec = config.UI_EDITABLE["NUNCIO_FULL_BUDGET_S"]
    assert spec.category == "live"
    assert spec.type == "float"
    assert spec.min == 30 and spec.max == 600
    assert spec.group == "pipeline"


# --- BLOCKER 4: NUNCIO_FULL_BUDGET_S < NUNCIO_BUDGET_S is NEVER a ConfigError ---

def test_full_budget_below_standard_budget_never_raises(caplog):
    # An install with NUNCIO_BUDGET_S raised above the 60s NUNCIO_FULL_BUDGET_S
    # default (e.g. NUNCIO_BUDGET_S=90) must boot cleanly, not brick on
    # upgrade -- see the Phase B spec's BLOCKER 4.
    s = config.load_settings(base_env(NUNCIO_BUDGET_S="90"))  # NUNCIO_FULL_BUDGET_S stays default 60
    assert s.effective_full_budget_s == 90.0  # the LARGER of the two, via max()
    assert any("NUNCIO_FULL_BUDGET_S" in r.message for r in caplog.records)  # warned, not raised


def test_effective_full_budget_is_max_of_the_two_when_full_budget_larger():
    s = config.load_settings(base_env(NUNCIO_BUDGET_S="20", NUNCIO_FULL_BUDGET_S="60"))
    assert s.effective_full_budget_s == 60.0


def test_effective_full_budget_no_warning_when_full_budget_already_larger(caplog):
    s = config.load_settings(base_env(NUNCIO_BUDGET_S="20", NUNCIO_FULL_BUDGET_S="60"))
    assert s.effective_full_budget_s == 60.0
    assert not any("NUNCIO_FULL_BUDGET_S" in r.message for r in caplog.records)


# --- FIX 4: a startup warning when NUNCIO_ENRICH_DEPTH=full can never
# actually run the 2-call pipeline because the effective full-depth budget is
# below the ladder's own post-gather reserve. ---

def test_low_full_budget_at_depth_full_warns_pipeline_wont_run(caplog):
    # NUNCIO_FULL_BUDGET_S=40 (NUNCIO_BUDGET_S stays default 30) ->
    # effective_full_budget_s = max(40, 30) = 40, which is below
    # _FULL_POST_GATHER_RESERVE_S(48) + 1 = 49 -- the 2-call pipeline's gather
    # gate (see Engine._enrich_full) can never pass at this budget, so every
    # full-depth alert silently degrades to a single standard call.
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_FULL_BUDGET_S="40"))  # NUNCIO_ENRICH_DEPTH defaults to "full"
    assert s.effective_full_budget_s == 40.0
    assert any("NUNCIO_ENRICH_DEPTH" in r.message and "single standard call" in r.message
               for r in caplog.records)


def test_adequate_full_budget_at_depth_full_no_warning(caplog):
    with caplog.at_level("WARNING"):
        config.load_settings(base_env(NUNCIO_FULL_BUDGET_S="60"))  # default, comfortably above the floor
    assert not any("single standard call" in r.message for r in caplog.records)


def test_low_full_budget_at_depth_low_no_warning(caplog):
    # The warning is specific to depth=full -- depth=low never runs the
    # 2-call pipeline at all, so a low NUNCIO_FULL_BUDGET_S is irrelevant.
    with caplog.at_level("WARNING"):
        config.load_settings(base_env(NUNCIO_FULL_BUDGET_S="40", NUNCIO_ENRICH_DEPTH="low"))
    assert not any("single standard call" in r.message for r in caplog.records)


def test_build_app_wires_depth_and_full_budget_into_engine_and_app(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_ENRICH_DEPTH="low",
                      NUNCIO_BUDGET_S="90", NUNCIO_FULL_BUDGET_S="60")  # full < standard -> max() = 90
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.depth == "low"
    assert app.engine.full_budget_s == 90.0
    assert app.full_budget_s == 90.0
    app.store.close()


def test_build_app_default_depth_is_full(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.engine.depth == "full"
    app.store.close()


# --- build_gatherer: Phase B deep collector profile wiring ---

def test_build_gatherer_wires_full_collectors_with_history_and_deep_correlated(tmp_path):
    from nuncio.store import Store
    store = Store(":memory:")
    try:
        s = config.load_settings(base_env())
        g = config.build_gatherer(s, store)
        assert "history" in g.collectors
        assert "history" in g.full_collectors
        assert "recurrence" in g.full_collectors  # store-only, present in both profiles
        # deep 'recent_logs' is a DIFFERENT closure than the standard one
        assert g.full_collectors["recent_logs"] is not g.collectors["recent_logs"]
    finally:
        store.close()


def test_build_gatherer_recurrence_collector_actually_callable(tmp_path):
    # Regression: collect_recurrence was referenced but never imported in
    # nuncio/config.py -- build_gatherer()'s "recurrence" closure raised
    # NameError the first time it was actually CALLED (never caught by any
    # existing test, since none exercised the closure body itself).
    from nuncio.store import Store
    store = Store(":memory:")
    try:
        s = config.load_settings(base_env())
        g = config.build_gatherer(s, store)
        result = g.collectors["recurrence"]({"host": "h", "output": "down"}, "k1", 1000.0)
        assert "Recurrence" in result
    finally:
        store.close()


def test_build_gatherer_history_collector_actually_callable(tmp_path):
    from nuncio.store import Store
    store = Store(":memory:")
    try:
        s = config.load_settings(base_env())
        g = config.build_gatherer(s, store)
        result = g.collectors["history"]({"host": "h", "output": "down"}, "k1", 1000.0)
        assert "Alert history" in result
    finally:
        store.close()


# --- apply_changes: live NUNCIO_ENRICH_DEPTH / NUNCIO_FULL_BUDGET_S / NUNCIO_BUDGET_S swaps ---

def test_apply_changes_enrich_depth_swap(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    try:
        assert app.engine.depth == "full"
        result = config.apply_changes(app, {"NUNCIO_ENRICH_DEPTH": "low"})
        assert app.engine.depth == "low"
        assert "NUNCIO_ENRICH_DEPTH" in result["applied"]
    finally:
        app.store.close()


def test_apply_changes_full_budget_swap(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    try:
        config.apply_changes(app, {"NUNCIO_FULL_BUDGET_S": "120"})
        assert app.engine.full_budget_s == 120.0
        assert app.full_budget_s == 120.0
    finally:
        app.store.close()


def test_apply_changes_budget_s_raise_also_lifts_effective_full_budget(tmp_path):
    # NUNCIO_BUDGET_S raised above the CURRENT NUNCIO_FULL_BUDGET_S (default
    # 60) must push the effective full budget up too, live -- not just at
    # the next restart.
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    try:
        assert app.engine.full_budget_s == 60.0
        config.apply_changes(app, {"NUNCIO_BUDGET_S": "90"})
        assert app.engine.budget_s == 90.0
        assert app.engine.full_budget_s == 90.0  # max(90, 60) via effective_full_budget_s
        assert app.full_budget_s == 90.0
    finally:
        app.store.close()


def test_apply_changes_budget_s_lower_than_full_budget_leaves_full_budget_unchanged(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_FULL_BUDGET_S="120")
    app, settings = config.build_app(config.load_settings(s_env))
    try:
        assert app.engine.full_budget_s == 120.0
        config.apply_changes(app, {"NUNCIO_BUDGET_S": "40"})
        assert app.engine.full_budget_s == 120.0  # max(40, 120) unchanged
    finally:
        app.store.close()


# --- delivery wiring ---

def test_build_delivery_defaults_to_stdout_bridge():
    s = config.load_settings(base_env())
    d = config.build_delivery(s)
    assert d.send(_envelope()) is True  # stdout always "succeeds"


def test_build_delivery_unknown_adapter_name_is_fatal():
    s = config.load_settings(base_env(NUNCIO_DELIVERY="not-a-real-channel"))
    with pytest.raises(config.ConfigError):
        config.build_delivery(s)


def test_build_delivery_multi_channel_builds_fanout():
    s = config.load_settings(base_env(NUNCIO_DELIVERY="stdout,stdout"))
    d = config.build_delivery(s)
    assert d.send(_envelope()) is True


def test_build_delivery_dispatch_matches_engine_calling_convention():
    # engine.py calls delivery.send(envelope) -- the sole call shape Dispatch
    # must satisfy.
    s = config.load_settings(base_env())
    d = config.build_delivery(s)
    assert d.send(_envelope("just a message")) is True


# --- LOW: Dispatch's contract is "return bool, never raise" ---

def test_dispatch_returns_false_not_raise_on_adapter_exception():
    class RaisingAdapter:
        def send(self, title, body, severity="unknown", **kw):
            raise RuntimeError("channel exploded")

    from nuncio.delivery import Dispatch, FULL
    d = Dispatch([("raising", RaisingAdapter(), FULL)])
    assert d.send(_envelope()) is False


# --- client / gatherer wiring (null-only in this build) ---

def test_build_gatherer_wires_correlated_even_with_all_null_clients():
    from nuncio.store import Store
    s = config.load_settings(base_env())
    store = Store(":memory:")
    g = config.build_gatherer(s, store)
    assert "correlated" in g.collectors
    assert "recent_logs" in g.collectors
    store.close()


def test_unimplemented_client_impl_falls_back_to_null(caplog):
    # An NUNCIO_LOGS value that isn't "null"/"openobserve"/"loki" (a typo, or
    # simply not implemented in this build) must degrade to the null client,
    # not raise -- env vars aren't validated against UI_EDITABLE's enum at
    # load time (that only gates the settings-screen API), so this can
    # legitimately happen at startup.
    s = config.load_settings(base_env(NUNCIO_LOGS="not-a-real-backend"))
    client = config.build_log_client(s)
    assert client.query("h", "u", 900) == []


# --- masked config transparency (dogfoods the redactor) ---

def test_masked_config_hides_llm_key():
    s = config.load_settings(base_env(NUNCIO_LLM_KEY="sk-" "supersecretvalue1234567890"))
    masked = config.masked_config_dict(s)
    assert "sk-" "supersecretvalue1234567890" not in json.dumps(masked)


def test_masked_config_hides_ingest_token():
    s = config.load_settings(base_env(NUNCIO_INGEST_TOKEN="topsecrettoken"))
    masked = config.masked_config_dict(s)
    assert "topsecrettoken" not in json.dumps(masked)


def test_masked_config_keeps_non_secret_values_visible():
    s = config.load_settings(base_env())
    masked = config.masked_config_dict(s)
    assert masked["NUNCIO_LLM_URL"] == "http://ollama:11434"
    assert masked["NUNCIO_DEFAULT_SOURCE"] == "generic"


# --- default source validation ---

def test_validate_default_source_accepts_generic():
    s = config.load_settings(base_env())
    config.validate_default_source(s)  # must not raise


def test_validate_default_source_rejects_unregistered():
    s = config.load_settings(base_env(NUNCIO_DEFAULT_SOURCE="not-a-real-source"))
    with pytest.raises(config.ConfigError):
        config.validate_default_source(s)


# --- config.example.json: keep the shipped example from rotting ---

def test_config_example_json_loads_and_builds_a_working_router():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    example_path = os.path.join(repo_root, "config.example.json")
    assert os.path.exists(example_path)
    s = config.load_settings(base_env(NUNCIO_CONFIG=example_path))
    assert isinstance(s.yaml, dict)
    table = s.yaml["classification_table"]
    for category in ("storage", "container", "network", "hardware"):
        assert category in table
        assert isinstance(table[category], str) and table[category]
    router = config.build_router(s)
    # DEFAULT_CLASSIFICATION_TABLE is merged UNDER the operator's table --
    # every operator-supplied category above is present with the operator's
    # own string, PLUS "generic" (not in config.example.json) falls back to
    # the built-in default rather than being silently absent.
    for category, generic_prompt in table.items():
        assert router.classification_table[category] == generic_prompt
    assert router.classification_table["generic"] == config.DEFAULT_CLASSIFICATION_TABLE["generic"]
    assert isinstance(s.yaml.get("dependency_hints"), dict)


# --- clean-boot sanity: only NUNCIO_LLM_URL set yields zero unknown-var warnings ---

def test_minimal_boot_produces_no_unknown_var_warnings(caplog):
    with caplog.at_level("WARNING"):
        config.load_settings({"NUNCIO_LLM_URL": "http://ollama:11434"})
    assert "unknown env var" not in caplog.text


# --- full composition root (build_app) ---

def test_build_app_returns_a_working_app(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert isinstance(app, App)
    assert isinstance(app.engine, Engine)
    assert app.healthy()
    assert app.default_source == "generic"
    body = json.loads(app.config_json.decode())
    assert body["NUNCIO_LLM_URL"] == "http://ollama:11434"
    app.store.close()


def test_build_app_ingest_end_to_end_with_stdout_delivery(tmp_path, capsys):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_CONCURRENCY="0")
    app, settings = config.build_app(config.load_settings(s_env))
    status = app.ingest("generic", {"host": "web-1", "message": "disk 91% full"})
    assert status == 200
    assert app.q.qsize() == 1  # nothing is consuming it (concurrency=0), just verifying persistence
    app.store.close()


# --- dashboard context wiring ---

def test_build_plane_info_reports_private_model():
    s = config.load_settings(base_env(NUNCIO_LLM_MODEL="my-alias", NUNCIO_KNOWLEDGE_ENABLED="false"))
    info = config.build_plane_info(s)
    assert info["private"]["model"] == "my-alias"
    assert info["knowledge"]["enabled"] is False
    assert info["knowledge"]["model"] is None


def test_build_plane_info_reports_knowledge_model_only_when_enabled():
    s = config.load_settings(base_env(
        NUNCIO_KNOWLEDGE_ENABLED="true", NUNCIO_KNOWLEDGE_URL="http://gw:4000",
        NUNCIO_KNOWLEDGE_MODEL="gemini-alias",
    ))
    info = config.build_plane_info(s)
    assert info["knowledge"]["enabled"] is True
    assert info["knowledge"]["model"] == "gemini-alias"
    assert info["knowledge"]["data"] == "anonymised problem-class only"
    assert "distinct knowledge endpoint/model" in info["knowledge"]["active_when"]


def test_build_plane_info_knowledge_model_reflects_inheritance_when_unset():
    # Phase C: enabled by default, no NUNCIO_KNOWLEDGE_MODEL override -- the
    # reported model must be the EFFECTIVE (inherited) one, not empty.
    s = config.load_settings(base_env(NUNCIO_LLM_MODEL="private-alias"))
    info = config.build_plane_info(s)
    assert info["knowledge"]["enabled"] is True
    assert info["knowledge"]["model"] == "private-alias"


def test_collector_impl_names_reports_null_for_the_null_client():
    from nuncio.clients import NullClient
    n = NullClient()
    names = config.collector_impl_names(n, n, n)
    assert names == {"logs": "null", "containers": "null", "metrics": "null"}


def test_collector_impl_names_ignores_configured_but_unimplemented_backend():
    # An unrecognized NUNCIO_LOGS value -- build_log_client silently falls
    # back to NullClient, and the dashboard's impl name must reflect what was
    # ACTUALLY constructed, not the (misleading) configured value -- see
    # config._impl_name's docstring.
    s = config.load_settings(base_env(NUNCIO_LOGS="not-a-real-backend"))
    client = config.build_log_client(s)
    names = config.collector_impl_names(client, client, client)
    assert names["logs"] == "null"


# --- real client wiring: config selects the right class + impl name ---

def test_build_log_client_selects_openobserve():
    from nuncio.clients.logs import OpenObserveClient
    s = config.load_settings(base_env(NUNCIO_LOGS="openobserve", NUNCIO_LOGS_URL="http://o2:5080/api/default"))
    client = config.build_log_client(s)
    assert isinstance(client, OpenObserveClient)
    assert config.collector_impl_names(client, client, client)["logs"] == "openobserve"


def test_build_log_client_selects_loki():
    from nuncio.clients.logs import LokiClient
    s = config.load_settings(base_env(NUNCIO_LOGS="loki", NUNCIO_LOGS_URL="http://loki:3100"))
    client = config.build_log_client(s)
    assert isinstance(client, LokiClient)
    assert config.collector_impl_names(client, client, client)["logs"] == "loki"


def test_build_container_client_selects_docker():
    from nuncio.clients.containers import DockerClient
    s = config.load_settings(base_env(NUNCIO_CONTAINERS="docker"))
    client = config.build_container_client(s)
    assert isinstance(client, DockerClient)
    assert config.collector_impl_names(client, client, client)["containers"] == "docker"


def test_build_metrics_client_selects_prometheus():
    from nuncio.clients.metrics import PrometheusClient
    s = config.load_settings(base_env(NUNCIO_METRICS="prometheus", NUNCIO_METRICS_URL="http://prom:9090"))
    client = config.build_metrics_client(s)
    assert isinstance(client, PrometheusClient)
    assert config.collector_impl_names(client, client, client)["metrics"] == "prometheus"


def test_build_metrics_client_selects_checkmk():
    from nuncio.clients.metrics import CheckmkClient
    s = config.load_settings(base_env(NUNCIO_METRICS="checkmk", NUNCIO_METRICS_URL="http://cmk/check_mk/api/1.0"))
    client = config.build_metrics_client(s)
    assert isinstance(client, CheckmkClient)
    assert config.collector_impl_names(client, client, client)["metrics"] == "checkmk"


def test_client_timeout_stays_strictly_below_gather_timeout():
    s = config.load_settings(base_env(NUNCIO_GATHER_TIMEOUT_S="3.0"))
    assert config._client_timeout(s) < s.NUNCIO_GATHER_TIMEOUT_S


def test_client_timeout_floors_at_one_second_for_a_tight_gather_budget():
    s = config.load_settings(base_env(NUNCIO_GATHER_TIMEOUT_S="1.0"))
    assert config._client_timeout(s) == 1.0


def test_build_gatherer_wires_real_docker_client_into_container_state():
    # end-to-end: a configured-but-unreachable docker backend must degrade
    # the collector output, never raise out of gather().
    from nuncio.store import Store
    s = config.load_settings(base_env(NUNCIO_CONTAINERS="docker", NUNCIO_DOCKER_HOST="unix:///no/such/socket"))
    store = Store(":memory:")
    g = config.build_gatherer(s, store)
    bundle = g.gather({"host": "h", "service": "sonarr"}, "k1", 1000.0, timeout=2.0)
    assert "container not found" in bundle or "context unavailable" in bundle
    store.close()


def test_build_gatherer_wires_real_log_client_and_degrades_within_timeout_when_unreachable():
    # Same end-to-end shape, but for the log backend, and asserting the
    # WALL-CLOCK bound: an unreachable NUNCIO_LOGS_URL must not make gather()
    # take meaningfully longer than the timeout it was given.
    import time as _time
    from nuncio.store import Store
    s = config.load_settings(base_env(
        NUNCIO_LOGS="openobserve", NUNCIO_LOGS_URL="http://127.0.0.1:1",  # nothing listens here
        NUNCIO_GATHER_TIMEOUT_S="2.0",
    ))
    store = Store(":memory:")
    g = config.build_gatherer(s, store)
    start = _time.monotonic()
    bundle = g.gather({"host": "h", "service": "sonarr"}, "k1", 1000.0, timeout=1.0)
    elapsed = _time.monotonic() - start
    assert "no matching log lines" in bundle or "context unavailable" in bundle
    assert elapsed < 5.0  # generous slack; asserts "didn't hang", not tight latency
    store.close()


def test_build_gatherer_wraps_calls_with_collector_health():
    from nuncio.clients import CollectorHealth
    from nuncio.store import Store
    s = config.load_settings(base_env())
    store = Store(":memory:")
    health = CollectorHealth()
    g = config.build_gatherer(s, store, health=health)
    g.gather({"host": "h", "service": "s"}, "k1", 1000.0, timeout=1.0)
    snap = health.snapshot()
    # every collector fed by the (never-failing) NullClient reports healthy
    assert snap.get("logs", {}).get("ok", True) is True
    store.close()


def test_build_app_populates_dashboard_context(tmp_path):
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert app.collector_impls == {"logs": "null", "containers": "null", "metrics": "null"}
    assert app.plane_info["private"]["model"] == "default"
    assert app.delivery_adapters == ["stdout"]
    assert app.collector_health is not None
    app.store.close()


def test_build_app_loads_committed_logo_and_favicon_assets(tmp_path):
    # Assets are committed under nuncio/web/static/ -- this
    # is a regression test for the load path, not a placeholder: if the
    # asset files ever move/get renamed this must fail loudly, not silently
    # degrade to an empty logo.
    s_env = base_env(NUNCIO_DATA_DIR=str(tmp_path))
    app, settings = config.build_app(config.load_settings(s_env))
    assert len(app.logo_bytes) > 1000            # a real PNG, not empty
    assert app.logo_bytes[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic bytes
    assert app.favicon_data_uri.startswith("data:image/png;base64,")
    app.store.close()


# =====================================================================
# Settings screen: the overrides-file layer 
# =====================================================================

def test_overrides_file_missing_is_the_normal_first_boot_state(tmp_path):
    s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert s.overrides_doc["overrides"] == {}
    assert s.source["NUNCIO_MODE"] == "default"


def test_overrides_layer_wins_over_env_for_an_editable_key(tmp_path):
    config.write_overrides_file(
        str(tmp_path / "settings-overrides.json"),
        {"version": 1, "updated_at": None, "overrides": {"NUNCIO_MODE": "bypass"}, "audit": []},
    )
    s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_MODE="enriched"))
    assert s.NUNCIO_MODE == "bypass"
    assert s.source["NUNCIO_MODE"] == "override"


def test_overrides_layer_reports_env_source_when_no_override_present(tmp_path):
    s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path), NUNCIO_MODE="bypass"))
    assert s.source["NUNCIO_MODE"] == "env"


def test_overrides_layer_rejects_a_never_key_hand_edited_into_the_file(tmp_path, caplog):
    # A hand-edited overrides file naming a forbidden (NEVER-category) key
    # must NOT brick startup -- the offending key is dropped with a loud
    # warning and the env value (if any) applies instead.
    config.write_overrides_file(
        str(tmp_path / "settings-overrides.json"),
        {"version": 1, "updated_at": None,
         "overrides": {"NUNCIO_LLM_URL": "http://attacker.example", "NUNCIO_MODE": "bypass"},
         "audit": []},
    )
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert s.NUNCIO_LLM_URL == "http://ollama:11434"  # env value, untouched
    assert s.NUNCIO_MODE == "bypass"                  # the other, editable key still applies
    assert "NUNCIO_LLM_URL" in caplog.text


def test_overrides_layer_rejects_an_unknown_key(tmp_path, caplog):
    config.write_overrides_file(
        str(tmp_path / "settings-overrides.json"),
        {"version": 1, "updated_at": None, "overrides": {"NUNCIO_TOTALLY_MADE_UP": "x"}, "audit": []},
    )
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert not hasattr(s, "NUNCIO_TOTALLY_MADE_UP")


def test_overrides_layer_rejects_an_out_of_bounds_value(tmp_path, caplog):
    config.write_overrides_file(
        str(tmp_path / "settings-overrides.json"),
        {"version": 1, "updated_at": None, "overrides": {"NUNCIO_BUDGET_S": 99999}, "audit": []},
    )
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert s.NUNCIO_BUDGET_S == 30.0  # falls back to default, not the bad override
    assert s.source["NUNCIO_BUDGET_S"] == "default"


def test_overrides_layer_drops_a_retired_mode_value_with_a_warning(tmp_path, caplog):
    # A hand-edited (or stale, pre-upgrade) overrides file naming the retired
    # "raw_first" mode must not brick startup or silently resurrect the old
    # mode -- it's dropped (fails the enum's `allowed` check in _cast_value)
    # with a loud warning, and env/default applies instead.
    config.write_overrides_file(
        str(tmp_path / "settings-overrides.json"),
        {"version": 1, "updated_at": None, "overrides": {"NUNCIO_MODE": "raw_first"}, "audit": []},
    )
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert s.NUNCIO_MODE == "enriched"  # default applies, not the dropped override
    assert s.source["NUNCIO_MODE"] == "default"
    assert "NUNCIO_MODE" in caplog.text


def test_overrides_file_corrupt_json_degrades_to_empty_not_fatal(tmp_path):
    p = tmp_path / "settings-overrides.json"
    p.write_text("{not json", encoding="utf-8")
    s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))  # must not raise
    assert s.overrides_doc["overrides"] == {}


def test_write_overrides_file_is_atomic_no_tmp_left_behind(tmp_path):
    path = str(tmp_path / "settings-overrides.json")
    config.write_overrides_file(path, {"version": 1, "updated_at": "t", "overrides": {}, "audit": []})
    assert os.path.exists(path)
    assert not os.path.exists(path + ".tmp")


def test_ui_editable_table_has_no_overlap_with_never_reasons():
    assert set(config.UI_EDITABLE) & set(config.NEVER_REASONS) == set()


def test_never_reasons_covers_the_documented_security_perimeter():
    expected = {
        "NUNCIO_LLM_URL", "NUNCIO_LLM_KEY", "NUNCIO_LLM_HEADERS",
        "NUNCIO_KNOWLEDGE_URL", "NUNCIO_KNOWLEDGE_KEY",
        "NUNCIO_ASSIST_URL", "NUNCIO_ASSIST_KEY",
        "NUNCIO_ASSIST_DATA_POSTURE", "NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK",
        "NUNCIO_REDACT_EXTRA", "NUNCIO_EXTRA_SOURCES",
        "NUNCIO_DATA_DIR", "NUNCIO_CONFIG", "NUNCIO_ADMIN_TOKEN",
    }
    assert set(config.NEVER_REASONS) == expected


def test_never_reasons_are_terse_tooltip_length_now(tmp_path=None):
    # Live-feedback revision (v3-visual-refinements.md §4c): these strings
    # moved from an always-visible inline line to a hover/focus tooltip --
    # rewritten terse. Each still keeps its true rationale class (repoint /
    # credential / RCE / file-read / self-elevation / boot-only) but the old
    # long-form "security: ..."/"bootstrap: ..." prose prefix is gone, and
    # every string is short enough to read at a glance in a bubble.
    for key, reason in config.NEVER_REASONS.items():
        assert len(reason) <= 115, (key, reason, len(reason))
        assert not reason.startswith("security:"), key
        assert not reason.startswith("bootstrap:"), key
    # Spot-check the exact terse rewrites for a representative few.
    assert config.NEVER_REASONS["NUNCIO_LLM_KEY"] == "Env-only: private-plane credential."
    assert config.NEVER_REASONS["NUNCIO_EXTRA_SOURCES"] == "Env-only: importing modules by name is code execution."
    assert config.NEVER_REASONS["NUNCIO_ADMIN_TOKEN"] == "Env-only: the token that gates this API can't set itself."
    assert config.NEVER_REASONS["NUNCIO_CONFIG"] == "Read once at boot."
    # The knowledge-plane anonymisation sentence is kept once (on the URL
    # key), not duplicated on the KEY entry.
    assert "anonymised" in config.NEVER_REASONS["NUNCIO_KNOWLEDGE_URL"]
    assert "anonymised" not in config.NEVER_REASONS["NUNCIO_KNOWLEDGE_KEY"]


# =====================================================================
# Settings screen: rebuild-and-swap live-apply 
# =====================================================================

def _app_with_data_dir(tmp_path, **extra_env):
    env = base_env(NUNCIO_DATA_DIR=str(tmp_path), **extra_env)
    return config.build_app(config.load_settings(env))


def test_apply_changes_sets_a_live_key_and_persists_the_overrides_file(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    result = config.apply_changes(app, {"NUNCIO_MODE": "bypass"})
    assert result == {"applied": ["NUNCIO_MODE"], "restart_required": []}
    assert app.engine.mode == "bypass"
    assert app.settings.NUNCIO_MODE == "bypass"
    assert app.settings.source["NUNCIO_MODE"] == "override"
    on_disk = config.load_overrides_file(app.settings._overrides_path)[0]
    assert on_disk["overrides"]["NUNCIO_MODE"] == "bypass"
    app.store.close()


def test_apply_changes_atomic_nothing_written_on_validation_failure(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_MODE": "bypass", "NUNCIO_BUDGET_S": 99999})
    assert app.engine.mode == "enriched"  # the valid key in the same batch did NOT apply
    on_disk = config.load_overrides_file(app.settings._overrides_path)[0]
    assert on_disk["overrides"] == {}
    app.store.close()


def test_apply_changes_rejects_unknown_key_atomically(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_MODE": "bypass", "NUNCIO_NOT_A_REAL_KEY": "x"})
    assert "NUNCIO_NOT_A_REAL_KEY" in exc.value.errors
    assert app.engine.mode == "enriched"  # the whole batch is atomic -- nothing applied
    app.store.close()


def test_apply_changes_rebuilds_delivery_and_swaps_engine_delivery(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.delivery
    result = config.apply_changes(app, {"NUNCIO_DELIVERY": "stdout,stdout"})
    assert result["applied"] == ["NUNCIO_DELIVERY"]
    assert app.engine.delivery is not before
    assert app.delivery_adapters == ["stdout", "stdout"]
    assert app.engine.delivery.send(_envelope("hello")) is True
    app.store.close()


def test_apply_changes_unknown_delivery_adapter_rejected_nothing_swapped(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.delivery
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_DELIVERY": "not-a-real-channel"})
    assert app.engine.delivery is before
    app.store.close()


def test_apply_changes_rebuilds_llm_client_on_model_change(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.llm
    config.apply_changes(app, {"NUNCIO_LLM_MODEL": "a-new-alias"})
    assert app.engine.llm is not before
    assert app.engine.llm.model == "a-new-alias"
    app.store.close()


def test_apply_changes_enrich_format_updates_engine_attr(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    assert app.engine.enrich_format == "auto"
    config.apply_changes(app, {"NUNCIO_ENRICH_FORMAT": "text"})
    assert app.engine.enrich_format == "text"
    app.store.close()


def test_apply_changes_enrich_format_change_rebuilds_llm_client_resetting_cache(tmp_path):
    # A live NUNCIO_ENRICH_FORMAT flip is itself a member of _LLM_ROUTER_KEYS
    # (see test_nuncio_enrich_format_is_in_llm_router_keys) -- the client
    # rebuild it triggers is what clears a stale
    # llm._json_object_supported=False cache (e.g. text -> auto after an
    # operator fixes the endpoint's json_object support).
    app, settings = _app_with_data_dir(tmp_path)
    app.engine.llm._json_object_supported = False
    before = app.engine.llm
    config.apply_changes(app, {"NUNCIO_ENRICH_FORMAT": "text"})
    assert app.engine.llm is not before
    assert app.engine.llm._json_object_supported is None
    app.store.close()


def test_apply_changes_llm_timeout_updates_engine_per_attempt_s(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_LLM_TIMEOUT_S": 12})
    assert app.engine.per_attempt_s == 12.0
    app.store.close()


def test_apply_changes_llm_timeout_cannot_exceed_budget(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_LLM_TIMEOUT_S": 500})  # default budget is 30
    app.store.close()


def test_apply_changes_rebuilds_gatherer_on_correlation_window_change(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.gatherer
    config.apply_changes(app, {"NUNCIO_CORRELATION_WINDOW_S": 60})
    assert app.engine.gatherer is not before
    app.store.close()


# --- Batch B: NUNCIO_FINGERPRINT_WINDOW_S / NUNCIO_EVIDENCE_MAX_BYTES live-apply ---

def test_fingerprint_window_default():
    s = config.load_settings(base_env())
    assert s.NUNCIO_FINGERPRINT_WINDOW_S == 172800


def test_evidence_max_bytes_default():
    s = config.load_settings(base_env())
    assert s.NUNCIO_EVIDENCE_MAX_BYTES == 32000


def test_engine_built_with_fingerprint_window_and_evidence_max_bytes(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    assert app.engine.fingerprint_window_s == 172800
    assert app.engine.evidence_max_bytes == 32000
    app.store.close()


def test_apply_changes_fingerprint_window_updates_engine_attr_directly(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_FINGERPRINT_WINDOW_S": 3600})
    assert app.engine.fingerprint_window_s == 3600
    app.store.close()


def test_apply_changes_fingerprint_window_also_rebuilds_gatherer(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.gatherer
    config.apply_changes(app, {"NUNCIO_FINGERPRINT_WINDOW_S": 3600})
    assert app.engine.gatherer is not before  # so collect_recurrence picks up the new window
    app.store.close()


# --- Phase 3.2: NUNCIO_HOST_DOMAINS (correlation host-canonicalization suffixes) ---

def test_host_domains_default_is_empty_tuple():
    s = config.load_settings(base_env())
    assert s.host_domains == ()


def test_host_domains_csv_parsing_strips_whitespace_leading_dots_lowercases():
    s = config.load_settings(base_env(NUNCIO_HOST_DOMAINS=" .Kirits.NET , local, .example.com "))
    assert s.host_domains == ("kirits.net", "local", "example.com")


def test_host_domains_csv_parsing_drops_empties():
    s = config.load_settings(base_env(NUNCIO_HOST_DOMAINS="kirits.net,, ,.,local"))
    assert s.host_domains == ("kirits.net", "local")


def test_host_domains_is_ui_editable_live_category():
    spec = config.UI_EDITABLE["NUNCIO_HOST_DOMAINS"]
    assert spec.category == "live"
    assert spec.type == "str"


def test_apply_changes_host_domains_rebuilds_gatherer(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    before = app.engine.gatherer
    config.apply_changes(app, {"NUNCIO_HOST_DOMAINS": "kirits.net"})
    assert app.engine.gatherer is not before
    app.store.close()


def test_apply_changes_host_domains_takes_effect_live(tmp_path):
    # End-to-end: after a live NUNCIO_HOST_DOMAINS change, the rebuilt
    # gatherer's `correlated` collector actually canonicalizes hosts with
    # the new suffix -- not just "some gatherer object got rebuilt".
    import time as _time
    app, settings = _app_with_data_dir(tmp_path)
    app.store.persist("gpf", "[PROBLEM] svr disk pressure", host="svr", service="unrelated-check")
    config.apply_changes(app, {"NUNCIO_HOST_DOMAINS": "kirits.net"})
    alert = {"host": "svr.kirits.net", "service": "disk-root", "output": ""}
    section = app.engine.gatherer.collectors["correlated"](alert, "self", _time.time())
    assert "also active on svr" in section
    app.store.close()


def test_apply_changes_evidence_max_bytes_updates_engine_attr(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_EVIDENCE_MAX_BYTES": 5000})
    assert app.engine.evidence_max_bytes == 5000
    app.store.close()


def test_evidence_max_bytes_bounds_enforced(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_EVIDENCE_MAX_BYTES": 500})  # floor is 1000
    app.store.close()


# --- dependency_hints (NUNCIO_CONFIG) wiring ---

def test_build_gatherer_wires_dependency_hints_from_yaml_config(tmp_path):
    from nuncio.store import Store
    cfg_path = tmp_path / "aug.json"
    cfg_path.write_text(json.dumps({"dependency_hints": {"infisical": ["infisical-postgres"]}}))
    s = config.load_settings(base_env(NUNCIO_CONFIG=str(cfg_path)))
    store = Store(":memory:", clock=lambda: 990.0)
    store.persist("k1", "[PROBLEM] infisical-postgres FATAL wedge", source="checkmk")
    g = config.build_gatherer(s, store)
    section = g.collectors["correlated"](
        {"host": "", "service": "infisical", "output": "cannot connect to db"}, "self", 1000.0)
    assert "upstream dependency of infisical" in section
    store.close()


def test_build_gatherer_no_dependency_hints_when_absent():
    from nuncio.store import Store
    s = config.load_settings(base_env())
    store = Store(":memory:")
    g = config.build_gatherer(s, store)
    assert "correlated" in g.collectors
    store.close()


def test_apply_changes_restart_key_persists_but_does_not_touch_running_socket_settings(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    result = config.apply_changes(app, {"NUNCIO_PORT": 9999})
    assert result["applied"] == []                      # not live -- nothing "applied" now
    assert result["restart_required"] == ["NUNCIO_PORT"]
    assert app.settings.NUNCIO_PORT == 9999               # reflected for transparency
    app.store.close()


def test_restart_pending_diffs_against_boot_snapshot(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    assert config.restart_pending(app) == []
    config.apply_changes(app, {"NUNCIO_QUEUE_MAX": 5})
    assert config.restart_pending(app) == ["NUNCIO_QUEUE_MAX"]
    app.store.close()


def test_apply_changes_reset_removes_an_override(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_MODE": "bypass"})
    assert app.settings.NUNCIO_MODE == "bypass"
    config.apply_changes(app, {}, reset_list=["NUNCIO_MODE"])
    assert app.settings.NUNCIO_MODE == "enriched"  # back to the default
    assert app.settings.source["NUNCIO_MODE"] == "default"
    app.store.close()


def test_apply_changes_audit_log_records_key_names_and_action_never_values(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_NTFY_TOKEN": "supersecretvalue123"})
    audit = app.settings.overrides_doc["audit"]
    assert audit[0]["keys"] == ["NUNCIO_NTFY_TOKEN"]
    assert audit[0]["action"] == "set"
    assert "supersecretvalue123" not in json.dumps(audit)
    app.store.close()


def test_apply_changes_scalars_budget_retention_default_source(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_BUDGET_S": 30, "NUNCIO_RETENTION_DAYS": 5, "NUNCIO_DEFAULT_SOURCE": "checkmk"})
    assert app.engine.budget_s == 30.0
    assert app.budget_s == 30.0
    assert app.retention_s == 5 * 86400
    assert app.default_source == "checkmk"
    app.store.close()


# =====================================================================
# Settings screen: hard invariant guards 
# =====================================================================

@pytest.mark.parametrize("key", sorted(config.NEVER_REASONS))
def test_never_key_cannot_be_set_via_apply_changes(tmp_path, key):
    app, settings = _app_with_data_dir(tmp_path, **({"NUNCIO_KNOWLEDGE_URL": "http://gw:4000"} if key == "NUNCIO_KNOWLEDGE_KEY" else {}))
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {key: "attacker-controlled-value"})
    assert key in exc.value.errors
    app.store.close()


def test_never_key_cannot_be_reset_either(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {}, reset_list=["NUNCIO_ADMIN_TOKEN"])
    app.store.close()


def test_knowledge_plane_can_be_enabled_without_env_configured_url_inherits_private(tmp_path):
    # Phase C: inheritance makes the old "requires NUNCIO_KNOWLEDGE_URL" guard
    # unsatisfiable-to-violate -- enabling with no knowledge URL configured
    # now succeeds and the built knowledge_llm inherits the private plane's
    # endpoint.
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_ENABLED="false")  # no NUNCIO_KNOWLEDGE_URL in env
    result = config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": True})
    assert result["applied"] == ["NUNCIO_KNOWLEDGE_ENABLED"]
    assert app.router.knowledge_enabled is True
    assert app.engine.knowledge_llm is not None
    assert app.engine.knowledge_llm.base_url == settings.NUNCIO_LLM_URL
    app.store.close()


def test_knowledge_plane_can_be_enabled_when_env_url_present(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000",
                                        NUNCIO_KNOWLEDGE_ENABLED="false")
    result = config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": True})
    assert result["applied"] == ["NUNCIO_KNOWLEDGE_ENABLED"]
    assert app.router.knowledge_enabled is True
    app.store.close()


def test_knowledge_plane_can_always_be_disabled(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000",
                                        NUNCIO_KNOWLEDGE_ENABLED="true")
    result = config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": False})
    assert result["applied"] == ["NUNCIO_KNOWLEDGE_ENABLED"]
    app.store.close()


def test_settings_apply_never_constructs_a_knowledge_client_for_the_engine(tmp_path):
    # Structural guard: no combination of settings changes may cause
    # engine.llm to be built from anything but the env-pinned private-plane
    # URL/key -- there is no key that could smuggle a knowledge endpoint in.
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000")
    config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": True, "NUNCIO_LLM_MODEL": "x"})
    assert app.engine.llm.base_url == "http://ollama:11434"
    app.store.close()


def test_build_app_wires_no_knowledge_llm_when_disabled(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_ENABLED="false")  # Phase C: default is now true
    assert app.engine.knowledge_llm is None
    assert app.engine.router is not None  # router always built (gates knowledge_llm's use)
    app.store.close()


def test_build_app_wires_knowledge_llm_when_enabled_with_url(tmp_path):
    app, settings = _app_with_data_dir(
        tmp_path, NUNCIO_KNOWLEDGE_ENABLED="true", NUNCIO_KNOWLEDGE_URL="http://gw:4000",
        NUNCIO_KNOWLEDGE_MODEL="k-alias",
    )
    assert app.engine.knowledge_llm is not None
    assert app.engine.knowledge_llm.base_url == "http://gw:4000"
    assert app.engine.knowledge_llm.model == "k-alias"
    assert app.engine.router.knowledge_enabled is True
    app.store.close()


def test_apply_changes_enabling_knowledge_plane_builds_and_swaps_knowledge_llm(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000",
                                        NUNCIO_KNOWLEDGE_ENABLED="false")
    assert app.engine.knowledge_llm is None  # not enabled yet
    config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": True})
    assert app.engine.knowledge_llm is not None
    assert app.engine.knowledge_llm.base_url == "http://gw:4000"
    assert app.engine.router.knowledge_enabled is True
    app.store.close()


def test_apply_changes_disabling_knowledge_plane_swaps_router_off(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000",
                                        NUNCIO_KNOWLEDGE_ENABLED="true")
    assert app.engine.router.knowledge_enabled is True
    config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": False})
    assert app.engine.router.knowledge_enabled is False
    app.store.close()


def test_ingest_token_cannot_be_cleared_via_apply_changes(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_INGEST_TOKEN="original-token")
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_INGEST_TOKEN": ""})
    assert "NUNCIO_INGEST_TOKEN" in exc.value.errors
    assert app.token == "original-token"  # unchanged
    app.store.close()


def test_ingest_token_can_be_rotated_via_apply_changes(tmp_path):
    app, settings = _app_with_data_dir(tmp_path, NUNCIO_INGEST_TOKEN="original-token")
    config.apply_changes(app, {"NUNCIO_INGEST_TOKEN": "rotated-token"})
    assert app.token == "rotated-token"
    app.store.close()


def test_ingest_token_can_be_set_when_previously_unset(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)  # no ingest token configured
    config.apply_changes(app, {"NUNCIO_INGEST_TOKEN": "brand-new-token"})
    assert app.token == "brand-new-token"
    app.store.close()


def test_budget_s_cannot_be_set_below_the_floor(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_BUDGET_S": 1})  # floor is 10
    app.store.close()


def test_redaction_extra_rules_bad_regex_rejected_nothing_persisted(tmp_path):
    app, settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError):
        config.apply_changes(app, {"NUNCIO_REDACT_EXTRA_RULES": [{"type": "bad", "regex": "("}]})
    on_disk = config.load_overrides_file(app.settings._overrides_path)[0]
    assert "NUNCIO_REDACT_EXTRA_RULES" not in on_disk["overrides"]
    app.store.close()


def test_redaction_extra_rules_are_additive_and_take_effect_live(tmp_path):
    from nuncio.redactor import redact
    app, settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_REDACT_EXTRA_RULES": [{"type": "ticketid", "regex": r"TICKET-\d+"}]})
    text, findings = redact("see TICKET-4471 for context")
    assert "TICKET-4471" not in text
    assert any(f["type"] == "ticketid" for f in findings)
    app.store.close()


def test_redaction_extra_rules_cannot_remove_the_builtin_catalog(tmp_path):
    from nuncio.redactor import redact
    app, settings = _app_with_data_dir(tmp_path)
    # Setting the UI rule list to something unrelated must never disturb the
    # built-in catalog's ability to catch a recognizable secret shape.
    config.apply_changes(app, {"NUNCIO_REDACT_EXTRA_RULES": [{"type": "irrelevant", "regex": "zzz-not-present"}]})
    text, _ = redact("token sk-" "abcdefghijklmnopqrstuvwx1234 leaked")
    assert "sk-" "abcdefghijklmnopqrstuvwx1234" not in text
    app.store.close()


def test_redaction_extra_rules_reset_removes_ui_rules_but_env_rules_survive(tmp_path):
    from nuncio import redactor
    redactor.add_extra_rule("envrule", r"ENVSECRET-\d+")
    try:
        app, settings = _app_with_data_dir(tmp_path)
        config.apply_changes(app, {"NUNCIO_REDACT_EXTRA_RULES": [{"type": "uirule", "regex": r"UISECRET-\d+"}]})
        text, _ = redactor.redact("ENVSECRET-1 and UISECRET-2")
        assert "ENVSECRET-1" not in text and "UISECRET-2" not in text
        config.apply_changes(app, {}, reset_list=["NUNCIO_REDACT_EXTRA_RULES"])
        text, _ = redactor.redact("ENVSECRET-1 and UISECRET-2")
        assert "ENVSECRET-1" not in text        # env rule: still redacted
        assert "UISECRET-2" in text              # UI rule: gone after reset
        app.store.close()
    finally:
        redactor._ENV_EXTRA_RULES.clear()
        redactor._UI_EXTRA_RULES.clear()
        redactor._rebuild_extra_rules()


def test_extra_sources_key_not_editable_grep_guard():
    # NUNCIO_EXTRA_SOURCES (importlib.import_module of an operator string) is
    # the clearest RCE primitive in the whole settings surface -- assert its
    # absence from the editable table directly, rather than only indirectly
    # via the parametrized NEVER-key test above.
    assert "NUNCIO_EXTRA_SOURCES" not in config.UI_EDITABLE
    assert "NUNCIO_REDACT_EXTRA" not in config.UI_EDITABLE  # the PATH form, not _RULES
    assert "NUNCIO_REDACT_EXTRA_RULES" in config.UI_EDITABLE  # the safe inline form IS editable


# =====================================================================
# Coverage: validation error branches (invalid enum/JSON/range -> ConfigError
# or SettingsValidationError), the build_*()/plane-info paths, and a few
# startup-time branches not otherwise exercised.
# =====================================================================

def test_load_overrides_file_rejects_unexpected_shape(tmp_path, caplog):
    path = tmp_path / "settings-overrides.json"
    path.write_text(json.dumps({"not": "the expected shape"}), encoding="utf-8")
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DATA_DIR=str(tmp_path)))
    assert s.overrides_doc["overrides"] == {}
    assert "unexpected shape" in caplog.text


def test_load_overrides_file_normalizes_non_list_audit_to_empty_list(tmp_path):
    path = tmp_path / "settings-overrides.json"
    path.write_text(json.dumps({"version": 1, "updated_at": None, "overrides": {}, "audit": "not-a-list"}),
                     encoding="utf-8")
    doc, warnings = config.load_overrides_file(str(path))
    assert doc["audit"] == []
    assert warnings == []


# --- _cast_value: every ValueError branch, driven through apply_changes ---

def test_cast_value_rejects_non_string_for_a_str_key(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_LLM_MODEL": 12345})
    assert "expected a string" in exc.value.errors["NUNCIO_LLM_MODEL"]
    app.store.close()


def test_cast_value_rejects_bool_for_a_numeric_key(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_LLM_MAX_TOKENS": True})
    assert "expected a number" in exc.value.errors["NUNCIO_LLM_MAX_TOKENS"]
    app.store.close()


def test_cast_value_rejects_a_non_numeric_string_for_a_numeric_key(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_LLM_MAX_TOKENS": "not-a-number"})
    assert "not a valid int" in exc.value.errors["NUNCIO_LLM_MAX_TOKENS"]
    app.store.close()


def test_cast_value_rejects_an_invalid_bool_string(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": "maybe"})
    assert "expected a boolean" in exc.value.errors["NUNCIO_KNOWLEDGE_ENABLED"]
    app.store.close()


def test_cast_value_accepts_a_valid_bool_string(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path, NUNCIO_KNOWLEDGE_URL="http://gw:4000",
                                         NUNCIO_KNOWLEDGE_ENABLED="false")
    result = config.apply_changes(app, {"NUNCIO_KNOWLEDGE_ENABLED": "true"})
    assert result["applied"] == ["NUNCIO_KNOWLEDGE_ENABLED"]
    assert app.settings.NUNCIO_KNOWLEDGE_ENABLED is True
    app.store.close()


def test_cast_value_rejects_invalid_json_for_a_json_key(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_WEBHOOK_HEADERS": "{not valid json"})
    assert "not valid JSON" in exc.value.errors["NUNCIO_WEBHOOK_HEADERS"]
    app.store.close()


def test_cast_value_accepts_a_json_string_that_needs_parsing(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    result = config.apply_changes(app, {"NUNCIO_WEBHOOK_HEADERS": json.dumps({"X-Test": "1"})})
    assert result["applied"] == ["NUNCIO_WEBHOOK_HEADERS"]
    assert app.settings.webhook_headers == {"X-Test": "1"}
    app.store.close()


# --- NUNCIO_CONFIG (the YAML-flow-style JSON file) ---

def test_nuncio_config_invalid_json_content_raises_config_error(tmp_path):
    bad = tmp_path / "nuncio.yml"
    bad.write_text("{not: json, at, all", encoding="utf-8")
    with pytest.raises(config.ConfigError, match="only JSON-compatible YAML"):
        config.load_settings(base_env(NUNCIO_CONFIG=str(bad)))


def test_nuncio_config_valid_json_is_loaded():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "nuncio.yml")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"classification_table": {"container": "generic guidance"}}, f)
        s = config.load_settings(base_env(NUNCIO_CONFIG=path))
        assert s.yaml["classification_table"]["container"] == "generic guidance"


# --- Settings.__init__: env-value numeric cast failure ---

def test_settings_init_rejects_non_numeric_float_env_value():
    with pytest.raises(config.ConfigError, match="not a valid number"):
        config.load_settings(base_env(NUNCIO_BUDGET_S="not-a-number"))


def test_settings_init_rejects_non_numeric_int_env_value():
    with pytest.raises(config.ConfigError, match="not a valid integer"):
        config.load_settings(base_env(NUNCIO_CONCURRENCY="not-a-number"))


# --- Assist data-posture enum validation ---

def test_assist_data_posture_invalid_value_raises_config_error():
    with pytest.raises(config.ConfigError, match="NUNCIO_ASSIST_DATA_POSTURE"):
        config.load_settings(base_env(NUNCIO_ASSIST_DATA_POSTURE="not-a-real-posture"))


# --- webhook_headers / delivery_verbosity: env-string vs already-parsed-dict ---

def test_webhook_headers_invalid_json_env_string_raises_config_error():
    with pytest.raises(config.ConfigError, match="NUNCIO_WEBHOOK_HEADERS"):
        config.load_settings(base_env(NUNCIO_WEBHOOK_HEADERS="{not valid"))


def test_webhook_headers_already_a_dict_after_override_apply(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_WEBHOOK_HEADERS": {"X-Already-Dict": "1"}})
    assert app.settings.webhook_headers == {"X-Already-Dict": "1"}
    app.store.close()


def test_delivery_verbosity_already_a_dict_after_override_apply(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    config.apply_changes(app, {"NUNCIO_DELIVERY_VERBOSITY": {"stdout": "full"}})
    assert app.settings.delivery_verbosity == {"stdout": "full"}
    app.store.close()


def test_delivery_verbosity_invalid_json_raises_config_error():
    with pytest.raises(config.ConfigError, match="NUNCIO_DELIVERY_VERBOSITY"):
        config.load_settings(base_env(NUNCIO_DELIVERY_VERBOSITY="{not valid"))


def test_delivery_verbosity_non_dict_json_raises_config_error():
    with pytest.raises(config.ConfigError, match="must be a JSON object"):
        config.load_settings(base_env(NUNCIO_DELIVERY_VERBOSITY=json.dumps([1, 2, 3])))


def test_delivery_verbosity_invalid_value_raises_config_error():
    with pytest.raises(config.ConfigError, match="must be"):
        config.load_settings(base_env(NUNCIO_DELIVERY_VERBOSITY=json.dumps({"stdout": "extremely-loud"})))


def test_delivery_verbosity_unregistered_adapter_name_only_warns(caplog):
    with caplog.at_level("WARNING"):
        s = config.load_settings(base_env(NUNCIO_DELIVERY_VERBOSITY=json.dumps({"not-a-real-adapter": "brief"})))
    assert s.delivery_verbosity == {"not-a-real-adapter": "brief"}  # accepted, just warned
    assert "not-a-real-adapter" in caplog.text


def test_delivery_names_empty_string_falls_back_to_stdout():
    s = config.load_settings(base_env(NUNCIO_DELIVERY=""))
    assert s.delivery_names == ["stdout"]


def test_delivery_title_non_default_value_logs_a_notice(caplog):
    with caplog.at_level("INFO"):
        config.load_settings(base_env(NUNCIO_DELIVERY_TITLE="Custom Title"))
    assert "NUNCIO_DELIVERY_TITLE" in caplog.text


# --- apply_changes: structural checks beyond per-key bounds ---

def test_apply_changes_gather_timeout_cannot_exceed_budget(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_GATHER_TIMEOUT_S": 100})  # default budget is 30
    assert "NUNCIO_GATHER_TIMEOUT_S" in exc.value.errors
    app.store.close()


def test_apply_changes_rejects_an_unregistered_default_source(tmp_path):
    app, _settings = _app_with_data_dir(tmp_path)
    with pytest.raises(config.SettingsValidationError) as exc:
        config.apply_changes(app, {"NUNCIO_DEFAULT_SOURCE": "not-a-real-source"})
    assert "NUNCIO_DEFAULT_SOURCE" in exc.value.errors
    app.store.close()


def test_apply_changes_log_level_updates_the_root_logger(tmp_path):
    import logging as _logging
    app, _settings = _app_with_data_dir(tmp_path)
    original_level = _logging.getLogger().level
    try:
        config.apply_changes(app, {"NUNCIO_LOG_LEVEL": "debug"})
        assert _logging.getLogger().level == _logging.DEBUG
    finally:
        _logging.getLogger().setLevel(original_level)
        app.store.close()


# --- build_container_client / build_metrics_client: unrecognized backend ---

def test_build_container_client_unrecognized_backend_falls_back_to_null(caplog):
    from nuncio.clients import NullClient
    s = config.load_settings(base_env(NUNCIO_CONTAINERS="not-a-real-backend"))
    with caplog.at_level("WARNING"):
        client = config.build_container_client(s)
    assert isinstance(client, NullClient)
    assert "NUNCIO_CONTAINERS" in caplog.text


def test_build_metrics_client_unrecognized_backend_falls_back_to_null(caplog):
    from nuncio.clients import NullClient
    s = config.load_settings(base_env(NUNCIO_METRICS="not-a-real-backend"))
    with caplog.at_level("WARNING"):
        client = config.build_metrics_client(s)
    assert isinstance(client, NullClient)
    assert "NUNCIO_METRICS" in caplog.text


# --- build_assist: the enabled+configured construction path ---

def test_build_assist_disabled_returns_none():
    s = config.load_settings(base_env())
    assert config.build_assist(s, dispatch=None, store=None) is None


def test_build_assist_enabled_builds_an_assist_track():
    from nuncio.assist import AssistTrack
    s = config.load_settings(base_env(NUNCIO_ASSIST_ENABLED="true", NUNCIO_ASSIST_URL="http://assist:1234",
                                       NUNCIO_ASSIST_MODEL="assist-alias"))
    track = config.build_assist(s, dispatch=object(), store=object(), metrics=None)
    assert isinstance(track, AssistTrack)
    assert track.posture == "generic"
    assert track.severities == {"critical"}


# --- load_extra_sources: the actual importlib.import_module call ---

def test_load_extra_sources_imports_a_real_module():
    # A real, harmless stdlib module -- proves the import actually runs
    # (not just that the comma-split/strip logic works).
    s = config.load_settings(base_env(NUNCIO_EXTRA_SOURCES="json"))
    config.load_extra_sources(s)  # must not raise


# --- dashboard asset loading: missing-file degradation ---

def test_load_dashboard_assets_degrades_when_files_are_missing(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(config, "_ASSETS_DIR", tmp_path)  # empty dir -- neither asset exists
    with caplog.at_level("WARNING"):
        logo_bytes, favicon_data_uri = config._load_dashboard_assets()
    assert logo_bytes == b""
    assert favicon_data_uri == ""
    assert "logo asset not found" in caplog.text
    assert "favicon asset not found" in caplog.text


# --- build_app: loads NUNCIO_REDACT_EXTRA (the PATH form) at startup ---

def test_build_app_loads_extra_redaction_rules_from_env_path(tmp_path):
    from nuncio import redactor
    rules_path = tmp_path / "extra_rules.json"
    rules_path.write_text(json.dumps([
        {"type": "test_marker_rule", "regex": r"ZZZ_TEST_MARKER_UNLIKELY_TO_COLLIDE_98765"},
    ]), encoding="utf-8")
    data_dir = tmp_path / "data"
    env = base_env(NUNCIO_DATA_DIR=str(data_dir), NUNCIO_REDACT_EXTRA=str(rules_path))
    app, _settings = config.build_app(config.load_settings(env))
    try:
        text, _findings = redactor.redact("value is ZZZ_TEST_MARKER_UNLIKELY_TO_COLLIDE_98765 here")
        assert "ZZZ_TEST_MARKER_UNLIKELY_TO_COLLIDE_98765" not in text
    finally:
        app.store.close()
        redactor._ENV_EXTRA_RULES.clear()
        redactor._UI_EXTRA_RULES.clear()
        redactor._rebuild_extra_rules()


# --- Phase 0: per-key `stage` (intake|context|enrich|deliver|global) ---
#
# `stage` tells the (future) pipeline UI which pipeline stage owns a given
# setting. Every UI_EDITABLE key and every NEVER_REASONS key must resolve to
# one of the five canonical stages via config.stage_for().

_STAGES = {"intake", "context", "enrich", "deliver", "global"}


def test_every_ui_editable_key_resolves_to_a_valid_stage():
    for name, spec in config.UI_EDITABLE.items():
        stage = config.stage_for(name, spec)
        assert stage in _STAGES, f"{name} resolved to {stage!r}"


def test_every_never_key_resolves_to_a_valid_stage():
    for name in config.NEVER_REASONS:
        stage = config.stage_for(name, None)
        assert stage in _STAGES, f"{name} resolved to {stage!r}"


@pytest.mark.parametrize("name,expected", [
    # explicit pipeline-group overrides
    ("NUNCIO_ENRICH_FORMAT", "enrich"),
    ("NUNCIO_ENRICH_DEPTH", "enrich"),
    ("NUNCIO_GATHER_TIMEOUT_S", "context"),
    ("NUNCIO_BUNDLE_MAX_BYTES", "context"),
    ("NUNCIO_CORRELATION_WINDOW_S", "context"),
    ("NUNCIO_FINGERPRINT_WINDOW_S", "context"),
    ("NUNCIO_HOST_DOMAINS", "context"),
    # group-derived
    ("NUNCIO_LLM_MODEL", "enrich"),
    ("NUNCIO_INGEST_TOKEN", "intake"),
    ("NUNCIO_DELIVERY", "deliver"),
    ("NUNCIO_MODE", "global"),
])
def test_stage_for_ui_editable_spot_checks(name, expected):
    spec = config.UI_EDITABLE[name]
    assert config.stage_for(name, spec) == expected


@pytest.mark.parametrize("name,expected", [
    ("NUNCIO_LLM_URL", "enrich"),
    ("NUNCIO_LLM_KEY", "enrich"),
    ("NUNCIO_LLM_HEADERS", "enrich"),
    ("NUNCIO_KNOWLEDGE_URL", "enrich"),
    ("NUNCIO_KNOWLEDGE_KEY", "enrich"),
    ("NUNCIO_ASSIST_URL", "enrich"),
    ("NUNCIO_ASSIST_KEY", "enrich"),
    ("NUNCIO_ASSIST_DATA_POSTURE", "enrich"),
    ("NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK", "enrich"),
    ("NUNCIO_EXTRA_SOURCES", "intake"),
    ("NUNCIO_REDACT_EXTRA", "global"),
    ("NUNCIO_DATA_DIR", "global"),
    ("NUNCIO_CONFIG", "global"),
    ("NUNCIO_ADMIN_TOKEN", "global"),
])
def test_stage_for_never_keys_spot_checks(name, expected):
    assert config.stage_for(name, None) == expected
