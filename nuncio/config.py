"""Configuration + composition root — the ONLY module (besides `__main__.py`)
that reads `os.environ`. Parses the full `NUNCIO_*` contract (+ optional
`NUNCIO_CONFIG` file), validates it, and constructs every collaborator the
server needs — wiring the pluggable source/delivery/client rings without the
core ever importing an adapter module directly.

Fail loud at startup: unknown `NUNCIO_*` vars are logged as warnings (typo
detection); the one missing required var (`NUNCIO_LLM_URL`) raises
`ConfigError` with a clear, example-bearing message. The full effective
config is logged (secrets masked BY THE REDACTOR ITSELF — dogfooding) and
served at `GET /config.json`.
"""
import importlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from nuncio import delivery as delivery_ring
from nuncio import sources
from nuncio.clients import CollectorHealth, NullClient
from nuncio.clients.containers import DockerClient
from nuncio.clients.logs import LokiClient, OpenObserveClient
from nuncio.clients.metrics import CheckmkClient, PrometheusClient
from nuncio.collectors import (
    collect_container_state,
    collect_correlated,
    collect_history,
    collect_kernel,
    collect_metrics,
    collect_recent_logs,
    collect_recurrence,
)
from nuncio.assist import AssistClient, AssistTrack
from nuncio.engine import Engine, _FULL_POST_GATHER_RESERVE_S
from nuncio.gatherer import Gatherer
from nuncio.llm import LLMClient, _chat_completions_url
from nuncio.redactor import compile_extra_rules, load_extra_rules, redact, set_ui_extra_rules
from nuncio.router import DEFAULT_CLASSIFICATION_TABLE, Router
from nuncio.server import App, Metrics
from nuncio.store import Store

log = logging.getLogger("nuncio.config")

# The dashboard's committed logo/favicon assets, shipped inside the package
# itself so a container build doesn't need the repo-root `assets/` directory.
_ASSETS_DIR = Path(__file__).resolve().parent / "web" / "static"

# name -> (default, caster). The complete NUNCIO_* contract.
# NUNCIO_LLM_URL has no usable default -- its absence is a fatal startup error,
# checked explicitly below (it is the ONLY required setting).
_SCHEMA = {
    "NUNCIO_LLM_URL": (None, str),
    "NUNCIO_LLM_KEY": ("", str),
    "NUNCIO_LLM_MODEL": ("default", str),
    "NUNCIO_LLM_TIMEOUT_S": (10.0, float),
    "NUNCIO_LLM_MAX_TOKENS": (400, int),
    "NUNCIO_LLM_HEADERS": ("{}", str),
    "NUNCIO_ENRICH_FORMAT": ("auto", str),
    "NUNCIO_KNOWLEDGE_ENABLED": ("true", str),
    "NUNCIO_KNOWLEDGE_URL": ("", str),
    "NUNCIO_KNOWLEDGE_KEY": ("", str),
    "NUNCIO_KNOWLEDGE_MODEL": ("", str),
    "NUNCIO_ASSIST_ENABLED": ("false", str),
    "NUNCIO_ASSIST_URL": ("", str),
    "NUNCIO_ASSIST_KEY": ("", str),
    "NUNCIO_ASSIST_MODEL": ("", str),
    "NUNCIO_ASSIST_DATA_POSTURE": ("generic", str),
    "NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK": ("false", str),
    "NUNCIO_ASSIST_SEVERITIES": ("critical", str),
    "NUNCIO_ASSIST_TIMEOUT_S": (60.0, float),
    "NUNCIO_DELIVERY": ("stdout", str),
    "NUNCIO_APPRISE_URL": ("", str),
    "NUNCIO_NTFY_URL": ("", str),
    "NUNCIO_NTFY_TOPIC": ("", str),
    "NUNCIO_NTFY_TOKEN": ("", str),
    "NUNCIO_TELEGRAM_BOT_TOKEN": ("", str),
    "NUNCIO_TELEGRAM_CHAT_ID": ("", str),
    "NUNCIO_SLACK_WEBHOOK_URL": ("", str),
    "NUNCIO_WEBHOOK_URL": ("", str),
    "NUNCIO_WEBHOOK_HEADERS": ("{}", str),
    "NUNCIO_WEBHOOK_TEMPLATE": ("", str),
    "NUNCIO_DELIVERY_TITLE": ("Nuncio alert", str),
    "NUNCIO_EMAIL_SMTP_HOST": ("", str),
    "NUNCIO_EMAIL_SMTP_PORT": (587, int),
    "NUNCIO_EMAIL_USER": ("", str),
    "NUNCIO_EMAIL_PASSWORD": ("", str),
    "NUNCIO_EMAIL_FROM": ("", str),
    "NUNCIO_EMAIL_TO": ("", str),
    "NUNCIO_EMAIL_TLS": ("starttls", str),
    "NUNCIO_DELIVERY_VERBOSITY": ("{}", str),
    "NUNCIO_MODE": ("enriched", str),
    "NUNCIO_DATA_DIR": ("/data", str),
    "NUNCIO_PORT": (8095, int),
    "NUNCIO_BIND": ("0.0.0.0", str),
    "NUNCIO_INGEST_TOKEN": ("", str),
    "NUNCIO_DEFAULT_SOURCE": ("generic", str),
    "NUNCIO_EXTRA_SOURCES": ("", str),
    "NUNCIO_BUDGET_S": (30.0, float),
    "NUNCIO_ENRICH_DEPTH": ("full", str),
    "NUNCIO_FULL_BUDGET_S": (60.0, float),
    "NUNCIO_CONCURRENCY": (1, int),
    "NUNCIO_QUEUE_MAX": (20, int),
    "NUNCIO_RETENTION_DAYS": (30, int),
    "NUNCIO_GATHER_TIMEOUT_S": (5.0, float),
    "NUNCIO_BUNDLE_MAX_BYTES": (16000, int),
    "NUNCIO_CORRELATION_WINDOW_S": (600, int),
    "NUNCIO_FINGERPRINT_WINDOW_S": (172800, int),
    "NUNCIO_HOST_DOMAINS": ("", str),
    "NUNCIO_EVIDENCE_MAX_BYTES": (32000, int),
    "NUNCIO_LOGS": ("null", str),
    "NUNCIO_LOGS_URL": ("", str),
    "NUNCIO_LOGS_USER": ("", str),
    "NUNCIO_LOGS_TOKEN": ("", str),
    "NUNCIO_LOGS_INDEX": ("", str),
    "NUNCIO_CONTAINERS": ("null", str),
    "NUNCIO_DOCKER_HOST": ("unix:///var/run/docker.sock", str),
    "NUNCIO_METRICS": ("null", str),
    "NUNCIO_METRICS_URL": ("", str),
    "NUNCIO_METRICS_USER": ("", str),
    "NUNCIO_METRICS_TOKEN": ("", str),
    "NUNCIO_REDACT_EXTRA": ("", str),
    "NUNCIO_LOG_LEVEL": ("info", str),
    "NUNCIO_CONFIG": ("", str),
    "NUNCIO_ADMIN_TOKEN": ("", str),
}

_TRUTHY = ("1", "true", "yes", "on")

# The built-in delivery-safety modes.
_VALID_MODES = ("enriched", "bypass")

_OVERRIDES_FILENAME = "settings-overrides.json"
_EMPTY_OVERRIDES_DOC = {"version": 1, "updated_at": None, "overrides": {}, "audit": []}


class ConfigError(Exception):
    """Raised for a fatal startup config problem — `__main__.py` prints this
    and exits(1) rather than dumping a traceback."""


# --- the settings-screen editability contract ---
#
# UI_EDITABLE is the single source of truth for: the POST /settings
# allowlist, the settings-overrides.json load-time filter, and the
# GET /settings.json per-key metadata. A key absent from this table cannot be
# set via the HTTP API or a hand-edited overrides file, period -- that
# absence is itself the security boundary for the NEVER-category keys (see
# NEVER_REASONS below), not a branch that has to remember to reject them.

@dataclass(frozen=True)
class KeySpec:
    category: str            # "live" | "restart"
    type: str                # "str" | "int" | "float" | "bool" | "enum" | "json"
    default: object = None
    allowed: tuple = None    # for type == "enum"
    min: object = None       # for type in ("int", "float")
    max: object = None
    secret: bool = False     # write-only in the UI; GET renders «set»/«unset»
    confirm: bool = False    # UI shows an inline confirm dialog before apply
    group: str = "misc"
    label: str = ""
    help: str = ""


def _default(name):
    return _SCHEMA[name][0]


def _spec(name, **kw):
    kw.setdefault("default", _default(name) if name in _SCHEMA else None)
    return KeySpec(**kw)


UI_EDITABLE = {
    # --- LLM (private plane): only the model ALIAS + call-shaping knobs are
    # editable; the wire target (_URL/_KEY/_HEADERS) is a NEVER-key below. ---
    "NUNCIO_LLM_MODEL": _spec("NUNCIO_LLM_MODEL", category="live", type="str", group="llm",
                              label="Model", help="Model/alias name sent to the private-plane endpoint."),
    "NUNCIO_LLM_TIMEOUT_S": _spec("NUNCIO_LLM_TIMEOUT_S", category="live", type="float", min=1, max=600,
                                  group="llm", label="Per-attempt timeout (s)",
                                  help="Must not exceed the overall alert budget."),
    "NUNCIO_LLM_MAX_TOKENS": _spec("NUNCIO_LLM_MAX_TOKENS", category="live", type="int", min=16, max=4096,
                                   group="llm", label="Max completion tokens"),

    # --- Knowledge plane: on/off + alias only; the endpoint is a NEVER-key.
    # Enabled by default (Phase C) -- inherits the enrichment (private) plane's
    # endpoint/model/key whenever NUNCIO_KNOWLEDGE_URL/_MODEL/_KEY are empty, so
    # a default install has a working knowledge plane with zero extra config. ---
    "NUNCIO_KNOWLEDGE_ENABLED": _spec("NUNCIO_KNOWLEDGE_ENABLED", category="live", type="bool", confirm=True,
                                      group="knowledge", label="Knowledge plane enabled",
                                      help="Enabled by default: appends brief general guidance from a "
                                           "knowledge-plane LLM call after enrichment. Knowledge-plane calls are "
                                           "anonymised: only a generic, identifier-free problem-class description "
                                           "is ever sent — never alert text, hostnames, or any identifier. "
                                           "Defaults to the enrichment plane's endpoint/model; disabling is "
                                           "always allowed. At the homelab default (full depth, shared "
                                           "endpoint/model) the garnish is skipped as redundant with the deep RCA "
                                           "call already run on the same model -- it meaningfully fires only in "
                                           "low depth, or when pointed at a distinct knowledge endpoint/model."),
    "NUNCIO_KNOWLEDGE_MODEL": _spec("NUNCIO_KNOWLEDGE_MODEL", category="live", type="str", group="knowledge",
                                    label="Model",
                                    help="Alias sent to the knowledge-plane endpoint. Empty = inherit the "
                                         "enrichment model (NUNCIO_LLM_MODEL). Knowledge-plane calls are "
                                         "anonymised: only a generic, identifier-free problem-class description "
                                         "is ever sent — never alert text, hostnames, or any identifier."),

    # --- Assist plane: an optional, out-of-band, single hosted-LLM call made
    # STRICTLY AFTER the primary alert has already been delivered (own 60s
    # budget, never inside the 30s alert deadline). Only on/off + model alias
    # + severities + timeout are editable here; the wire target
    # (_URL/_KEY) and the data-exposure posture/attestation are NEVER-keys
    # below -- see NEVER_REASONS. ---
    "NUNCIO_ASSIST_ENABLED": _spec("NUNCIO_ASSIST_ENABLED", category="live", type="bool", confirm=True,
                                   group="assist", label="Assist plane enabled",
                                   help="Requires NUNCIO_ASSIST_URL to already be set in the environment; "
                                        "disabling is always allowed. Runs out-of-band, after the primary "
                                        "alert has already been delivered -- never inside the 30s alert budget."),
    "NUNCIO_ASSIST_MODEL": _spec("NUNCIO_ASSIST_MODEL", category="live", type="str", group="assist",
                                 label="Model",
                                 help="Alias sent to the assist endpoint. Recommend a Flash-tier/fast alias: a "
                                      "Pro-tier alias commonly returns 429 on a free-tier key (billing removes "
                                      "the limit but also flips the provider's terms to no-training); a "
                                      "Flash-tier alias measured ~19s average / ~32s worst case round trip, "
                                      "comfortably inside the 60s assist timeout."),
    "NUNCIO_ASSIST_SEVERITIES": _spec("NUNCIO_ASSIST_SEVERITIES", category="live", type="str", group="assist",
                                      label="Eligible severities (csv)",
                                      help="Comma-separated subset of critical|warning|info|ok|unknown -- only "
                                           "alerts at one of these severities are ever deferred to the assist "
                                           "plane."),
    "NUNCIO_ASSIST_TIMEOUT_S": _spec("NUNCIO_ASSIST_TIMEOUT_S", category="live", type="float", min=5, max=600,
                                     group="assist", label="Assist call budget (s)",
                                     help="The assist plane's OWN post-delivery budget -- entirely separate "
                                          "from the 30s alert deadline, which the assist call never runs inside."),

    # --- Delivery ---
    "NUNCIO_DELIVERY": _spec("NUNCIO_DELIVERY", category="live", type="str", confirm=True, group="delivery",
                             label="Delivery channels", help="Comma-separated adapter names."),
    # NUNCIO_APPRISE_URL, NUNCIO_SLACK_WEBHOOK_URL, NUNCIO_WEBHOOK_URL, and
    # NUNCIO_NTFY_TOPIC are all `secret=True`: a delivery target URL/topic IS
    # a credential (it grants "send a message as Nuncio" to whoever has it,
    # and several of these embed a bearer token directly in the path/query),
    # and GET /settings.json (like GET /config.json) is unauthenticated --
    # see the settings-screen security posture note at the top of this file.
    "NUNCIO_APPRISE_URL": _spec("NUNCIO_APPRISE_URL", category="live", type="str", secret=True, group="delivery",
                                label="Apprise URL"),
    "NUNCIO_NTFY_URL": _spec("NUNCIO_NTFY_URL", category="live", type="str", group="delivery", label="ntfy server URL"),
    "NUNCIO_NTFY_TOPIC": _spec("NUNCIO_NTFY_TOPIC", category="live", type="str", secret=True, group="delivery",
                               label="ntfy topic"),
    "NUNCIO_NTFY_TOKEN": _spec("NUNCIO_NTFY_TOKEN", category="live", type="str", secret=True, group="delivery",
                               label="ntfy token"),
    "NUNCIO_TELEGRAM_BOT_TOKEN": _spec("NUNCIO_TELEGRAM_BOT_TOKEN", category="live", type="str", secret=True,
                                       group="delivery", label="Telegram bot token"),
    "NUNCIO_TELEGRAM_CHAT_ID": _spec("NUNCIO_TELEGRAM_CHAT_ID", category="live", type="str", group="delivery",
                                     label="Telegram chat id"),
    "NUNCIO_SLACK_WEBHOOK_URL": _spec("NUNCIO_SLACK_WEBHOOK_URL", category="live", type="str", secret=True,
                                      group="delivery", label="Slack webhook URL"),
    "NUNCIO_WEBHOOK_URL": _spec("NUNCIO_WEBHOOK_URL", category="live", type="str", secret=True, group="delivery",
                                label="Generic webhook URL"),
    "NUNCIO_WEBHOOK_HEADERS": _spec("NUNCIO_WEBHOOK_HEADERS", category="live", type="json", secret=True,
                                    group="delivery", label="Generic webhook headers (JSON)"),
    "NUNCIO_WEBHOOK_TEMPLATE": _spec("NUNCIO_WEBHOOK_TEMPLATE", category="live", type="str", group="delivery",
                                     label="Generic webhook body template"),
    "NUNCIO_DELIVERY_TITLE": _spec("NUNCIO_DELIVERY_TITLE", category="live", type="str", group="delivery",
                                   label="Notification title prefix"),
    "NUNCIO_EMAIL_SMTP_HOST": _spec("NUNCIO_EMAIL_SMTP_HOST", category="live", type="str", group="delivery",
                                    label="Email SMTP host"),
    "NUNCIO_EMAIL_SMTP_PORT": _spec("NUNCIO_EMAIL_SMTP_PORT", category="live", type="int", min=1, max=65535,
                                    group="delivery", label="Email SMTP port"),
    "NUNCIO_EMAIL_USER": _spec("NUNCIO_EMAIL_USER", category="live", type="str", secret=True, group="delivery",
                               label="Email SMTP user"),
    "NUNCIO_EMAIL_PASSWORD": _spec("NUNCIO_EMAIL_PASSWORD", category="live", type="str", secret=True,
                                   group="delivery", label="Email SMTP password"),
    "NUNCIO_EMAIL_FROM": _spec("NUNCIO_EMAIL_FROM", category="live", type="str", group="delivery",
                               label="Email From address"),
    "NUNCIO_EMAIL_TO": _spec("NUNCIO_EMAIL_TO", category="live", type="str", secret=True, group="delivery",
                             label="Email To address(es)", help="Comma-separated; a delivery target is a credential."),
    "NUNCIO_EMAIL_TLS": _spec("NUNCIO_EMAIL_TLS", category="live", type="enum",
                              allowed=("starttls", "ssl", "none"), group="delivery", label="Email TLS mode"),
    "NUNCIO_DELIVERY_VERBOSITY": _spec("NUNCIO_DELIVERY_VERBOSITY", category="live", type="json", group="delivery",
                                       label="Per-adapter verbosity override (JSON)",
                                       help='JSON map of adapter name -> "brief" | "full", overlaying the built-in '
                                            "default per-adapter verbosity."),
    "NUNCIO_EVIDENCE_MAX_BYTES": _spec("NUNCIO_EVIDENCE_MAX_BYTES", category="live", type="int", min=1000, max=500000,
                                       group="delivery", label="Evidence section cap (bytes)",
                                       help="Cap on the labeled evidence sections (logs/metrics/container state/"
                                            "kernel/correlated/recurrence) rendered into the HTML detail and the "
                                            "plain-text evidence appendix."),

    # --- Pipeline & timing ---
    "NUNCIO_MODE": _spec("NUNCIO_MODE", category="live", type="enum", allowed=_VALID_MODES, confirm=True,
                         group="pipeline", label="Delivery mode",
                         help="enriched enriches via the LLM and falls back to the raw alert on any failure "
                              "or timeout (exactly one message, never lost); bypass skips enrichment and "
                              "delivers the raw alert as-is."),
    "NUNCIO_BUDGET_S": _spec("NUNCIO_BUDGET_S", category="live", type="float", min=10, max=600, group="pipeline",
                             label="Hard alert budget (s)"),
    "NUNCIO_ENRICH_DEPTH": _spec("NUNCIO_ENRICH_DEPTH", category="live", type="enum", allowed=("full", "low"),
                                 confirm=True, group="pipeline", label="Enrichment depth",
                                 help='"full" (default) adds recent-alert-history correlation and a bounded, '
                                      'up-to-2-call pipeline (fast triage + a deeper analysis) for richer context '
                                      '-- up to ~60s delivery latency. "low" is the single-call Phase-A path '
                                      '(faster, ~5-15s typical).'),
    "NUNCIO_FULL_BUDGET_S": _spec("NUNCIO_FULL_BUDGET_S", category="live", type="float", min=30, max=600,
                                  group="pipeline", label="Full-depth alert budget (s)",
                                  help="The hard budget a full-depth alert runs under (separate from, and always "
                                       "at least as large as, the standard NUNCIO_BUDGET_S -- a lower value here "
                                       "is used as a floor, never shrinks below NUNCIO_BUDGET_S, see the startup "
                                       "warning if this happens)."),
    "NUNCIO_GATHER_TIMEOUT_S": _spec("NUNCIO_GATHER_TIMEOUT_S", category="live", type="float", min=1, max=600,
                                     group="pipeline", label="Context-gather budget (s)"),
    "NUNCIO_BUNDLE_MAX_BYTES": _spec("NUNCIO_BUNDLE_MAX_BYTES", category="live", type="int", min=1000, max=100000,
                                     group="pipeline", label="Context bundle cap (bytes)"),
    "NUNCIO_CORRELATION_WINDOW_S": _spec("NUNCIO_CORRELATION_WINDOW_S", category="live", type="int", min=0, max=86400,
                                         group="pipeline", label="Correlation window (s)"),
    "NUNCIO_FINGERPRINT_WINDOW_S": _spec("NUNCIO_FINGERPRINT_WINDOW_S", category="live", type="int", min=0,
                                         max=2592000, group="pipeline", label="Recurrence window (s)",
                                         help="How far back to look when counting how many times this alert's "
                                              "signature has recurred (headline suffix + the recurrence "
                                              "collector section)."),
    "NUNCIO_HOST_DOMAINS": _spec("NUNCIO_HOST_DOMAINS", category="live", type="str", group="pipeline",
                                 label="Host domain suffixes",
                                 help="CSV of DNS suffixes stripped when comparing hosts for correlation "
                                      "(svr == svr.<suffix>). Empty = exact match only. Not DNS resolution -- "
                                      "correlation never resolves hostnames or IPs, it only strips a configured "
                                      "textual suffix before comparing."),
    "NUNCIO_ENRICH_FORMAT": _spec("NUNCIO_ENRICH_FORMAT", category="live", type="enum",
                                  allowed=("auto", "text"), group="pipeline", label="Enrichment output format",
                                  help='"auto" requests structured JSON output (with per-endpoint capability '
                                       'detection and an automatic fallback to plain text) for a clean, '
                                       'heading-free delivered message; "text" never attempts it.'),

    # --- Context sources (collector clients) ---
    "NUNCIO_LOGS": _spec("NUNCIO_LOGS", category="live", type="enum",
                         allowed=("null", "openobserve", "loki"),
                         group="sources", label="Log backend"),
    "NUNCIO_LOGS_URL": _spec("NUNCIO_LOGS_URL", category="live", type="str", group="sources", label="Log store URL"),
    "NUNCIO_LOGS_USER": _spec("NUNCIO_LOGS_USER", category="live", type="str", group="sources", label="Log store user"),
    "NUNCIO_LOGS_TOKEN": _spec("NUNCIO_LOGS_TOKEN", category="live", type="str", secret=True, group="sources",
                               label="Log store token"),
    "NUNCIO_LOGS_INDEX": _spec("NUNCIO_LOGS_INDEX", category="live", type="str", group="sources",
                               label="Log store index/stream"),
    "NUNCIO_CONTAINERS": _spec("NUNCIO_CONTAINERS", category="live", type="enum", allowed=("null", "docker"),
                               group="sources", label="Container backend"),
    "NUNCIO_DOCKER_HOST": _spec("NUNCIO_DOCKER_HOST", category="live", type="str", group="sources",
                                label="Docker/Podman socket or URL"),
    "NUNCIO_METRICS": _spec("NUNCIO_METRICS", category="live", type="enum", allowed=("null", "checkmk", "prometheus"),
                            group="sources", label="Metrics backend"),
    "NUNCIO_METRICS_URL": _spec("NUNCIO_METRICS_URL", category="live", type="str", group="sources", label="Metrics URL"),
    "NUNCIO_METRICS_USER": _spec("NUNCIO_METRICS_USER", category="live", type="str", group="sources",
                                 label="Metrics user"),
    "NUNCIO_METRICS_TOKEN": _spec("NUNCIO_METRICS_TOKEN", category="live", type="str", secret=True, group="sources",
                                  label="Metrics token"),

    # --- Redaction: additive-only inline rules; the built-in catalog and any
    # env-loaded NUNCIO_REDACT_EXTRA rules can never be disabled or removed
    # via this key -- see redactor.set_ui_extra_rules. ---
    "NUNCIO_REDACT_EXTRA_RULES": KeySpec(category="live", type="json", default=[], group="redaction",
                                         label="Extra redaction rules",
                                         help="JSON list of {\"type\", \"regex\"}, additive over the built-in "
                                              "catalog and any env-configured rules -- neither can be disabled here."),

    # --- Ingest ---
    "NUNCIO_INGEST_TOKEN": _spec("NUNCIO_INGEST_TOKEN", category="live", type="str", secret=True, group="ingest",
                                 label="Ingest shared token",
                                 help="May be set or rotated here, but never cleared -- clearing it must be an "
                                      "explicit environment-variable decision."),
    "NUNCIO_DEFAULT_SOURCE": _spec("NUNCIO_DEFAULT_SOURCE", category="live", type="str", group="ingest",
                                   label="Default source adapter"),

    # --- Storage & retention ---
    "NUNCIO_RETENTION_DAYS": _spec("NUNCIO_RETENTION_DAYS", category="live", type="int", min=1, max=3650,
                                   confirm=True, group="storage", label="Retention (days)",
                                   help="Lowering this destroys audit history for alerts older than the new "
                                        "window at the next maintenance sweep."),

    # --- Server (restart-required) ---
    "NUNCIO_CONCURRENCY": _spec("NUNCIO_CONCURRENCY", category="restart", type="int", min=1, max=64, group="server",
                                label="Worker concurrency"),
    "NUNCIO_QUEUE_MAX": _spec("NUNCIO_QUEUE_MAX", category="restart", type="int", min=1, max=100000, group="server",
                              label="Queue depth before load-shed"),
    "NUNCIO_PORT": _spec("NUNCIO_PORT", category="restart", type="int", min=1, max=65535, group="server",
                         label="Listen port"),
    "NUNCIO_BIND": _spec("NUNCIO_BIND", category="restart", type="str", group="server", label="Bind address"),

    # --- Misc ---
    "NUNCIO_LOG_LEVEL": _spec("NUNCIO_LOG_LEVEL", category="live", type="enum",
                              allowed=("debug", "info", "warning", "error"), group="misc", label="Log level"),
}

# The 14 NEVER-keys: genuine RCE/bootstrap/self-elevation primitives, not
# mere wiring. Deliberately absent from UI_EDITABLE (the absence IS the
# guard); listed here only for GET-side transparency (rendered read-only
# with a lock glyph and this reason).
NEVER_REASONS = {
    "NUNCIO_LLM_URL": "Env-only: a settable URL could repoint the private plane.",
    "NUNCIO_LLM_KEY": "Env-only: private-plane credential.",
    "NUNCIO_LLM_HEADERS": "Env-only: free-form headers could re-route the private plane.",
    "NUNCIO_KNOWLEDGE_URL": "Env-only endpoint. Only anonymised problem-class strings are ever sent to it "
                            "— never alert text or identifiers.",
    "NUNCIO_KNOWLEDGE_KEY": "Env-only: knowledge-plane credential.",
    "NUNCIO_ASSIST_URL": "Env-only: a settable URL could repoint the assist plane.",
    "NUNCIO_ASSIST_KEY": "Env-only: assist-plane credential.",
    "NUNCIO_ASSIST_DATA_POSTURE": "Env-only: what data may leave for assist is a boot decision, not a runtime "
                                  "toggle.",
    "NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK": "Env-only: this attestation can't be granted by the API it gates.",
    "NUNCIO_REDACT_EXTRA": "Env-only: a settable file path is a file-read primitive. Use NUNCIO_REDACT_EXTRA_RULES "
                           "instead.",
    "NUNCIO_EXTRA_SOURCES": "Env-only: importing modules by name is code execution.",
    "NUNCIO_DATA_DIR": "Set at boot: the store and this overrides file live here.",
    "NUNCIO_CONFIG": "Read once at boot.",
    "NUNCIO_ADMIN_TOKEN": "Env-only: the token that gates this API can't set itself.",
}


# --- pipeline stage: which of the five interactive-pipeline stages owns each
# setting (intake -> context -> enrich -> deliver, plus global/cross-cutting).
# Purely descriptive metadata for the (future) pipeline UI -- resolved at
# GET /settings.json emit time via stage_for() rather than baked onto each
# frozen KeySpec at construction, so this stays one obvious lookup table and
# NEVER-keys (which have no KeySpec/group at all) are handled the same way. ---

_GROUP_STAGE = {
    "llm": "enrich",
    "knowledge": "enrich",
    "assist": "enrich",
    "sources": "context",   # settings group "sources" = enrichment collectors
                             # (logs/metrics/containers), NOT ingest adapters
    "ingest": "intake",
    "delivery": "deliver",
    "pipeline": "global",
    "redaction": "global",
    "storage": "global",
    "misc": "global",
    "server": "global",
}

# Explicit per-key overrides for keys whose "pipeline" group name doesn't
# match the stage the key actually belongs to.
_KEY_STAGE_OVERRIDES = {
    "NUNCIO_ENRICH_FORMAT": "enrich",
    "NUNCIO_ENRICH_DEPTH": "enrich",
    "NUNCIO_GATHER_TIMEOUT_S": "context",
    "NUNCIO_BUNDLE_MAX_BYTES": "context",
    "NUNCIO_CORRELATION_WINDOW_S": "context",
    "NUNCIO_FINGERPRINT_WINDOW_S": "context",
    "NUNCIO_HOST_DOMAINS": "context",
}

# NEVER_REASONS keys have no KeySpec/group to derive a stage from -- mapped
# by hand instead. NUNCIO_ASSIST_DATA_POSTURE/_CONFIRM_EXTERNAL_OK are
# arguably global attestation flags rather than plane config, but are bucketed
# "enrich" here so they sit in the UI beside the assist controls they gate.
_NEVER_STAGE = {
    "NUNCIO_LLM_URL": "enrich",
    "NUNCIO_LLM_KEY": "enrich",
    "NUNCIO_LLM_HEADERS": "enrich",
    "NUNCIO_KNOWLEDGE_URL": "enrich",
    "NUNCIO_KNOWLEDGE_KEY": "enrich",
    "NUNCIO_ASSIST_URL": "enrich",
    "NUNCIO_ASSIST_KEY": "enrich",
    "NUNCIO_ASSIST_DATA_POSTURE": "enrich",
    "NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK": "enrich",
    "NUNCIO_EXTRA_SOURCES": "intake",
    "NUNCIO_REDACT_EXTRA": "global",
    "NUNCIO_DATA_DIR": "global",
    "NUNCIO_CONFIG": "global",
    "NUNCIO_ADMIN_TOKEN": "global",
}


def stage_for(name, spec):
    """Resolve the pipeline stage ("intake"|"context"|"enrich"|"deliver"|
    "global") for a setting `name`. `spec` is the key's KeySpec (from
    UI_EDITABLE) when it has one, or None for a NEVER_REASONS key. A per-key
    override wins; otherwise an editable key's group maps to a stage via
    _GROUP_STAGE, falling back to "global" for anything unrecognized."""
    if name in _KEY_STAGE_OVERRIDES:
        return _KEY_STAGE_OVERRIDES[name]
    if spec is None:
        return _NEVER_STAGE.get(name, "global")
    return _GROUP_STAGE.get(spec.group, "global")


def _overrides_path(data_dir):
    return os.path.join(data_dir, _OVERRIDES_FILENAME) if data_dir else None


def load_overrides_file(path):
    """Read `settings-overrides.json`. Returns (doc, warnings). A missing
    file is the normal first-boot state (no warning); a present-but-corrupt
    or malformed file degrades to empty overrides WITH a warning -- never
    fatal, same fail-loud-but-degrade posture as the rest of config."""
    if not path or not os.path.exists(path):
        return dict(_EMPTY_OVERRIDES_DOC), []
    warnings = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        return dict(_EMPTY_OVERRIDES_DOC), [f"{path}: could not be read/parsed ({e}); ignoring overrides"]
    if not isinstance(doc, dict) or not isinstance(doc.get("overrides"), dict):
        return dict(_EMPTY_OVERRIDES_DOC), [f"{path}: unexpected shape; ignoring overrides"]
    doc.setdefault("version", 1)
    doc.setdefault("updated_at", None)
    if not isinstance(doc.get("audit"), list):
        doc["audit"] = []
    return doc, warnings


def write_overrides_file(path, doc):
    """Atomic write: serialize -> tmp file -> flush+fsync -> os.replace. A
    crash mid-write leaves the previous file intact (same discipline as the
    store's persist-before-ACK, applied to config)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    data = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _cast_value(name, value, spec):
    """Cast+validate one incoming JSON value against its KeySpec. Raises
    ValueError (message is safe to surface to the operator) on any failure.
    Used both when loading settings-overrides.json (a bad entry there is
    logged and dropped, never fatal) and when validating a POST /settings
    body (a bad entry there is a 400, nothing applied)."""
    t = spec.type
    if t == "str":
        if not isinstance(value, str):
            raise ValueError("expected a string")
        return value
    if t in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError("expected a number")
        try:
            cast = int(value) if t == "int" else float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{value!r} is not a valid {t}")
        if spec.min is not None and cast < spec.min:
            raise ValueError(f"must be >= {spec.min}")
        if spec.max is not None and cast > spec.max:
            raise ValueError(f"must be <= {spec.max}")
        return cast
    if t == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in _TRUTHY + ("false", "0", "no", "off", ""):
            return value.strip().lower() in _TRUTHY
        raise ValueError("expected a boolean")
    if t == "enum":
        sval = str(value)
        if spec.allowed and sval not in spec.allowed:
            raise ValueError(f"must be one of {list(spec.allowed)}")
        return sval
    if t == "json":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                raise ValueError("not valid JSON")
        return value
    raise ValueError(f"unsupported type {t!r}")  # pragma: no cover -- defensive


def _load_json_config_file(path):
    """NUNCIO_CONFIG loader. The zero-dependency constraint (no pip installs,
    portability-critical) means no real YAML parser is available. Valid JSON
    is valid YAML 1.2 flow style, so this reads the file as JSON — a
    deliberate, documented subset of YAML, not full YAML support. A `.yml`
    extension is fine; the CONTENT must be JSON."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        return json.loads(text)
    except ValueError as e:
        raise ConfigError(
            f"NUNCIO_CONFIG={path!r}: only JSON-compatible YAML (flow style) is "
            f"supported without a YAML library; failed to parse as JSON: {e}"
        )


class Settings:
    """Parsed + validated NUNCIO_* settings (values only — building
    collaborators from them happens in the build_*() functions below)."""

    def __init__(self, env, overrides=None):
        """`overrides`, when given, is a pre-loaded overrides document
        (`{"version", "updated_at", "overrides", "audit"}`) to lay on top of
        `env` instead of reading `settings-overrides.json` off disk -- used
        by `apply_changes` to validate a CANDIDATE settings object (env plus
        a proposed change) through this exact same code path, so there is
        one validation story, not two. Normal boot (`overrides=None`) reads
        the file from `${NUNCIO_DATA_DIR}/settings-overrides.json`."""
        self._env = dict(env)
        for name, (default, caster) in _SCHEMA.items():
            raw = env.get(name)
            if raw is None:
                value = default
            elif caster is int:
                try:
                    value = int(raw)
                except ValueError:
                    raise ConfigError(f"{name}={raw!r} is not a valid integer")
            elif caster is float:
                try:
                    value = float(raw)
                except ValueError:
                    raise ConfigError(f"{name}={raw!r} is not a valid number")
            else:
                value = raw
            setattr(self, name, value)

        self.source = {name: ("env" if env.get(name) is not None else "default") for name in _SCHEMA}

        # --- overrides layer: the overrides file wins over env for editable
        # keys (S.1) -- an operator who edited a value in the settings screen
        # expects it to take effect, not be silently shadowed by an env var
        # set at container-build time. ---
        self._overrides_path = _overrides_path(self.NUNCIO_DATA_DIR)
        if overrides is None:
            doc, warnings = load_overrides_file(self._overrides_path)
        else:
            doc, warnings = overrides, []
        for w in warnings:
            log.warning("settings-overrides.json: %s", w)
        self.overrides_doc = doc
        self.NUNCIO_REDACT_EXTRA_RULES = list(UI_EDITABLE["NUNCIO_REDACT_EXTRA_RULES"].default)
        self.source["NUNCIO_REDACT_EXTRA_RULES"] = "default"
        for key, value in (doc.get("overrides") or {}).items():
            spec = UI_EDITABLE.get(key)
            if spec is None:
                log.warning(
                    "settings-overrides.json: %r is not a UI-editable key -- ignored "
                    "(env value, if any, applies)", key,
                )
                continue
            try:
                cast_value = _cast_value(key, value, spec)
            except ValueError as e:
                log.warning("settings-overrides.json: %r: %s -- ignored", key, e)
                continue
            setattr(self, key, cast_value)
            was_env = self.source.get(key) == "env"
            self.source[key] = "override"
            if was_env:
                log.info("%s: override %r shadows env value", key, cast_value)

        if not self.NUNCIO_LLM_URL:
            raise ConfigError(
                "NUNCIO_LLM_URL is required and is the ONLY mandatory Nuncio "
                "setting (example: NUNCIO_LLM_URL=http://ollama:11434)"
            )
        self.NUNCIO_KNOWLEDGE_ENABLED = str(self.NUNCIO_KNOWLEDGE_ENABLED).strip().lower() in _TRUTHY
        # Phase C: the knowledge plane INHERITS the enrichment (private)
        # plane's endpoint/model/key whenever the corresponding
        # NUNCIO_KNOWLEDGE_* var is empty -- so NUNCIO_KNOWLEDGE_ENABLED=true
        # (the default) is never unsatisfiable: there is no longer a
        # "requires NUNCIO_KNOWLEDGE_URL" startup error to raise, because an
        # empty NUNCIO_KNOWLEDGE_URL always resolves to a usable value (the
        # already-validated, required NUNCIO_LLM_URL). NUNCIO_KNOWLEDGE_URL/
        # _KEY stay env-only NEVER-keys; NUNCIO_KNOWLEDGE_MODEL stays
        # UI-editable -- see UI_EDITABLE/NEVER_REASONS above.
        # MUST-FIX 2: the private-plane KEY/MODEL must never be inherited to
        # a DISTINCT knowledge endpoint -- only inherit them when the URL
        # itself is ALSO inherited (i.e. NUNCIO_KNOWLEDGE_URL is empty, so the
        # knowledge plane shares the exact endpoint the key was already
        # authorized against). An operator who set a distinct
        # NUNCIO_KNOWLEDGE_URL but left NUNCIO_KNOWLEDGE_KEY empty must get an
        # empty knowledge_key, NEVER the private plane's credential sent to a
        # foreign host as a Bearer token.
        _knowledge_url_inherited = not self.NUNCIO_KNOWLEDGE_URL
        self.knowledge_url = self.NUNCIO_KNOWLEDGE_URL or self.NUNCIO_LLM_URL
        self.knowledge_model = self.NUNCIO_KNOWLEDGE_MODEL or (
            self.NUNCIO_LLM_MODEL if _knowledge_url_inherited else "")
        self.knowledge_key = self.NUNCIO_KNOWLEDGE_KEY or (
            self.NUNCIO_LLM_KEY if _knowledge_url_inherited else "")
        if (
            self.NUNCIO_KNOWLEDGE_ENABLED and not _knowledge_url_inherited
            and not self.NUNCIO_KNOWLEDGE_KEY
        ):
            log.warning(
                "knowledge plane targets a distinct endpoint with no NUNCIO_KNOWLEDGE_KEY; the private "
                "key is not inherited to a foreign endpoint -- set NUNCIO_KNOWLEDGE_KEY if it requires auth"
            )

        # --- Assist plane (Batch C) -- an optional, out-of-band, single
        # hosted-LLM call. Two independent flags gate anything leaving the
        # private planes for it: NUNCIO_ASSIST_ENABLED (turns the plane on at
        # all) and, separately, NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK (an explicit
        # attestation required ONLY when NUNCIO_ASSIST_DATA_POSTURE is the
        # riskier "scrubbed-real" setting) -- deliberately two flags, not
        # one, so a single typo can never leak scrubbed-real alert content to
        # an external endpoint. ---
        self.NUNCIO_ASSIST_ENABLED = str(self.NUNCIO_ASSIST_ENABLED).strip().lower() in _TRUTHY
        if self.NUNCIO_ASSIST_ENABLED and not self.NUNCIO_ASSIST_URL:
            raise ConfigError("NUNCIO_ASSIST_ENABLED=true requires NUNCIO_ASSIST_URL")
        self.NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK = str(self.NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK).strip().lower() in _TRUTHY
        _valid_postures = ("generic", "scrubbed-real")
        if self.NUNCIO_ASSIST_DATA_POSTURE not in _valid_postures:
            raise ConfigError(
                f"NUNCIO_ASSIST_DATA_POSTURE={self.NUNCIO_ASSIST_DATA_POSTURE!r} must be one of {_valid_postures}"
            )
        if self.NUNCIO_ASSIST_DATA_POSTURE == "scrubbed-real" and not self.NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK:
            raise ConfigError(
                "NUNCIO_ASSIST_DATA_POSTURE=scrubbed-real requires NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK=true -- "
                "both flags must be set explicitly: DATA_POSTURE picks what may leave the process, "
                "CONFIRM_EXTERNAL_OK is a separate attestation that an operator actually intended that, so a "
                "single typo'd flag can never leak scrubbed-real alert content to an external endpoint"
            )
        _valid_severities = ("critical", "warning", "info", "ok", "unknown")
        self.assist_severities = tuple(
            s.strip() for s in str(self.NUNCIO_ASSIST_SEVERITIES).split(",") if s.strip()
        )
        for s in self.assist_severities:
            if s not in _valid_severities:
                raise ConfigError(
                    f"NUNCIO_ASSIST_SEVERITIES contains {s!r}; must be a comma-separated subset of "
                    f"{_valid_severities}"
                )

        if self.NUNCIO_MODE not in _VALID_MODES:
            raise ConfigError(
                f"NUNCIO_MODE={self.NUNCIO_MODE!r} must be one of {_VALID_MODES}"
            )

        # --- Phase B: NUNCIO_ENRICH_DEPTH + NUNCIO_FULL_BUDGET_S ---
        _valid_depths = ("full", "low")
        if self.NUNCIO_ENRICH_DEPTH not in _valid_depths:
            raise ConfigError(
                f"NUNCIO_ENRICH_DEPTH={self.NUNCIO_ENRICH_DEPTH!r} must be one of {_valid_depths}"
            )
        # BLOCKER 4: deliberately NOT a ConfigError. NUNCIO_FULL_BUDGET_S <
        # NUNCIO_BUDGET_S must never brick a running install on upgrade (e.g.
        # an operator who raised NUNCIO_BUDGET_S above the 60s
        # NUNCIO_FULL_BUDGET_S default) -- take the larger of the two as the
        # effective full-depth budget (a full-depth alert must never get
        # LESS time than a standard one) and just warn. Every consumer
        # (Engine.full_budget_s, App.full_budget_s, the maintenance cutoff)
        # uses `effective_full_budget_s`, never the raw NUNCIO_FULL_BUDGET_S.
        self.effective_full_budget_s = max(self.NUNCIO_FULL_BUDGET_S, self.NUNCIO_BUDGET_S)
        if self.NUNCIO_FULL_BUDGET_S < self.NUNCIO_BUDGET_S:
            log.warning(
                "NUNCIO_FULL_BUDGET_S=%s is less than NUNCIO_BUDGET_S=%s -- using %s (the larger) as the "
                "effective full-depth budget so a full-depth alert is never given LESS time than a standard "
                "one; raise NUNCIO_FULL_BUDGET_S (or lower NUNCIO_BUDGET_S) to silence this warning",
                self.NUNCIO_FULL_BUDGET_S, self.NUNCIO_BUDGET_S, self.effective_full_budget_s,
            )

        # FIX 4: warn (never fatal) when NUNCIO_ENRICH_DEPTH=full can never
        # actually run the 2-call pipeline because the effective full-depth
        # budget is below the ladder's own post-gather reserve (see
        # Engine._enrich_full's gather gate, `_FULL_POST_GATHER_RESERVE_S`) --
        # at that budget every full-depth alert silently degrades to a single
        # standard call, which an operator who deliberately raised
        # NUNCIO_ENRICH_DEPTH=full for the 2-call pipeline should know about.
        _full_pipeline_floor_s = _FULL_POST_GATHER_RESERVE_S + 1.0
        if self.NUNCIO_ENRICH_DEPTH == "full" and self.effective_full_budget_s < _full_pipeline_floor_s:
            log.warning(
                "NUNCIO_ENRICH_DEPTH=full but the effective full-depth budget (%.1fs) is below the "
                "minimum the 2-call pipeline needs (%.1fs = the %.1fs post-gather reserve + 1s) -- "
                "full-depth alerts will behave as a single standard call until NUNCIO_FULL_BUDGET_S is "
                "raised (or NUNCIO_ENRICH_DEPTH is lowered to low)",
                self.effective_full_budget_s, _full_pipeline_floor_s, _FULL_POST_GATHER_RESERVE_S,
            )

        try:
            self.llm_headers = json.loads(self.NUNCIO_LLM_HEADERS or "{}")
        except ValueError:
            raise ConfigError(f"NUNCIO_LLM_HEADERS is not valid JSON: {self.NUNCIO_LLM_HEADERS!r}")
        # NUNCIO_WEBHOOK_HEADERS is UI-editable (type "json") -- once an
        # override has been applied its value is already a parsed dict, not
        # the raw env string, so both shapes are accepted here.
        if isinstance(self.NUNCIO_WEBHOOK_HEADERS, dict):
            self.webhook_headers = self.NUNCIO_WEBHOOK_HEADERS
        else:
            try:
                self.webhook_headers = json.loads(self.NUNCIO_WEBHOOK_HEADERS or "{}")
            except ValueError:
                raise ConfigError(f"NUNCIO_WEBHOOK_HEADERS is not valid JSON: {self.NUNCIO_WEBHOOK_HEADERS!r}")

        self.delivery_names = [n.strip() for n in self.NUNCIO_DELIVERY.split(",") if n.strip()]
        if not self.delivery_names:
            self.delivery_names = ["stdout"]

        # Phase 3.2: NUNCIO_HOST_DOMAINS -- CSV of DNS suffixes stripped when
        # comparing hosts for correlation (nuncio.model.canonical_host).
        # Default "" -> empty tuple -> canonical_host is a no-op beyond
        # lowercase/trailing-dot, i.e. exact match only -- nothing homelab-
        # specific baked into code. Each entry is stripped of whitespace and
        # leading dots and lowercased HERE (once) so canonical_host doesn't
        # have to re-normalize the config on every comparison; empties are
        # dropped.
        self.host_domains = tuple(
            d.strip().lstrip(".").lower()
            for d in str(self.NUNCIO_HOST_DOMAINS or "").split(",")
            if d.strip().lstrip(".")
        )

        # NUNCIO_DELIVERY_TITLE predates the Envelope/Dispatch rendering path
        # (nuncio/envelope.py's build_headline is now the sole source of a
        # delivered message's title) -- kept as a published, still-settable
        # key (never remove a published key out from under an operator) but
        # no longer consulted; a non-default value gets a one-line startup
        # notice rather than silently doing nothing.
        if self.NUNCIO_DELIVERY_TITLE != _default("NUNCIO_DELIVERY_TITLE"):
            log.info(
                "NUNCIO_DELIVERY_TITLE=%r is set but no longer used -- delivered titles are now built "
                "from each alert's headline (see nuncio.envelope.build_headline)",
                self.NUNCIO_DELIVERY_TITLE,
            )

        # NUNCIO_DELIVERY_VERBOSITY is UI-editable (type "json") -- once an
        # override has been applied its value is already a parsed dict, not
        # the raw env string, same dual-shape handling as webhook_headers
        # above.
        if isinstance(self.NUNCIO_DELIVERY_VERBOSITY, dict):
            raw_verbosity = self.NUNCIO_DELIVERY_VERBOSITY
        else:
            try:
                raw_verbosity = json.loads(self.NUNCIO_DELIVERY_VERBOSITY or "{}")
            except ValueError:
                raise ConfigError(
                    f"NUNCIO_DELIVERY_VERBOSITY is not valid JSON: {self.NUNCIO_DELIVERY_VERBOSITY!r}"
                )
        if not isinstance(raw_verbosity, dict):
            raise ConfigError("NUNCIO_DELIVERY_VERBOSITY must be a JSON object of adapter name -> verbosity")
        for adapter_name, v in raw_verbosity.items():
            if v not in (delivery_ring.BRIEF, delivery_ring.FULL):
                raise ConfigError(
                    f"NUNCIO_DELIVERY_VERBOSITY[{adapter_name!r}]={v!r} must be "
                    f"{delivery_ring.BRIEF!r} or {delivery_ring.FULL!r}"
                )
            if delivery_ring.get(adapter_name) is None:
                log.warning(
                    "NUNCIO_DELIVERY_VERBOSITY names %r, which is not a registered delivery "
                    "adapter (typo?)", adapter_name,
                )
        self.delivery_verbosity = raw_verbosity

        self.yaml = {}
        if self.NUNCIO_CONFIG:
            doc = _load_json_config_file(self.NUNCIO_CONFIG)
            self.yaml = doc if isinstance(doc, dict) else {}

    def as_dict(self):
        return {name: getattr(self, name) for name in _SCHEMA}


def load_settings(env=None):
    env = os.environ if env is None else env
    unknown = sorted(k for k in env if k.startswith("NUNCIO_") and k not in _SCHEMA)
    for k in unknown:
        log.warning("unknown env var %s (typo? not a recognized NUNCIO_* setting)", k)
    return Settings(env)


# --- live settings reconfiguration (settings screen backend) ---
#
# Design summary:
# rebuild the affected component(s) from a freshly VALIDATED candidate
# Settings, persist the overrides file, THEN swap the new object(s) into the
# running app with single attribute assignments. Order (validate -> build ->
# persist -> swap) means a rejected change leaves zero trace, and a crash
# between persist and swap merely means the change applies at next boot.

_APPLY_LOCK = threading.Lock()  # serializes concurrent POST /settings


class SettingsValidationError(Exception):
    """Raised for any rejected settings change -- caller (the HTTP layer)
    maps this to 400 with `.errors` as the per-key error map. Nothing is
    written or swapped when this is raised."""

    def __init__(self, errors):
        super().__init__("settings validation failed: " + ", ".join(sorted(errors)))
        self.errors = dict(errors)


# Which rebuild(s) a changed key triggers -- used by apply_changes to decide
# what to pre-build. Grouped generously (e.g. any LLM-affecting key rebuilds
# both the LLM client and the router together) because the builders are
# cheap and it removes any chance of a stale cross-reference between two
# components that are supposed to agree (e.g. the router's model alias vs.
# the LLM client's).
_LLM_ROUTER_KEYS = frozenset({
    "NUNCIO_LLM_MODEL", "NUNCIO_LLM_TIMEOUT_S", "NUNCIO_LLM_MAX_TOKENS",
    "NUNCIO_KNOWLEDGE_ENABLED", "NUNCIO_KNOWLEDGE_MODEL",
    # NUNCIO_ENRICH_FORMAT: a text<->auto flip must rebuild the LLMClient so
    # a stale `_json_object_supported` capability-cache value (learned
    # against a previous endpoint/mode) can never leak into the new one --
    # see nuncio.llm.LLMClient.__init__ and nuncio.engine's format ladder.
    "NUNCIO_ENRICH_FORMAT",
})
_ASSIST_KEYS = frozenset({
    "NUNCIO_ASSIST_ENABLED", "NUNCIO_ASSIST_MODEL", "NUNCIO_ASSIST_SEVERITIES", "NUNCIO_ASSIST_TIMEOUT_S",
})
_DELIVERY_KEYS = frozenset({
    "NUNCIO_DELIVERY", "NUNCIO_APPRISE_URL", "NUNCIO_NTFY_URL", "NUNCIO_NTFY_TOPIC", "NUNCIO_NTFY_TOKEN",
    "NUNCIO_TELEGRAM_BOT_TOKEN", "NUNCIO_TELEGRAM_CHAT_ID", "NUNCIO_SLACK_WEBHOOK_URL",
    "NUNCIO_WEBHOOK_URL", "NUNCIO_WEBHOOK_HEADERS", "NUNCIO_WEBHOOK_TEMPLATE", "NUNCIO_DELIVERY_TITLE",
    "NUNCIO_EMAIL_SMTP_HOST", "NUNCIO_EMAIL_SMTP_PORT", "NUNCIO_EMAIL_USER", "NUNCIO_EMAIL_PASSWORD",
    "NUNCIO_EMAIL_FROM", "NUNCIO_EMAIL_TO", "NUNCIO_EMAIL_TLS", "NUNCIO_DELIVERY_VERBOSITY",
})
_GATHERER_KEYS = frozenset({
    "NUNCIO_GATHER_TIMEOUT_S", "NUNCIO_BUNDLE_MAX_BYTES", "NUNCIO_CORRELATION_WINDOW_S",
    "NUNCIO_FINGERPRINT_WINDOW_S", "NUNCIO_HOST_DOMAINS",
    "NUNCIO_LOGS", "NUNCIO_LOGS_URL", "NUNCIO_LOGS_USER", "NUNCIO_LOGS_TOKEN", "NUNCIO_LOGS_INDEX",
    "NUNCIO_CONTAINERS", "NUNCIO_DOCKER_HOST",
    "NUNCIO_METRICS", "NUNCIO_METRICS_URL", "NUNCIO_METRICS_USER", "NUNCIO_METRICS_TOKEN",
})


def _touches(changed, group):
    return not changed.isdisjoint(group)


def restart_pending(app):
    """RESTART-category keys whose current effective value (post any
    settings apply) differs from the value captured at boot
    (`app.boot_effective`) -- the source of the persistent "restart to
    apply" banner. A RESTART key IS written to the overrides file and DOES
    show up in `Settings` immediately (so the settings screen honestly shows
    what will happen at next boot); nothing about the running process reads
    it again until then."""
    settings = app.settings
    boot = app.boot_effective or {}
    pending = []
    for name, spec in UI_EDITABLE.items():
        if spec.category != "restart":
            continue
        current = getattr(settings, name, spec.default)
        if boot.get(name, spec.default) != current:
            pending.append(name)
    return sorted(pending)


def _utcnow_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def apply_changes(app, set_map, reset_list=None):
    """Validate, persist, and live-apply a settings change against a running
    `App`. `set_map` is `{NUNCIO_KEY: json_value}`; `reset_list` drops a key's
    override so it falls back to its env/default value. Returns
    `{"applied": [...], "restart_required": [...]}` on success. Raises
    `SettingsValidationError` (-> HTTP 400) on any invalid key/value -- the
    request is atomic, nothing is written or swapped on a partial failure.
    An `OSError` from the file write (-> HTTP 500) also leaves the running
    config completely unchanged."""
    reset_list = list(reset_list or [])
    set_map = dict(set_map or {})

    with _APPLY_LOCK:
        errors = {}
        for k in list(set_map) + reset_list:
            if k not in UI_EDITABLE:
                errors[k] = NEVER_REASONS.get(k, "unknown setting")
        if errors:
            raise SettingsValidationError(errors)

        settings = app.settings
        candidate_values = {}
        for k, v in set_map.items():
            try:
                candidate_values[k] = _cast_value(k, v, UI_EDITABLE[k])
            except ValueError as e:
                errors[k] = str(e)
        if errors:
            raise SettingsValidationError(errors)

        # Hard guard: NUNCIO_INGEST_TOKEN may be rotated but never cleared via
        # this API -- going set -> empty must be an explicit env decision.
        if candidate_values.get("NUNCIO_INGEST_TOKEN") == "" and settings.NUNCIO_INGEST_TOKEN:
            raise SettingsValidationError({
                "NUNCIO_INGEST_TOKEN": "cannot be cleared via the settings API "
                                       "(would weaken ingest auth) -- unset NUNCIO_INGEST_TOKEN in the environment instead",
            })

        merged = dict(settings.overrides_doc.get("overrides") or {})
        for k in reset_list:
            merged.pop(k, None)
        merged.update(candidate_values)

        # The candidate's overrides_doc carries the REAL (post-this-change)
        # audit trail from the start -- so app.settings.overrides_doc is
        # correct immediately after the swap below, with no separate
        # "which doc did we actually persist" bookkeeping to keep in sync.
        doc = dict(settings.overrides_doc)
        doc["overrides"] = merged
        doc["version"] = 1
        doc["updated_at"] = _utcnow_iso()
        new_entries = []
        if set_map:
            new_entries.append({"ts": doc["updated_at"], "keys": sorted(set_map), "action": "set"})
        if reset_list:
            new_entries.append({"ts": doc["updated_at"], "keys": sorted(reset_list), "action": "reset"})
        doc["audit"] = (new_entries + list(doc.get("audit") or []))[:100]  # capped ring, newest first

        try:
            candidate = Settings(settings._env, overrides=doc)
        except ConfigError as e:
            # Settings.__init__ already enforces every remaining cross-field
            # rule (e.g. NUNCIO_ASSIST_ENABLED=true requires NUNCIO_ASSIST_URL)
            # -- reuse that ONE validation story rather than duplicating it
            # here. (Phase C removed the one cross-field rule that used to
            # need re-attribution to a specific key -- NUNCIO_KNOWLEDGE_ENABLED
            # can no longer fail this way, since an empty NUNCIO_KNOWLEDGE_URL
            # now always inherits NUNCIO_LLM_URL -- so this is a generic "_"
            # error for whatever startup rule remains.)
            raise SettingsValidationError({"_": str(e)})

        # Structural checks the per-key KeySpec bounds can't express alone.
        if candidate.NUNCIO_LLM_TIMEOUT_S > candidate.NUNCIO_BUDGET_S:
            raise SettingsValidationError({"NUNCIO_LLM_TIMEOUT_S": "must not exceed NUNCIO_BUDGET_S"})
        if candidate.NUNCIO_GATHER_TIMEOUT_S > candidate.NUNCIO_BUDGET_S:
            raise SettingsValidationError({"NUNCIO_GATHER_TIMEOUT_S": "must not exceed NUNCIO_BUDGET_S"})
        try:
            validate_default_source(candidate)
        except ConfigError as e:
            raise SettingsValidationError({"NUNCIO_DEFAULT_SOURCE": str(e)})

        changed = set(set_map) | set(reset_list)
        live_changed = {k for k in changed if UI_EDITABLE[k].category == "live"}

        # --- PRE-BUILD: any failure here still leaves everything untouched. ---
        rebuilt = {}
        try:
            if _touches(live_changed, _LLM_ROUTER_KEYS):
                rebuilt["llm"] = LLMClient(
                    candidate.NUNCIO_LLM_URL, candidate.NUNCIO_LLM_KEY, candidate.NUNCIO_LLM_MODEL,
                    timeout=candidate.NUNCIO_LLM_TIMEOUT_S, extra_headers=candidate.llm_headers,
                )
                rebuilt["router"] = build_router(candidate)
                rebuilt["knowledge_llm"] = build_knowledge_llm(candidate)
            if _touches(live_changed, _DELIVERY_KEYS):
                rebuilt["delivery"] = build_delivery(candidate)
            if _touches(live_changed, _ASSIST_KEYS) or _touches(live_changed, _DELIVERY_KEYS):
                # Rebuilt on a delivery-only change too, not just assist keys
                # -- the assist plane holds a `dispatch` reference captured
                # at construction time; a delivery-ring swap without this
                # would leave it pointed at the stale, pre-change Dispatch.
                rebuilt["assist"] = build_assist(
                    candidate, rebuilt.get("delivery", app.engine.delivery), app.store, metrics=app.metrics,
                )
            if _touches(live_changed, _GATHERER_KEYS):
                logs_client = build_log_client(candidate)
                container_client = build_container_client(candidate)
                metrics_client = build_metrics_client(candidate)
                rebuilt["gatherer"] = build_gatherer(
                    candidate, app.store, health=app.collector_health,
                    logs_client=logs_client, container_client=container_client, metrics_client=metrics_client,
                )
                rebuilt["collector_impls"] = collector_impl_names(logs_client, container_client, metrics_client)
            if "NUNCIO_REDACT_EXTRA_RULES" in live_changed:
                rebuilt["extra_rules"] = compile_extra_rules(candidate.NUNCIO_REDACT_EXTRA_RULES)
        except (ConfigError, ValueError) as e:
            raise SettingsValidationError({"_": str(e)})

        # --- PERSIST: durable intent, before anything is swapped. ---
        write_overrides_file(settings._overrides_path, doc)

        # --- SWAP: single-assignment installs; never mutate a live object. ---
        engine = app.engine
        if "llm" in rebuilt:
            engine.llm = rebuilt["llm"]
        if "router" in rebuilt:
            app.router = rebuilt["router"]
            engine.router = rebuilt["router"]
        if "knowledge_llm" in rebuilt:
            engine.knowledge_llm = rebuilt["knowledge_llm"]
        if "delivery" in rebuilt:
            engine.delivery = rebuilt["delivery"]
            app.delivery_adapters = list(candidate.delivery_names)
        if "assist" in rebuilt:
            engine.assist = rebuilt["assist"]
        if "gatherer" in rebuilt:
            engine.gatherer = rebuilt["gatherer"]
            app.collector_impls = rebuilt["collector_impls"]
        if "extra_rules" in rebuilt:
            set_ui_extra_rules(candidate.NUNCIO_REDACT_EXTRA_RULES)
        if "NUNCIO_LLM_TIMEOUT_S" in live_changed:
            engine.per_attempt_s = candidate.NUNCIO_LLM_TIMEOUT_S
        if "NUNCIO_MODE" in live_changed:
            engine.mode = candidate.NUNCIO_MODE
        if "NUNCIO_ENRICH_FORMAT" in live_changed:
            engine.enrich_format = candidate.NUNCIO_ENRICH_FORMAT
        if "NUNCIO_ENRICH_DEPTH" in live_changed:
            engine.depth = candidate.NUNCIO_ENRICH_DEPTH
        if "NUNCIO_FULL_BUDGET_S" in live_changed:
            engine.full_budget_s = candidate.effective_full_budget_s
            app.full_budget_s = candidate.effective_full_budget_s
        if "NUNCIO_BUDGET_S" in live_changed:
            engine.budget_s = candidate.NUNCIO_BUDGET_S
            app.budget_s = candidate.NUNCIO_BUDGET_S
            # NUNCIO_BUDGET_S feeds effective_full_budget_s's max() too -- a
            # BUDGET_S raise that now exceeds the current FULL_BUDGET_S must
            # push the effective full budget up right along with it (see
            # Settings.__init__'s BLOCKER 4 computation, re-run here via the
            # candidate that already went through it).
            engine.full_budget_s = candidate.effective_full_budget_s
            app.full_budget_s = candidate.effective_full_budget_s
        if "NUNCIO_FINGERPRINT_WINDOW_S" in live_changed:
            engine.fingerprint_window_s = candidate.NUNCIO_FINGERPRINT_WINDOW_S
        if "NUNCIO_EVIDENCE_MAX_BYTES" in live_changed:
            engine.evidence_max_bytes = candidate.NUNCIO_EVIDENCE_MAX_BYTES
        if "NUNCIO_RETENTION_DAYS" in live_changed:
            app.retention_s = candidate.NUNCIO_RETENTION_DAYS * 86400
        if "NUNCIO_INGEST_TOKEN" in live_changed:
            app.token = candidate.NUNCIO_INGEST_TOKEN or None
        if "NUNCIO_DEFAULT_SOURCE" in live_changed:
            app.default_source = candidate.NUNCIO_DEFAULT_SOURCE
        if "NUNCIO_LOG_LEVEL" in live_changed:
            logging.getLogger().setLevel(getattr(logging, candidate.NUNCIO_LOG_LEVEL.upper(), logging.INFO))

        app.settings = candidate
        app.plane_info = build_plane_info(candidate)
        app.config_json = json.dumps(masked_config_dict(candidate), sort_keys=True, default=str).encode()

        return {
            "applied": sorted(live_changed),
            "restart_required": restart_pending(app),
        }


# --- masked effective-config transparency (dogfoods nuncio's own redactor) ---

def masked_config_dict(settings):
    """The effective config with secrets stripped by nuncio.redactor.redact()
    itself — the same function that protects every outbound alert payload, so
    the startup log and `/config.json` can never leak a credential the
    redactor wouldn't also catch in normal traffic. Works because every
    secret-bearing NUNCIO_* name already matches the redactor's generic
    KEY/TOKEN/SECRET/PASSWORD "env" rule, and URL-embedded creds are caught by
    its "basic_auth" rule."""
    # Each "KEY = value" pair is redacted INDIVIDUALLY, with spaces around
    # "=" (not one joined multi-line "KEY=value" blob). Two independent
    # redactor edge cases otherwise bite here: (1) the kv/env value patterns
    # are whitespace-terminated but not newline-anchored, so an empty value
    # immediately followed by a newline can let a match's trailing \s*
    # swallow the newline and bleed into the next line's key; (2) a tight
    # "KEY=value" token with no separating space reads as ONE high-entropy
    # candidate to the entropy backstop (mixed-case + digits + "="/"_" is
    # exactly its trigger shape) even for an ordinary, non-secret setting
    # name. Spacing the "=" and redacting one line at a time avoids both.
    d = settings.as_dict()
    masked = {}
    for k, v in d.items():
        line = redact(f"{k} = {v}")[0]
        # A matched rule's replacement re-glues "KEY=value" WITHOUT the
        # spacing (its own hardcoded "="), so split on the first "=" and
        # strip rather than assuming " = " survives.
        _, _, mv = line.partition("=")
        masked[k] = mv.strip()
    return masked


def log_startup_config(settings):
    log.info("nuncio effective config: %s", json.dumps(masked_config_dict(settings), sort_keys=True))


# --- delivery ring wiring ---

def _delivery_cfg_by_name(settings):
    return {
        "apprise": {"url": settings.NUNCIO_APPRISE_URL},
        "ntfy": {"url": settings.NUNCIO_NTFY_URL, "topic": settings.NUNCIO_NTFY_TOPIC,
                 "token": settings.NUNCIO_NTFY_TOKEN or None},
        "telegram": {"bot_token": settings.NUNCIO_TELEGRAM_BOT_TOKEN,
                     "chat_id": settings.NUNCIO_TELEGRAM_CHAT_ID},
        "slack": {"webhook_url": settings.NUNCIO_SLACK_WEBHOOK_URL},
        "webhook": {"url": settings.NUNCIO_WEBHOOK_URL, "headers": settings.webhook_headers,
                    "template": settings.NUNCIO_WEBHOOK_TEMPLATE or None},
        "email": {"smtp_host": settings.NUNCIO_EMAIL_SMTP_HOST, "smtp_port": settings.NUNCIO_EMAIL_SMTP_PORT,
                  "user": settings.NUNCIO_EMAIL_USER, "password": settings.NUNCIO_EMAIL_PASSWORD,
                  "from_addr": settings.NUNCIO_EMAIL_FROM, "to": settings.NUNCIO_EMAIL_TO,
                  "tls": settings.NUNCIO_EMAIL_TLS},
        "stdout": {},
    }


def _verbosity_for(name, settings):
    return getattr(settings, "delivery_verbosity", {}).get(name, delivery_ring.DEFAULT_VERBOSITY.get(name, delivery_ring.FULL))


def build_delivery(settings):
    """NUNCIO_DELIVERY=a,b,c -> a `Dispatch` of `[(name, Retrying(adapter),
    verbosity), ...]`, one per configured channel -- the sole thing the
    engine calls (`Dispatch.send(envelope)`)."""
    cfg_by_name = _delivery_cfg_by_name(settings)
    channels = []
    for name in settings.delivery_names:
        if delivery_ring.get(name) is None:
            raise ConfigError(
                f"NUNCIO_DELIVERY names unknown adapter {name!r}; available: "
                f"{', '.join(delivery_ring.names())}"
            )
        adapter = delivery_ring.build(name, cfg_by_name.get(name, {}))
        channels.append((name, delivery_ring.Retrying(adapter), _verbosity_for(name, settings)))
    return delivery_ring.Dispatch(channels)


# --- collector-client ring wiring (protocols + NullClient default; real
# read-only implementations live in nuncio/clients/{logs,containers,metrics}.py
# and are selected here by NUNCIO_LOGS/NUNCIO_CONTAINERS/NUNCIO_METRICS. An
# unrecognized or not-yet-implemented backend name falls back to the null
# client with a warning rather than failing startup -- Level A must always
# keep working.) ---

def _client_impl_warning(env_name, value):
    log.warning(
        "%s=%s has no client implementation in this build — falling back to "
        "the null client",
        env_name, value,
    )


def _client_timeout(settings):
    """Every real client's socket timeout must sit strictly below the
    gather timeout passed to the collector (see the contract in
    nuncio/clients/__init__.py) -- otherwise a client's own I/O can hang
    past the budget the gatherer thinks it's enforcing. One second of
    headroom, floored at 1s so a very tight NUNCIO_GATHER_TIMEOUT_S doesn't
    produce a zero/negative timeout."""
    return max(1.0, settings.NUNCIO_GATHER_TIMEOUT_S - 1.0)


def build_log_client(settings):
    backend = settings.NUNCIO_LOGS
    timeout = _client_timeout(settings)
    if backend == "openobserve":
        return OpenObserveClient(
            settings.NUNCIO_LOGS_URL, user=settings.NUNCIO_LOGS_USER,
            token=settings.NUNCIO_LOGS_TOKEN, stream=settings.NUNCIO_LOGS_INDEX,
            timeout=timeout,
        )
    if backend == "loki":
        return LokiClient(
            settings.NUNCIO_LOGS_URL, user=settings.NUNCIO_LOGS_USER,
            token=settings.NUNCIO_LOGS_TOKEN, timeout=timeout,
        )
    if backend not in ("null", "", None):
        _client_impl_warning("NUNCIO_LOGS", backend)
    return NullClient()


def build_container_client(settings):
    backend = settings.NUNCIO_CONTAINERS
    if backend == "docker":
        return DockerClient(settings.NUNCIO_DOCKER_HOST, timeout=_client_timeout(settings))
    if backend not in ("null", "", None):
        _client_impl_warning("NUNCIO_CONTAINERS", backend)
    return NullClient()


def build_metrics_client(settings):
    backend = settings.NUNCIO_METRICS
    timeout = _client_timeout(settings)
    if backend == "prometheus":
        return PrometheusClient(settings.NUNCIO_METRICS_URL, timeout=timeout)
    if backend == "checkmk":
        return CheckmkClient(
            settings.NUNCIO_METRICS_URL, user=settings.NUNCIO_METRICS_USER,
            token=settings.NUNCIO_METRICS_TOKEN, timeout=timeout,
        )
    if backend not in ("null", "", None):
        _client_impl_warning("NUNCIO_METRICS", backend)
    return NullClient()


def build_gatherer(settings, store, health=None,
                    logs_client=None, container_client=None, metrics_client=None):
    """Wires up the context gatherer. `correlated`/`recurrence` need only the
    store, so even a bare install (all-null clients) gets cross-alert
    correlation and recurrence for free — useful signal on a clean install
    with no other backends configured.

    `health` is an optional `CollectorHealth` tracker; when given, every
    collector-client call is wrapped so success/failure feeds the dashboard's
    plumbing-health strip. The `*_client` kwargs let `build_app` construct
    each client exactly once and reuse it for both this gatherer and the
    dashboard's impl-name reporting (`collector_impl_names`) — building fresh
    ones here too would double the unimplemented-backend warning log line.
    All still default to a fresh `build_*_client(settings)` call so this
    function also works standalone with just `(settings, store)`."""
    logs = logs_client if logs_client is not None else build_log_client(settings)
    cont = container_client if container_client is not None else build_container_client(settings)
    mets = metrics_client if metrics_client is not None else build_metrics_client(settings)
    logs_query = health.wrap("logs", logs.query) if health else logs.query
    cont_inspect = health.wrap("containers", cont.inspect) if health else cont.inspect
    mets_query = health.wrap("metrics", mets.query) if health else mets.query
    deps = settings.yaml.get("dependency_hints") if isinstance(settings.yaml, dict) else None
    if not isinstance(deps, dict):
        deps = None
    # Store-only sections (no network client involved) -- shared, unchanged
    # regardless of profile, so "full" and "low" always see the exact same
    # recurrence/history data; only correlated's own params (limit/top_n)
    # differ deep vs. standard (see full_collectors below).
    recurrence_fn = lambda a, k, now: collect_recurrence(  # noqa: E731
        store, a, now, window_s=settings.NUNCIO_FINGERPRINT_WINDOW_S
    )
    # Phase 3.5: `history_fn` used to omit `deps` entirely -- a pre-existing
    # inconsistency with `correlated` (below) that silently meant the
    # dependency-edge causal gate never fired in the 24h History section.
    # Both closures also take `host_domains=settings.host_domains` -- read
    # off THIS `settings` object at build time (not inside the lambda body),
    # which is still "live" because a NUNCIO_HOST_DOMAINS change is in
    # `_GATHERER_KEYS`, so `apply_changes` rebuilds this whole gatherer
    # (a fresh `build_gatherer` call with the new candidate Settings) rather
    # than mutating one in place -- see config.py's apply_changes.
    history_fn = lambda a, k, now: collect_history(  # noqa: E731
        store, k, now, a, back_edge_s=settings.NUNCIO_CORRELATION_WINDOW_S,
        deps=deps, host_domains=settings.host_domains,
    )
    collectors = {
        "recent_logs": lambda a, k, now: collect_recent_logs(logs_query, a),
        "container_state": lambda a, k, now: collect_container_state(cont_inspect, a),
        "metrics": lambda a, k, now: collect_metrics(mets_query, a),
        "kernel": lambda a, k, now: collect_kernel(logs_query, a),
        "correlated": lambda a, k, now: collect_correlated(
            store, k, now, window_s=settings.NUNCIO_CORRELATION_WINDOW_S, alert=a, deps=deps,
            host_domains=settings.host_domains,
        ),
        "recurrence": recurrence_fn,
        "history": history_fn,
    }
    # Deep collector profile (Phase B, NUNCIO_ENRICH_DEPTH=full) -- constants,
    # not settings-screen knobs (see the Phase B spec's "constants, not
    # knobs" note): wider log/kernel windows, more correlation candidates.
    # recurrence/history are identical to the standard profile (store-only,
    # nothing "deeper" to ask for) -- included here anyway so
    # Gatherer.select(profile="full") can find them without a per-name
    # degrade to `collectors` (harmless either way, but explicit is clearer).
    full_collectors = {
        "recent_logs": lambda a, k, now: collect_recent_logs(logs_query, a, max_lines=300, max_bytes=24000),
        "container_state": lambda a, k, now: collect_container_state(cont_inspect, a, max_log_lines=150),
        "metrics": lambda a, k, now: collect_metrics(mets_query, a, limit=80),
        "kernel": lambda a, k, now: collect_kernel(logs_query, a, max_lines=150),
        "correlated": lambda a, k, now: collect_correlated(
            store, k, now, window_s=settings.NUNCIO_CORRELATION_WINDOW_S, alert=a, deps=deps,
            host_domains=settings.host_domains, limit=50, top_n=12,
        ),
        "recurrence": recurrence_fn,
        "history": history_fn,
    }
    return Gatherer(collectors, timeout_s=settings.NUNCIO_GATHER_TIMEOUT_S,
                     max_bytes=settings.NUNCIO_BUNDLE_MAX_BYTES, full_collectors=full_collectors)


def _impl_name(client):
    """The dashboard's honest "impl" label for a collector-client ring slot —
    derived from the constructed object's own class name (e.g. a future
    `LokiClient` reports "loki") rather than from the configured env value,
    so a typo'd/unimplemented `NUNCIO_LOGS` setting that silently fell back to
    `NullClient` (see `_client_impl_warning`) honestly shows "null" on the
    dashboard too, not the misleading configured name."""
    if isinstance(client, NullClient):
        return "null"
    name = type(client).__name__
    if name.endswith("Client"):
        name = name[: -len("Client")]
    return name.lower() or "null"


def collector_impl_names(logs_client, container_client, metrics_client):
    return {
        "logs": _impl_name(logs_client),
        "containers": _impl_name(container_client),
        "metrics": _impl_name(metrics_client),
    }


# --- router (knowledge-plane classification table; consumed by the engine's
# best-effort knowledge-plane garnish -- see Engine._garnish_with_knowledge) ---

def _knowledge_redundant_with_private(settings):
    """True when the knowledge plane's EFFECTIVE endpoint+model (after
    inheritance, see Settings.__init__) is the same as the private plane's --
    computed by normalizing both base URLs through the exact same
    chat-completions-URL rule the real LLMClient uses (`_chat_completions_url`),
    so an operator who wrote NUNCIO_LLM_URL with/without a trailing `/v1` still
    compares equal to a knowledge URL spelled differently but resolving to the
    same resource. At the homelab default (knowledge inherits everything),
    this is always True -- see Engine._garnish_with_knowledge's redundancy
    skip, which combines this static, settings-time fact with the per-alert
    depth."""
    private_endpoint = _chat_completions_url((settings.NUNCIO_LLM_URL or "").rstrip("/"))
    knowledge_endpoint = _chat_completions_url((settings.knowledge_url or "").rstrip("/"))
    return private_endpoint == knowledge_endpoint and settings.knowledge_model == settings.NUNCIO_LLM_MODEL


def build_router(settings):
    operator_table = settings.yaml.get("classification_table") if isinstance(settings.yaml, dict) else None
    # DEFAULT_CLASSIFICATION_TABLE is merged UNDER any operator-supplied
    # table (operator entries win per-key) -- see the module docstring in
    # nuncio/router.py for why: without this, a fresh install's table
    # defaults to `{}` and enabling the knowledge plane would silently do
    # nothing (every route_knowledge() call misses).
    merged_table = {**DEFAULT_CLASSIFICATION_TABLE, **(operator_table or {})}
    return Router(
        private_alias=settings.NUNCIO_LLM_MODEL,
        knowledge_alias=settings.knowledge_model,
        classification_table=merged_table,
        knowledge_enabled=settings.NUNCIO_KNOWLEDGE_ENABLED,
        knowledge_redundant_with_private=_knowledge_redundant_with_private(settings),
    )


def build_knowledge_llm(settings):
    """The second, optional LLMClient for the knowledge plane -- built
    whenever the plane is ENABLED (Phase C: the URL/model/key always resolve
    to a usable value via inheritance, see Settings.__init__, so ENABLED is
    the only gate now). Returns None when disabled, which is the engine's own
    signal to never attempt a knowledge-plane call (see
    Engine._garnish_with_knowledge)."""
    if settings.NUNCIO_KNOWLEDGE_ENABLED:
        return LLMClient(
            settings.knowledge_url, settings.knowledge_key, settings.knowledge_model,
            timeout=settings.NUNCIO_LLM_TIMEOUT_S,
        )
    return None


def build_assist(settings, dispatch, store, metrics=None):
    """The optional Batch-C out-of-band assist plane -- a SINGLE post-
    delivery LLM call per eligible alert, made on its own worker thread with
    its own budget, NEVER inside the 30s alert deadline (see
    nuncio.assist's module docstring). Returns None when disabled (both
    `NUNCIO_ASSIST_ENABLED` and `NUNCIO_ASSIST_URL` are required, exactly like
    the knowledge plane's ENABLED+URL pairing) -- `Engine.assist is None` is
    itself the "disabled" signal everywhere downstream, so a disabled assist
    plane behaves exactly like pre-Batch-C Nuncio."""
    if not settings.NUNCIO_ASSIST_ENABLED or not settings.NUNCIO_ASSIST_URL:
        return None
    llm = LLMClient(
        settings.NUNCIO_ASSIST_URL, settings.NUNCIO_ASSIST_KEY, settings.NUNCIO_ASSIST_MODEL,
        timeout=settings.NUNCIO_ASSIST_TIMEOUT_S,
    )
    client = AssistClient(llm)
    table = settings.yaml.get("classification_table") if isinstance(settings.yaml, dict) else None
    return AssistTrack(
        client, dispatch, store, metrics=metrics,
        timeout_s=settings.NUNCIO_ASSIST_TIMEOUT_S,
        severities=settings.assist_severities,
        posture=settings.NUNCIO_ASSIST_DATA_POSTURE,
        classification_table=table or {},
    )


# --- source ring wiring ---

def load_extra_sources(settings):
    for mod in [m.strip() for m in settings.NUNCIO_EXTRA_SOURCES.split(",") if m.strip()]:
        importlib.import_module(mod)


def validate_default_source(settings):
    if sources.get(settings.NUNCIO_DEFAULT_SOURCE) is None:
        raise ConfigError(
            f"NUNCIO_DEFAULT_SOURCE={settings.NUNCIO_DEFAULT_SOURCE!r} is not a "
            f"registered source adapter; available: {', '.join(sources.names())}"
        )


# --- dashboard context wiring ---

def _load_dashboard_assets():
    """The dashboard's logo/favicon, read once at startup so `GET /logo.png`
    never touches the filesystem per-request. A missing asset degrades to
    empty (the dashboard's `<img>` tag has an `onerror` fallback and
    `_page_shell` omits the favicon `<link>` entirely when empty) rather than
    failing startup — the dashboard is a transparency nicety, never a reason
    Nuncio refuses to run."""
    logo_bytes = b""
    favicon_data_uri = ""
    try:
        logo_bytes = (_ASSETS_DIR / "nuncio-logo-mark.png").read_bytes()
    except OSError:
        log.warning("dashboard logo asset not found: %s", _ASSETS_DIR / "nuncio-logo-mark.png")
    try:
        favicon_data_uri = (_ASSETS_DIR / "favicon-32.b64.txt").read_text(encoding="utf-8").strip()
    except OSError:
        log.warning("dashboard favicon asset not found: %s", _ASSETS_DIR / "favicon-32.b64.txt")
    return logo_bytes, favicon_data_uri


def build_plane_info(settings):
    return {
        "private": {"model": settings.NUNCIO_LLM_MODEL},
        "knowledge": {
            "enabled": settings.NUNCIO_KNOWLEDGE_ENABLED,
            "model": settings.knowledge_model if settings.NUNCIO_KNOWLEDGE_ENABLED else None,
            "data": "anonymised problem-class only",
            "active_when": "low depth, or a distinct knowledge endpoint/model",
        },
        "assist": {
            "enabled": settings.NUNCIO_ASSIST_ENABLED,
            "model": settings.NUNCIO_ASSIST_MODEL if settings.NUNCIO_ASSIST_ENABLED else None,
            "posture": settings.NUNCIO_ASSIST_DATA_POSTURE,
        },
    }


# --- top-level composition root ---

def build_app(settings=None, clock=None):
    settings = settings or load_settings()
    clock = clock or time.monotonic
    logging.basicConfig(level=getattr(logging, settings.NUNCIO_LOG_LEVEL.upper(), logging.INFO))

    load_extra_sources(settings)
    validate_default_source(settings)
    if settings.NUNCIO_REDACT_EXTRA:
        load_extra_rules(settings.NUNCIO_REDACT_EXTRA)
    # UI-managed extra rules persisted in settings-overrides.json (if any)
    # apply at boot too, same as any other override.
    set_ui_extra_rules(settings.NUNCIO_REDACT_EXTRA_RULES)

    os.makedirs(settings.NUNCIO_DATA_DIR, exist_ok=True)
    store = Store(os.path.join(settings.NUNCIO_DATA_DIR, "alerts.db"))
    llm = LLMClient(
        settings.NUNCIO_LLM_URL, settings.NUNCIO_LLM_KEY, settings.NUNCIO_LLM_MODEL,
        timeout=settings.NUNCIO_LLM_TIMEOUT_S, extra_headers=settings.llm_headers,
    )
    delivery = build_delivery(settings)
    # Construct each collector client exactly once, wrap it for health
    # tracking, and reuse the SAME instances for both the gatherer and the
    # dashboard's impl-name reporting (a second construction would double
    # the unimplemented-backend warning log line -- see build_gatherer's
    # docstring).
    collector_health = CollectorHealth()
    logs_client = build_log_client(settings)
    container_client = build_container_client(settings)
    metrics_client = build_metrics_client(settings)
    gatherer = build_gatherer(
        settings, store, health=collector_health,
        logs_client=logs_client, container_client=container_client, metrics_client=metrics_client,
    )
    router = build_router(settings)
    knowledge_llm = build_knowledge_llm(settings)
    metrics = Metrics()
    assist = build_assist(settings, delivery, store, metrics=metrics)
    engine = Engine(
        store, llm, delivery, gatherer=gatherer,
        budget_s=settings.NUNCIO_BUDGET_S, per_attempt_s=settings.NUNCIO_LLM_TIMEOUT_S,
        mode=settings.NUNCIO_MODE,
        clock=clock,
        router=router, knowledge_llm=knowledge_llm,
        fingerprint_window_s=settings.NUNCIO_FINGERPRINT_WINDOW_S,
        evidence_max_bytes=settings.NUNCIO_EVIDENCE_MAX_BYTES,
        assist=assist,
        enrich_format=settings.NUNCIO_ENRICH_FORMAT,
        depth=settings.NUNCIO_ENRICH_DEPTH, full_budget_s=settings.effective_full_budget_s,
    )
    logo_bytes, favicon_data_uri = _load_dashboard_assets()
    app = App(
        engine, store, metrics, budget_s=settings.NUNCIO_BUDGET_S,
        concurrency=settings.NUNCIO_CONCURRENCY, queue_max=settings.NUNCIO_QUEUE_MAX,
        clock=clock, retention_s=settings.NUNCIO_RETENTION_DAYS * 86400,
        full_budget_s=settings.effective_full_budget_s,
        token=settings.NUNCIO_INGEST_TOKEN or None,
        default_source=settings.NUNCIO_DEFAULT_SOURCE,
        config_json=json.dumps(masked_config_dict(settings), sort_keys=True).encode(),
        collector_impls=collector_impl_names(logs_client, container_client, metrics_client),
        collector_health=collector_health,
        plane_info=build_plane_info(settings),
        delivery_adapters=settings.delivery_names,
        logo_bytes=logo_bytes,
        favicon_data_uri=favicon_data_uri,
        admin_token=settings.NUNCIO_ADMIN_TOKEN or None,
    )
    app.router = router
    # Settings-screen bookkeeping: the current effective Settings (apply_changes
    # reads/replaces this), and a snapshot of every RESTART-category key's
    # boot-time value (restart_pending() diffs against this to drive the
    # "restart to apply" banner).
    app.settings = settings
    app.boot_effective = {
        name: getattr(settings, name, spec.default)
        for name, spec in UI_EDITABLE.items() if spec.category == "restart"
    }
    log_startup_config(settings)
    return app, settings
