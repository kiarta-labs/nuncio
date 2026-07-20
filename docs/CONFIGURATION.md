# Configuration reference

Nuncio is configured entirely through environment variables prefixed `NUNCIO_`, plus an optional JSON/YAML-subset file for settings that don't fit a flat env var (see `NUNCIO_CONFIG` below). There are no config files baked into the image and no hidden defaults tied to any particular deployment.

`NUNCIO_LLM_URL` is the only required setting. An unrecognized `NUNCIO_*` variable is logged as a warning at startup (typo detection) rather than silently ignored.

The effective configuration (with every secret masked by Nuncio's own redactor) is available at `GET /config.json` and logged once at startup.

## LLM (required)

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_LLM_URL` | *(none — required)* | Base URL of any OpenAI-compatible chat-completions endpoint, e.g. `http://your-llm-gateway:11434/v1`. The `/v1` suffix is the documented convention and is accepted either way — with or without a trailing `/v1`, the client appends `/chat/completions` correctly and never doubles it. |
| `NUNCIO_LLM_KEY` | `""` | API key / bearer token for `NUNCIO_LLM_URL`, if required. |
| `NUNCIO_LLM_MODEL` | `default` | Model name/alias requested from `NUNCIO_LLM_URL`. |
| `NUNCIO_LLM_TIMEOUT_S` | `10.0` | Per-attempt LLM call timeout, in seconds. |
| `NUNCIO_LLM_MAX_TOKENS` | `400` | Cap on tokens requested from the LLM per enrichment. |
| `NUNCIO_LLM_HEADERS` | `{}` | Extra HTTP headers sent with every LLM request, as a JSON object string. |

## Knowledge plane (optional second LLM)

**On by default**, and by default it shares the enrichment (private) plane's endpoint, model, and key — nothing extra to configure for a working knowledge plane out of the box. An optional second, typically-hosted LLM that can add generic, non-sensitive guidance to alerts of specific, operator-chosen classes — the private plane above ALWAYS produces the real enrichment first; the knowledge plane, when it fires, only appends a clearly-labeled "General guidance" footer to that result. It never replaces the private plane, and a knowledge-plane failure (disabled, unreachable, timeout, empty response) never affects delivery — the private-plane result ships either way.

**Inheritance.** `NUNCIO_KNOWLEDGE_URL`/`_MODEL`/`_KEY` are each optional: leave any of them empty and it inherits the corresponding `NUNCIO_LLM_URL`/`_MODEL`/`_KEY` value. `NUNCIO_KNOWLEDGE_URL`/`_KEY` stay env-only (never settable via the settings screen — see the security perimeter note below); `NUNCIO_KNOWLEDGE_MODEL` is settings-screen editable.

**Classification table.** A built-in, identifier-free default table covers all five built-in categories (`hardware`/`storage`/`network`/`container`/`generic`) out of the box — enabling the plane is never a silent no-op. An operator-authored table (`classification_table` in an `NUNCIO_CONFIG` file, see [`config.example.json`](../config.example.json) for a ready-to-copy template) is merged **on top of** the built-in default, per-key — an override for one category leaves the others at their built-in default. **Caveat:** any operator-authored table string MUST itself stay generic and identifier-free — the anonymisation guarantee only holds if every value in the table does.

**Redundancy skip (honest default).** At the default combination — full enrichment depth (`NUNCIO_ENRICH_DEPTH=full`) plus the knowledge plane inheriting the private plane's endpoint and model — the garnish call is automatically **skipped**: the full-depth deep RCA call has already run the identical model against the full real context, so a second, generic, context-free call against that same model adds latency and tokens for no new information. The garnish therefore meaningfully fires only in `low` depth, or once you point the knowledge plane at a genuinely distinct endpoint/model.

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_KNOWLEDGE_ENABLED` | `true` | Enable the knowledge plane. Knowledge-plane calls are anonymised: only a generic, identifier-free problem-class description is ever sent — never alert text, hostnames, or any identifier. |
| `NUNCIO_KNOWLEDGE_URL` | `""` (inherits `NUNCIO_LLM_URL`) | Base URL. Same `/v1`-tolerant convention as `NUNCIO_LLM_URL`. Only anonymised problem-class strings are ever sent to this endpoint. |
| `NUNCIO_KNOWLEDGE_KEY` | `""` (inherits `NUNCIO_LLM_KEY`) | API key, if required. Only anonymised problem-class strings are ever sent to this endpoint. |
| `NUNCIO_KNOWLEDGE_MODEL` | `""` (inherits `NUNCIO_LLM_MODEL`) | Model name/alias. |

**Privacy invariant:** Knowledge-plane calls are anonymised: only a generic, identifier-free problem-class description is ever sent — never alert text, hostnames, or any identifier. The ONLY string the knowledge plane can ever receive is the classification table's VALUE for a matched class — never the alert's own text, host, service, output, or the private plane's enrichment. An alert's "class" is its `category` field (an adapter-supplied hint, or the same built-in heuristic — `hardware`/`storage`/`network`/`container`/`generic` — used elsewhere); the classification table's keys should match one of those. An alert whose class isn't in the table, or with the plane disabled, makes zero knowledge-plane calls — there is no code path that can send it raw alert content.

Example `NUNCIO_CONFIG` (JSON) classification table (same content as [`config.example.json`](../config.example.json)) — overrides just these two categories, `hardware`/`network`/`generic` still fall back to the built-in default:

```json
{
  "classification_table": {
    "storage": "common causes and standard fixes for a filesystem/mount failure on Linux",
    "container": "common causes and standard fixes for a crashed or restarting container"
  }
}
```

## Assist plane (optional, out-of-band)

Off by default. A SINGLE, optional call to a hosted LLM (Gemini, OpenAI, or any OpenAI-compatible endpoint) made STRICTLY AFTER the primary alert has already been delivered — never inside the 30s alert budget (`NUNCIO_BUDGET_S`). It runs on its own dedicated worker thread with its own separate budget (`NUNCIO_ASSIST_TIMEOUT_S`, default 60s), so a hung or slow assist call can never delay, or affect the outcome of, the primary alert — by the time the assist call even starts, the primary alert has already gone out. This is NOT an agentic loop: one scrub, one call, one insight (or none).

**Where it delivers.** The assist plane only ever enriches the FULL/rich delivery leg, never the terse/brief one:
- If you configure at least one BRIEF-verbosity channel (`ntfy`/`telegram`/`apprise`) AND at least one FULL-verbosity channel (`email`/`slack`/`webhook`/`stdout`), an eligible alert is *deferred*: the brief leg ships immediately (this is what discharges the never-lose guarantee — see [`observability.md`](observability.md) or the engine's own docstring), and the full leg waits for the assist call, then ships with a labeled `--- External assist (scrubbed):` block appended, at most `NUNCIO_ASSIST_TIMEOUT_S` later.
- If you only configure FULL-verbosity channels (e.g. `NUNCIO_DELIVERY=email` alone), there's no brief leg to defer past — the alert ships in full immediately, exactly like `NUNCIO_ASSIST_ENABLED=false` would, and the assist result (if any) arrives afterward as a **separate**, clearly-labeled `Assist follow-up: <headline>` message rather than being merged into the alert that already went out.
- If you only configure BRIEF-verbosity channels (e.g. `ntfy` alone), the assist plane never fires — there's no FULL channel to deliver even a follow-up into.
- Any assist failure or timeout never re-sends the primary alert (already delivered) and never blocks it — the rich leg, when applicable, simply ships late with no insight appended instead.

**What may leave the process** is gated by TWO independent settings on purpose — `NUNCIO_ASSIST_DATA_POSTURE` picks *what* may leave, `NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK` is a separate attestation that an operator actually intended that. Both env-only (never settable via the settings screen) — a single typo'd flag can never leak more than intended:

| Posture | What leaves the process |
|---|---|
| `generic` (default) | Only the alert's category + severity + this deployment's `classification_table` generic string for that category (the SAME allowlisted, identifier-free strings the knowledge plane above uses). No alert text, no host/service, no log lines — ever. |
| `scrubbed-real` | The alert's own (already-redacted) content — headline, top evidence sections (correlated/recurrence/first 20 log lines), and the private enrichment's first line — additionally run through a stricter scrubber (`nuncio.redactor.scrub_for_assist_plane`) that ALSO replaces emails, IPv4/IPv6 addresses, full domains, and known-shape usernames with stable `<type-N>` placeholders before anything leaves the process. Requires `NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK=true` at startup, or Nuncio refuses to boot. |

**Honest scrubbing limitation:** the assist scrubber only catches usernames in `user=`/`username=`/`login=`-shaped key-value pairs and `/home/<name>/` paths. A name mentioned in ordinary prose ("ping me, kirit, if this recurs") has no reliable generic pattern and will **not** be caught. Cover org-specific identifying shapes via `NUNCIO_REDACT_EXTRA`, same mechanism as any other secret shape.

A second, opposite-direction quirk: because the secrets-first pass runs before the scrubber's own placeholder rules, a long multi-level hostname whose leading label contains digits (e.g. `svr01.lan.example.net`) can get swept up whole as `«REDACTED:high_entropy»` instead of keeping the bare host label — this is over-redaction, never a leak, and common short hostnames like `svr.kirits.net` → `svr` are unaffected.

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_ASSIST_ENABLED` | `false` | Enable the assist plane. Requires `NUNCIO_ASSIST_URL` to already be set in the environment. |
| `NUNCIO_ASSIST_URL` | `""` | Base URL, required if enabled. Same `/v1`-tolerant convention as `NUNCIO_LLM_URL` — plus one extra case: a base already ending `/openai` (Gemini's OpenAI-compat shape, `.../v1beta/openai`) gets `/chat/completions` appended without an extra `/v1`. |
| `NUNCIO_ASSIST_KEY` | `""` | API key, if required. |
| `NUNCIO_ASSIST_MODEL` | `""` | Model name/alias. Recommend a **Flash-tier** (fast) alias, not a Pro-tier one: a Pro-tier alias commonly returns HTTP 429 on a free-tier key — paying for billing removes the 429s, but also flips that provider's terms to no-training on your traffic, a tradeoff worth making deliberately rather than by accident. A Flash-tier alias measured ~19s average / ~32s worst-case round trip in practice, comfortably inside the 60s default timeout. |
| `NUNCIO_ASSIST_DATA_POSTURE` | `generic` | `generic` or `scrubbed-real` — see the table above. |
| `NUNCIO_ASSIST_CONFIRM_EXTERNAL_OK` | `false` | Required (`true`) if `NUNCIO_ASSIST_DATA_POSTURE=scrubbed-real`; irrelevant for the default `generic` posture. |
| `NUNCIO_ASSIST_SEVERITIES` | `critical` | Comma-separated subset of `critical`\|`warning`\|`info`\|`ok`\|`unknown` — only alerts at one of these severities are ever deferred to the assist plane. |
| `NUNCIO_ASSIST_TIMEOUT_S` | `60.0` | The assist plane's OWN post-delivery budget, in seconds — entirely separate from `NUNCIO_BUDGET_S`; the assist call never runs inside the 30s alert deadline. |

## Delivery

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_DELIVERY` | `stdout` | Comma-separated adapter names to fan out to: `stdout`, `apprise`, `ntfy`, `telegram`, `slack`, `webhook`, `email`. |
| `NUNCIO_DELIVERY_TITLE` | `Nuncio alert` | Deprecated/unused as of v0.3.0 -- titles are now built from each alert's headline (`nuncio.envelope.build_headline`). Kept settable, never consulted. |
| `NUNCIO_APPRISE_URL` | `""` | Apprise gateway notify URL. |
| `NUNCIO_NTFY_URL` | `""` | ntfy server URL. |
| `NUNCIO_NTFY_TOPIC` | `""` | ntfy topic. |
| `NUNCIO_NTFY_TOKEN` | `""` | ntfy access token, if the topic is protected. |
| `NUNCIO_TELEGRAM_BOT_TOKEN` | `""` | Telegram bot token. |
| `NUNCIO_TELEGRAM_CHAT_ID` | `""` | Telegram chat id to send to. |
| `NUNCIO_SLACK_WEBHOOK_URL` | `""` | Slack incoming webhook URL. |
| `NUNCIO_WEBHOOK_URL` | `""` | Generic webhook URL. |
| `NUNCIO_WEBHOOK_HEADERS` | `{}` | Extra headers for the generic webhook, as a JSON object string. |
| `NUNCIO_WEBHOOK_TEMPLATE` | `""` | Optional body template for the generic webhook; empty uses the adapter's default JSON body. |
| `NUNCIO_EMAIL_SMTP_HOST` | `""` | SMTP host. |
| `NUNCIO_EMAIL_SMTP_PORT` | `587` | SMTP port. |
| `NUNCIO_EMAIL_USER` | `""` | SMTP auth user (login skipped if empty). |
| `NUNCIO_EMAIL_PASSWORD` | `""` | SMTP auth password. |
| `NUNCIO_EMAIL_FROM` | `""` | `From:` address. |
| `NUNCIO_EMAIL_TO` | `""` | Comma-separated `To:` address(es) -- a delivery target, treated as a credential. |
| `NUNCIO_EMAIL_TLS` | `starttls` | One of `starttls`, `ssl`, `none`. |
| `NUNCIO_DELIVERY_VERBOSITY` | `{}` | JSON object of adapter name -> `"brief"` \| `"full"`, overlaying the built-in default (`ntfy`/`telegram`/`apprise` = brief; `email`/`slack`/`webhook`/`stdout` = full). An unknown adapter name logs a startup warning; an invalid value is a fatal `ConfigError`. |

Every delivery attempt is retried by the built-in `Retrying` wrapper; a non-2xx or connection failure on one adapter doesn't stop the others in a multi-adapter `NUNCIO_DELIVERY` list. Each channel renders the alert at its own verbosity: `brief` channels get a terse title + a short (≤120 char) body, `full` channels get the complete detail (enrichment + embedded raw alert).

## Fail-safe mode

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_MODE` | `enriched` | One of `enriched`, `bypass`. |

- `enriched` — wait for the LLM, deliver the enriched message. Falls back to the raw alert (with an `[enrichment unavailable]` marker) if enrichment fails or times out — exactly one message, never lost.
- `bypass` — skip enrichment entirely and deliver the raw alert as-is, no marker. A pure, intentional pass-through for when you don't want LLM enrichment at all.

## Server & storage

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_DATA_DIR` | `/data` | Directory for the SQLite idempotency/audit store. |
| `NUNCIO_PORT` | `8095` | HTTP listen port. |
| `NUNCIO_BIND` | `0.0.0.0` | HTTP bind address. |
| `NUNCIO_INGEST_TOKEN` | `""` | Shared secret required as header `X-Auth-Token` on `/ingest*`. Empty means no auth check — put Nuncio behind a reverse proxy or IP allowlist in that case. |

## Ingest

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_DEFAULT_SOURCE` | `generic` | Source adapter used by `POST /ingest` when the payload doesn't identify its own source. |
| `NUNCIO_EXTRA_SOURCES` | `""` | Comma-separated Python modules to import at startup, each registering a custom source adapter. |

## Engine & concurrency

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_BUDGET_S` | `30.0` | Hard wall-clock budget per alert before the fail-safe path takes over. |
| `NUNCIO_CONCURRENCY` | `1` | Alerts enriched concurrently. |
| `NUNCIO_QUEUE_MAX` | `20` | Max alerts queued for enrichment before load-shedding. |
| `NUNCIO_RETENTION_DAYS` | `30` | Days of alert history kept before pruning. |

## Context gathering

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_GATHER_TIMEOUT_S` | `5.0` | Per-collector timeout when gathering extra context. |
| `NUNCIO_BUNDLE_MAX_BYTES` | `16000` | Hard cap on the assembled context bundle size. |
| `NUNCIO_CORRELATION_WINDOW_S` | `600` | Time window used to correlate related alerts together. |
| `NUNCIO_HOST_DOMAINS` | *(empty)* | Comma-separated DNS suffixes stripped when canonicalizing a host for correlation, so `svr`, `svr.kirits.net`, and `SVR` all collapse to one identity. E.g. `kirits.net,lan`. Matching is case-insensitive; a bare short name and its FQDN are treated as the same host. Empty means only case-folding is applied. Live-editable. |
| `NUNCIO_FINGERPRINT_WINDOW_S` | `172800` (48h) | How far back to look when counting how many times an alert's normalized signature (see `nuncio.fingerprint`) has recurred — feeds the headline's "(2nd in 48h)" suffix and the `## Recurrence` context section. Recurrence is ANNOTATION ONLY: it never suppresses, merges, or delays a delivery — deduplicating noisy alerts is the monitoring source's job, not Nuncio's. |
| `NUNCIO_EVIDENCE_MAX_BYTES` | `32000` | Cap on the labeled evidence sections (log excerpt/metrics/container state/kernel/correlated/recurrence) rendered into the HTML detail (`detail_html`) and the plain-text `--- Evidence:` appendix on `detail` for full-verbosity channels that render plain text only. |

### Correlation model

Correlation answers "is this alert related to another recent one?" using **causal keys**, not proximity. An alert is offered as correlated only when it shares at least one causal signal with the alert being enriched:

- **fingerprint** — the same normalized alert signature recurring.
- **unit / service** — the same container or service (`unit` is matched strictly and never falls back to a host or a placeholder like `-`).
- **declared dependency** — an `upstream dependency of <service>` relationship from the `dependency_hints` map below.

**Host is a grouping hint, not a causal signal.** On a single-host deployment (one machine running dozens of containers) every alert shares the host, so scoring on host alone would make everything "correlate" with everything. Host is therefore used only to *label* an already-causally-related alert ("also active on `<host>`"), never to admit an unrelated one. Hosts are canonicalized first (see `NUNCIO_HOST_DOMAINS`) so `svr` and `svr.kirits.net` are one identity, and placeholder/empty host values are ignored rather than treated as a wildcard.

### Dependency hints (optional, `NUNCIO_CONFIG`)

An optional `dependency_hints` map in an `NUNCIO_CONFIG` file lets the correlation collector recognize "alert B is a known upstream of alert A's service" and add an `upstream dependency of <service>` reason/score to the ranked correlation list, on top of the fingerprint/unit/service causal signals above:

```json
{
  "dependency_hints": {
    "infisical": ["infisical-postgres"],
    "gitea": ["gitea-db"]
  }
}
```

Keys are service names as they appear in the alert's `service` field; values are the list of upstream service names to word-match against other alerts' summaries in the correlation window. Entirely optional — omitting it (or the key) leaves correlation scoring exactly as it was without it.

## Extra-field enrichment

Beyond the base `host`/`service`/`state`/`output`/`timestamp` fields, the built-in CheckMK, Grafana, and OpenObserve adapters also populate a fixed set of optional "extra" fields on the alert — long output, performance data, the check command, acknowledgement/downtime state, group membership, evaluated values, and related links — from whatever their native payload carries. Each present extra is rendered as its own line in the `## Alert` block sent to the LLM, in a fixed order, right after the base fields.

**No new environment variables were added for this** — the field list and its per-field caps are internal constants (`nuncio/prompt.py`'s `_EXTRA_FIELD_SPECS`), not configurable. There's nothing to set here; this section exists purely to document what the prompt now includes.

**Canonical keys and caps** (chars; values over the cap are truncated with a marker naming the true original length):

| Key | Rendered as | Cap | Preserves |
|---|---|---|---|
| `details` | `details:` | 6144 | tail |
| `perfdata` | `perfdata:` | 2048 | tail |
| `check_command` | `check:` | 256 | head |
| `event` | `event:` | 64 | tail |
| `ack` | `ack:` | 512 | tail |
| `downtime` | `downtime:` | 64 | tail |
| `groups` | `groups:` | 256 | tail |
| `address` | `address:` | 128 | tail |
| `recurrence` | `recurrence:` | 64 | tail |
| `value` | `value:` | 768 | tail |
| `links` | `links:` | 512 | tail |

All but `check_command` are **tail-preserving** on overflow (the end of a long value is usually the most informative part — e.g. a failing summary line). `check_command` is **head-preserving** instead: CheckMK check commands are short, but the same field also carries OpenObserve's underlying query text (`SELECT ... FROM ...`), where the informative part is the start, not whatever trailing clause got cut off.

The base fields (`host`/`service`/`state`/`output`/`timestamp`) are capped too (`output` at 3072 chars, the rest at 64–256), and every field — base or extra — has any `«BUNDLE-START»`/`«BUNDLE-END»` sentinel text neutralized before rendering, so a value can't forge the untrusted-context boundary used elsewhere in the prompt.

**This allowlist is a prompt-injection boundary, not just a formatting convenience.** An alert dict may carry arbitrary adapter- or ingest-supplied keys (e.g. a payload posted straight at `/ingest/generic`); only the eleven keys above are ever rendered into the prompt, and every value — in any field — is treated as data to analyze, never as an instruction to follow, regardless of which field it arrived in.

**Per-source population** — see [docs/SOURCES.md](SOURCES.md#optional-extra-fields) for the full key list and the built-in adapters (`nuncio/sources/checkmk.py`, `nuncio/sources/grafana.py`, `nuncio/sources/openobserve.py`) for exactly which native fields map to which extra:

- **CheckMK** populates `details` (long plugin output), `perfdata`, `check_command`, `event` (notification type), `ack`, `downtime`, `groups`, `address`, and `recurrence` from the notification's `NOTIFY_*` macros.
- **Grafana** populates `value` (from `valueString`, falling back to a compact rendering of `values`) and `links` (runbook/panel/dashboard URLs from annotations).
- **OpenObserve** populates `details` (matched log rows, from an optional `rows`/`result`/`records` destination-template field), `value` (from `condition`/`threshold`/`trigger`), and `check_command` (from `query`/`sql`/`vrl` — the firing query itself). These three are the biggest single enrichment win for O2 alerts, but they require the alert destination's Body template to actually populate them — the recommended template and its `{rows}`/`{condition}`/`{sql}` placeholder keys are documented at the top of `nuncio/sources/openobserve.py`. **Those exact right-hand-side variable names are not confirmed against a live O2 v0.91-EE install** — verify the actual available template variables in your OpenObserve alert-destination editor and adjust the Body accordingly; the adapter degrades cleanly (the three extras are simply omitted) if the template doesn't populate them under one of the recognized aliases.

## Collector backends

All default to a no-op null client, so a bare install still runs (with cross-alert correlation available for free, since that collector only needs the alert store). Every real backend below is **read-only** (query/search/inspect endpoints only, never a write, exec, or admin action), uses a socket timeout kept strictly below `NUNCIO_GATHER_TIMEOUT_S`, and caps how much it fetches (line count and byte size). On any failure — timeout, connection error, bad auth, unexpected response shape — the backend degrades to an empty result rather than raising, so a misconfigured or temporarily-unreachable backend never blocks or breaks alert enrichment; the affected context section just reads "no matching log lines" / "container not found" / "(none)" instead.

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_LOGS` | `null` | Log backend: `null`, `openobserve`, or `loki`. |
| `NUNCIO_LOGS_URL` | `""` | Log store base URL. For `openobserve`, include the org segment (e.g. `http://your-log-store:5080/api/default`); the client appends `/_search` and names the stream in the query. For `loki`, the server root (e.g. `http://your-log-store:3100`); the client appends `/loki/api/v1/query_range`. |
| `NUNCIO_LOGS_USER` / `NUNCIO_LOGS_TOKEN` | `""` | Credentials. A username triggers HTTP Basic auth (`user:token`); a token alone is sent as a bearer token; neither means no auth header. |
| `NUNCIO_LOGS_INDEX` | `""` | Stream/index name. Used as the OpenObserve stream to query; not used by the `loki` backend, which instead selects on a label (default label name `host`, matched against the alert's host with a fuzzy `=~".*host.*"` regex, further narrowed by a `\|= "<unit>"` line filter when a unit is known). Exact field/label names are inherently deployment-specific — both backends make a best-effort broad match rather than assuming one schema. |
| `NUNCIO_CONTAINERS` | `null` | Container-state backend: `null` or `docker`. |
| `NUNCIO_DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker/Podman Engine API endpoint: a unix socket (`unix:///path/to.sock`) or a TCP endpoint (`http://host:port`). Only ever calls `GET /containers/<name>/json` and `GET /containers/<name>/logs` — never a write, exec, attach, or lifecycle endpoint. **A raw Docker socket is root-equivalent to anything that can reach it** (it can create privileged containers, mount the host filesystem, etc.); a read-only socket-proxy that only forwards GET requests is strongly recommended over mounting the real socket directly, especially beyond a single-operator setup. |
| `NUNCIO_METRICS` | `null` | Metrics backend: `null`, `prometheus`, or `checkmk`. |
| `NUNCIO_METRICS_URL` | `""` | Prometheus server root (e.g. `http://your-metrics:9090`; the client calls `/api/v1/query`), or the CheckMK REST API root (e.g. `http://your-checkmk/your-site/check_mk/api/1.0`; the client calls `/objects/host/<name>` and, if a service is known, `/objects/service/<host;service>`). |
| `NUNCIO_METRICS_USER` / `NUNCIO_METRICS_TOKEN` | `""` | CheckMK automation user name and secret, sent as CheckMK's own `Authorization: Bearer <user> <secret>` scheme (not standard OAuth bearer). Not used by the `prometheus` backend. |

Notes on what each backend actually queries, since neither log stores nor metrics stores agree on a schema:

- **openobserve**: runs a `str_match_ignore_case` search over the configured stream for the alert's host and/or unit, within the requested time window, ordered newest-first and then re-ordered to the `LogClient` contract's newest-last.
- **loki**: builds a LogQL query `{host=~".*<host>.*"}` (optionally narrowed with `\|= "<unit>"`) against `query_range`, merges all matched streams by timestamp.
- **prometheus**: runs a small set of broad instant-vector queries (`up{instance=~".*<host>.*"}`, and `up{job=~".*<service>.*"}` when a service is known) and renders each returned series as a `metric{labels} = value` line. Exact metric names are exporter-specific, so this deliberately queries on the common `instance`/`job` labels rather than assuming a particular exporter's catalog.
- **checkmk**: fetches the live status of the host object and, if a service is known, the service object, and reports state/plugin-output/last-check/ack/downtime fields as summary lines.
- **docker**: inspects the named container (status, restart count, exit code, start time) and tails its recent stdout/stderr log lines (demultiplexed from Docker's framed log format).

## Redaction

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_REDACT_EXTRA` | `""` | Path to a JSON file of extra `{"type", "regex"}` rules, applied on top of the built-in secret catalog. |

## Settings screen (runtime reconfiguration)

`GET /settings` (HTML) and `GET /settings.json` (machine-readable) expose most of the table above for live viewing and editing, without a restart, through a second self-contained page alongside the dashboard.

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_ADMIN_TOKEN` | `""` | Shared secret required (as header `X-Admin-Token`, constant-time compared) to make ANY change via `POST /settings`. Unset means writes are permanently refused (403) and the screen is read-only — there is no way to enable writes except setting this. It is itself never editable through the API it gates. |

Reads (`GET /settings`, `GET /settings.json`) never require `NUNCIO_ADMIN_TOKEN` — they behave exactly like `GET /config.json`: always available, every secret masked. Only `POST /settings` (a write) is gated.

Not every setting is editable here. Three categories:

- **live** — most settings; a change here applies immediately to the running process (delivery routing/targets, `NUNCIO_MODE`, timeouts, retention, redaction rules, log level, ingest token, etc.).
- **restart** — `NUNCIO_CONCURRENCY`, `NUNCIO_QUEUE_MAX`, `NUNCIO_PORT`, `NUNCIO_BIND`. Editable and persisted here, but only take effect on the next process restart (the screen flags these with a "restart required" banner once changed).
- **env-only (never editable here, under any credential)** — the LLM/knowledge-plane endpoints and credentials (`NUNCIO_LLM_URL`/`_KEY`/`_HEADERS`, `NUNCIO_KNOWLEDGE_URL`/`_KEY`), `NUNCIO_ADMIN_TOKEN` itself, `NUNCIO_REDACT_EXTRA` (a file path — arbitrary file read if it were settable), `NUNCIO_EXTRA_SOURCES` (arbitrary module import), and a few bootstrap-only paths (`NUNCIO_DATA_DIR`, `NUNCIO_CONFIG`). These are shown read-only on `GET /settings.json` with the reason why, for transparency, but the settings API has no code path that can change them — this is a structural guarantee, not a permission check that could be bypassed.

**`NUNCIO_REDACT_EXTRA_RULES`** is the one settings-only key with no environment-variable equivalent: a live-editable JSON list of `{"type", "regex"}` extra redaction rules, additive on top of the built-in catalog and any `NUNCIO_REDACT_EXTRA` file rules (neither can be disabled or removed through it).

**Overrides file:** every change made through `POST /settings` is persisted to `${NUNCIO_DATA_DIR}/settings-overrides.json` (atomic write) and takes precedence over the environment for that key from then on — `effective value = overrides file > environment > built-in default`. Each key's `source` (`default`/`env`/`override`) is reported on `GET /settings.json` and shown as a badge in the UI, along with a `reset to default` action that drops the override. A capped audit log (key names and action only, never values) of the last 100 changes is kept in the same file and rendered on the screen.

## Misc

| Variable | Default | Description |
|---|---|---|
| `NUNCIO_LOG_LEVEL` | `info` | `debug`, `info`, `warning`, or `error`. |
| `NUNCIO_CONFIG` | `""` | Path to an optional config file for settings not covered by a flat env var (currently: `classification_table` for the knowledge plane). See [`config.example.json`](../config.example.json) for a ready-to-copy template. The file must be valid JSON — a `.yml`/`.yaml` extension is accepted, but the content is parsed as JSON (a documented, deliberate subset of YAML flow style), since Nuncio ships with no third-party dependencies and therefore no YAML parser. |
