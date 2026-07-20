"""OpenAI-compatible LLM client.

Talks to whatever OpenAI-compatible chat-completions endpoint the operator
configures (a local model server, a hosted gateway, a cloud provider, etc.)
via `NUNCIO_LLM_URL`/model — it has no built-in notion of which provider is on
the other end. Speaks only the configured model name to the endpoint; any
provider-specific routing or aliasing is the endpoint's concern, not this
client's. Any failure (non-200, connection error, empty/malformed body)
raises LLMError so the orchestrator can fall back to raw. Transport is
injectable for testing.

`enrich()` returns `(content, usage)`. `usage` is `{"prompt_tokens":
int|None, "completion_tokens": int|None}`, read from the OpenAI-compatible
response's top-level `usage` object when present; either key (or the whole
object) may be absent — not every OpenAI-compat server reports token counts,
so this degrades to `None` per-field rather than raising. The engine's
fake-LLM test doubles predate this and still return a bare string;
`Engine._call_bounded` accepts both shapes (see its docstring) so this is
additive, not a breaking contract change for callers that don't care about
usage.

`enrich()`'s `timeout` parameter, when given, overrides the client's
construction-time `timeout` as the urllib socket timeout for THIS call only
-- see `Engine._call_bounded`, which threads its per-attempt wall-clock
bound through here so a non-streaming call's socket timeout always matches
the budget the caller actually gave it (a fixed NUNCIO_LLM_TIMEOUT_S would
otherwise silently cap every attempt, including a deliberately larger
full-depth RCA bound, at the smaller default).
"""
import json
import urllib.error
import urllib.request


class LLMError(Exception):
    def __init__(self, message, retryable=False, status=None, body_excerpt=""):
        super().__init__(message)
        self.retryable = retryable
        # `status`/`body_excerpt` are additive (defaulted so every existing
        # raise site/test is untouched) -- populated by the status != 200
        # branch below, and by _urllib_transport's HTTPError handling, so a
        # 400 (e.g. "response_format not supported") is distinguishable from
        # a genuine connection/timeout failure. See the module docstring.
        self.status = status
        self.body_excerpt = body_excerpt


def _urllib_transport(url, headers, body, timeout):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # urlopen RAISES on a non-200 response rather than returning it --
        # without this, the status != 200 branch in LLMClient.enrich is dead
        # code for the real transport, and every non-200 response (incl. a
        # non-retryable 400) falls through to the blanket `except Exception`
        # below and gets treated as a fast, retryable transport failure.
        # Bound the body read (a hostile/broken endpoint could stream
        # forever) and never let a body-read failure mask the real status.
        try:
            excerpt = e.read()[:2048].decode(errors="ignore")
        except Exception:
            excerpt = ""
        return e.code, {"_error_body": excerpt}


def _chat_completions_url(base_url):
    """Compose the chat-completions endpoint from an operator-supplied base
    URL. Every doc/example ships `NUNCIO_LLM_URL`/`NUNCIO_KNOWLEDGE_URL` WITH
    the `/v1` segment already included (e.g. `http://host:port/v1`, the
    OpenAI-compatible convention), but a bare gateway root
    (`http://host:port`) is also accepted. `base_url` is already
    trailing-slash-stripped by `__init__`.

    Some hosted providers' OpenAI-compat base already ends in a non-`/v1`
    segment that is NOT itself the resource root -- e.g. Gemini's
    `https://generativelanguage.googleapis.com/v1beta/openai`, where a naive
    "always append /v1/chat/completions" rule produces
    `.../v1beta/openai/v1/chat/completions` -> 404 -> silent permanent
    raw-fallback. Rule, in order:
      1. base already ends `/chat/completions` -> used as-is (an operator who
         pasted the full resource URL must never get it mangled).
      2. base ends `/openai` or `/v1` -> append only `/chat/completions`
         (both shapes are already "one segment away" from the resource).
      3. otherwise -> append the full `/v1/chat/completions`.
    """
    if base_url.endswith("/chat/completions"):
        return base_url
    if base_url.endswith("/openai") or base_url.endswith("/v1"):
        return base_url + "/chat/completions"
    return base_url + "/v1/chat/completions"


class LLMClient:
    def __init__(self, base_url, api_key, model, timeout=20, transport=None, extra_headers=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._transport = transport or _urllib_transport
        # NUNCIO_LLM_HEADERS — lets an operator pass vendor-specific quirks
        # (e.g. a gateway-specific provider header) without a code change.
        self.extra_headers = dict(extra_headers) if extra_headers else {}
        # Structured-JSON capability cache (Phase A -- see nuncio.engine's
        # format ladder). None = untried; True/False = known from a prior
        # call's outcome. Lives on the CLIENT (not the engine) so it
        # persists across alerts and is reset to None whenever the client
        # itself is rebuilt (see nuncio.config._LLM_ROUTER_KEYS, which
        # includes NUNCIO_ENRICH_FORMAT precisely so a text->auto flip can
        # never inherit a stale False from a previous endpoint).
        self._json_object_supported = None

    def enrich(self, messages, max_tokens=400, response_format=None, timeout=None):
        body = {"model": self.model, "messages": messages, "max_tokens": max_tokens}
        if response_format is not None:
            # Only included when the caller actually wants it -- an operator
            # whose endpoint 400s on an unrecognized field must never see it
            # on a plain text-mode call (see nuncio.engine's capability
            # fallback ladder for the caller side of this).
            body["response_format"] = response_format
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            # Empty key = no auth header (e.g. a bare local Ollama with no
            # authentication configured).
            headers["Authorization"] = "Bearer " + self.api_key
        headers.update(self.extra_headers)
        # `timeout`, when given, overrides self.timeout for THIS call only --
        # lets a caller (nuncio.engine._call_bounded) make the socket timeout
        # track a per-attempt wall-clock bound (e.g. the full-depth RCA
        # call's larger bound) rather than always using the client's
        # construction-time NUNCIO_LLM_TIMEOUT_S, which would otherwise cap
        # every non-streaming call at that fixed value regardless of how
        # much time the caller actually budgeted for this attempt.
        eff_timeout = timeout if timeout is not None else self.timeout
        try:
            status, resp = self._transport(
                _chat_completions_url(self.base_url), headers, body, eff_timeout
            )
        except Exception as e:  # connection refused/reset, timeout — a fast, retryable failure
            raise LLMError(f"transport error: {e!r}", retryable=True)
        if status != 200:
            # 5xx/429 may be transient (retry); 4xx won't fix itself (no retry).
            # body_excerpt flows from _urllib_transport's HTTPError handling
            # (or a test double returning the same {"_error_body": ...}
            # shape) -- degrades to "" for any other/malformed resp shape.
            body_excerpt = resp.get("_error_body", "") if isinstance(resp, dict) else ""
            raise LLMError(
                f"http {status}", retryable=(status >= 500 or status == 429),
                status=status, body_excerpt=body_excerpt,
            )
        try:
            msg = resp["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"malformed response: {e!r}", retryable=False)
        content = (msg.get("content") or "").strip()
        if not content:
            # defensive: some models (gpt-oss) return the answer in `reasoning`
            content = (msg.get("reasoning") or "").strip()
        if not content:
            raise LLMError("empty response", retryable=False)
        usage_raw = resp.get("usage") if isinstance(resp.get("usage"), dict) else {}
        usage = {
            "prompt_tokens": usage_raw.get("prompt_tokens"),
            "completion_tokens": usage_raw.get("completion_tokens"),
        }
        return content, usage
