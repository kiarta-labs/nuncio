"""OpenAI-compatible LLM client. Transport is injected so every failure
mode (non-200, connection error, empty/malformed body) is testable offline.

`enrich()` returns `(content, usage)` -- token-usage
transparency for the dashboard."""
import pytest
from nuncio.llm import LLMClient, LLMError


def ok_response(content="SUMMARY: ok\nSEVERITY: low", reasoning=None, usage=None):
    msg = {"role": "assistant", "content": content}
    if reasoning is not None:
        msg["reasoning"] = reasoning
    body = {"choices": [{"message": msg}]}
    body["usage"] = usage if usage is not None else {"prompt_tokens": 120, "completion_tokens": 40}
    return 200, body


def client_with(transport):
    return LLMClient("http://gw:4000", "sk-key", "local-model", timeout=20, transport=transport)


def test_enrich_returns_content_and_usage():
    c = client_with(lambda url, h, b, t: ok_response("SUMMARY: db down\nSEVERITY: urgent"))
    content, usage = c.enrich([{"role": "user", "content": "x"}])
    assert content == "SUMMARY: db down\nSEVERITY: urgent"
    assert usage == {"prompt_tokens": 120, "completion_tokens": 40}


def test_enrich_uses_alias_and_timeout_in_request():
    seen = {}

    def transport(url, headers, body, timeout):
        seen.update(url=url, body=body, timeout=timeout, headers=headers)
        return ok_response()

    client_with(transport).enrich([{"role": "user", "content": "x"}])
    assert seen["body"]["model"] == "local-model"      # the ALIAS, never a provider name
    assert seen["timeout"] == 20
    assert seen["headers"]["Authorization"] == "Bearer sk-key"


# --- base-URL /v1 handling: NUNCIO_LLM_URL is documented WITH a /v1 suffix
# (e.g. http://host:port/v1), so the client must never double it. ---

def test_enrich_url_without_v1_suffix_gets_v1_appended():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["url"] = url
        return ok_response()

    LLMClient("http://gw:4000", "", "m", transport=transport).enrich([{"role": "user", "content": "x"}])
    assert seen["url"] == "http://gw:4000/v1/chat/completions"


def test_enrich_url_already_ending_in_v1_is_not_doubled():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["url"] = url
        return ok_response()

    LLMClient("http://gw:4000/v1", "", "m", transport=transport).enrich([{"role": "user", "content": "x"}])
    assert seen["url"] == "http://gw:4000/v1/chat/completions"


def test_enrich_url_v1_with_trailing_slash_is_not_doubled():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["url"] = url
        return ok_response()

    LLMClient("http://gw:4000/v1/", "", "m", transport=transport).enrich([{"role": "user", "content": "x"}])
    assert seen["url"] == "http://gw:4000/v1/chat/completions"


# --- Gemini-shaped base (.../v1beta/openai): edge case --
# the naive "append /v1/chat/completions unless ends in /v1" rule 404s here.

def test_enrich_url_ending_in_openai_gets_chat_completions_appended_not_v1():
    from nuncio.llm import _chat_completions_url
    assert (_chat_completions_url("https://generativelanguage.googleapis.com/v1beta/openai")
            == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")


def test_chat_completions_url_bare_root():
    from nuncio.llm import _chat_completions_url
    assert _chat_completions_url("http://gw:4000") == "http://gw:4000/v1/chat/completions"


def test_chat_completions_url_v1_suffix():
    from nuncio.llm import _chat_completions_url
    assert _chat_completions_url("http://gw:4000/v1") == "http://gw:4000/v1/chat/completions"


def test_chat_completions_url_already_full_is_unchanged():
    from nuncio.llm import _chat_completions_url
    full = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert _chat_completions_url(full) == full


def test_enrich_falls_back_to_reasoning_when_content_empty():
    # defensive: some models (gpt-oss) put the answer in `reasoning`
    c = client_with(lambda *a: ok_response(content="", reasoning="SUMMARY: x\nSEVERITY: y"))
    content, _usage = c.enrich([{"role": "user", "content": "x"}])
    assert content == "SUMMARY: x\nSEVERITY: y"


def test_enrich_raises_on_non_200():
    c = client_with(lambda *a: (500, {"error": "boom"}))
    with pytest.raises(LLMError):
        c.enrich([{"role": "user", "content": "x"}])


def test_enrich_raises_on_transport_exception():
    def transport(*a):
        raise ConnectionError("refused")
    with pytest.raises(LLMError):
        client_with(transport).enrich([{"role": "user", "content": "x"}])


def test_enrich_raises_on_empty_response():
    c = client_with(lambda *a: ok_response(content="", reasoning=""))
    with pytest.raises(LLMError):
        c.enrich([{"role": "user", "content": "x"}])


def test_enrich_raises_on_malformed_body():
    c = client_with(lambda *a: (200, {"unexpected": "shape"}))
    with pytest.raises(LLMError):
        c.enrich([{"role": "user", "content": "x"}])


# --- retry classification: retry fast failures, never 4xx ---

def test_5xx_error_is_retryable():
    c = client_with(lambda *a: (503, {"error": "unavailable"}))
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.retryable is True


def test_4xx_error_is_not_retryable():
    c = client_with(lambda *a: (400, {"error": "bad request"}))
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.retryable is False


def test_transport_exception_is_retryable():
    def transport(*a):
        raise ConnectionError("refused")
    with pytest.raises(LLMError) as ei:
        client_with(transport).enrich([{"role": "user", "content": "x"}])
    assert ei.value.retryable is True


def test_empty_response_is_not_retryable():
    c = client_with(lambda *a: ok_response(content="", reasoning=""))
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.retryable is False


# --- token-usage plumbing ---

def test_usage_missing_entirely_degrades_to_none_fields():
    # Not every OpenAI-compat server reports usage -- must not raise, must
    # degrade to None per-field so the dashboard can show a null pill.
    def transport(*a):
        return 200, {"choices": [{"message": {"role": "assistant", "content": "SUMMARY: x"}}]}
    c = client_with(transport)
    content, usage = c.enrich([{"role": "user", "content": "x"}])
    assert content == "SUMMARY: x"
    assert usage == {"prompt_tokens": None, "completion_tokens": None}


def test_usage_partial_fields_present():
    c = client_with(lambda *a: ok_response(usage={"prompt_tokens": 55}))
    _content, usage = c.enrich([{"role": "user", "content": "x"}])
    assert usage["prompt_tokens"] == 55
    assert usage["completion_tokens"] is None


def test_usage_non_dict_shape_degrades_to_none_fields():
    # A malformed/unexpected `usage` value must not raise (usage is a
    # transparency nicety, never allowed to break enrichment).
    c = client_with(lambda *a: ok_response(usage="not a dict"))
    _content, usage = c.enrich([{"role": "user", "content": "x"}])
    assert usage == {"prompt_tokens": None, "completion_tokens": None}


# --- Section 0: transport rework -- HTTPError must carry status/body so a
# real non-200 response actually reaches LLMClient.enrich's status branch
# instead of being swallowed by the transport's blanket except-Exception. ---

import urllib.error


def _http_error(code, body=b""):
    return urllib.error.HTTPError(
        url="http://gw:4000/v1/chat/completions", code=code, msg="err",
        hdrs=None, fp=__import__("io").BytesIO(body),
    )


def test_urllib_transport_returns_status_and_body_on_http_error():
    from nuncio.llm import _urllib_transport

    def fake_urlopen(req, timeout):
        raise _http_error(400, b'{"error": "bad response_format"}')

    import nuncio.llm as llm_mod
    orig = llm_mod.urllib.request.urlopen
    llm_mod.urllib.request.urlopen = fake_urlopen
    try:
        status, parsed = _urllib_transport("http://x", {}, {}, 5)
    finally:
        llm_mod.urllib.request.urlopen = orig
    assert status == 400
    assert parsed["_error_body"] == '{"error": "bad response_format"}'


def test_enrich_raises_llmerror_with_status_and_body_excerpt_on_400():
    def transport(*a):
        return 400, {"_error_body": '{"error": "response_format not supported"}'}
    c = client_with(transport)
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.status == 400
    assert ei.value.retryable is False
    assert "response_format" in ei.value.body_excerpt


def test_enrich_503_still_retryable_with_status_set():
    def transport(*a):
        return 503, {"_error_body": "unavailable"}
    c = client_with(transport)
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.status == 503
    assert ei.value.retryable is True


def test_enrich_429_still_retryable_with_status_set():
    def transport(*a):
        return 429, {"_error_body": ""}
    c = client_with(transport)
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.status == 429
    assert ei.value.retryable is True


def test_llmerror_defaults_status_none_body_excerpt_empty():
    e = LLMError("boom")
    assert e.status is None
    assert e.body_excerpt == ""
    assert e.retryable is False


def test_enrich_includes_response_format_in_body_when_passed():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["body"] = body
        return ok_response()

    client_with(transport).enrich(
        [{"role": "user", "content": "x"}], response_format={"type": "json_object"}
    )
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_enrich_omits_response_format_when_not_passed():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["body"] = body
        return ok_response()

    client_with(transport).enrich([{"role": "user", "content": "x"}])
    assert "response_format" not in seen["body"]


# --- per-call timeout override: the socket timeout must be able to track a
# caller-supplied per-attempt bound (e.g. the engine's deep-RCA bound),
# rather than always being pinned to the client's construction-time
# `timeout`. ---

def test_enrich_uses_explicit_timeout_override_when_given():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["timeout"] = timeout
        return ok_response()

    client_with(transport).enrich([{"role": "user", "content": "x"}], timeout=30)
    assert seen["timeout"] == 30


def test_enrich_falls_back_to_client_timeout_when_override_not_given():
    seen = {}

    def transport(url, headers, body, timeout):
        seen["timeout"] = timeout
        return ok_response()

    client_with(transport).enrich([{"role": "user", "content": "x"}])
    assert seen["timeout"] == 20  # client_with(...) constructs with timeout=20


def test_non_dict_error_response_degrades_body_excerpt_to_empty():
    # status != 200 but the (fake) transport handed back something that
    # isn't a dict -- body_excerpt must degrade to "" rather than raise.
    c = client_with(lambda *a: (400, "not a dict"))
    with pytest.raises(LLMError) as ei:
        c.enrich([{"role": "user", "content": "x"}])
    assert ei.value.body_excerpt == ""
