"""Grok (xAI) adapter against a fake HTTP transport: request shape, parsing, errors."""

import json
from pathlib import Path

import pytest

from app.ai.agent import AgentLimits, run_agent
from app.ai.provider import GrokProvider, ProviderError
from app.ai.tools import TOOLS
from tests.ai.ai_helpers import QS, draft, load, write_scan


class FakeXai:
    """Records requests and replies with scripted (status, payload) pairs."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, url, headers, body, timeout):
        self.requests.append({"url": url, "headers": headers, "body": json.loads(json.dumps(body))})
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def chat(content="", tool_calls=None, finish="stop", usage=(50, 10)):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
        finish = "tool_calls"
    return 200, {
        "choices": [{"message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]},
    }


def call(call_id, name, args):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def grok(fake, effort=None):
    return GrokProvider("xai-test-key", "grok-4.7", effort, timeout=30, max_tokens=4000, post=fake)


@pytest.fixture
def bundle(tmp_path: Path):
    return load(write_scan(tmp_path / "scan"))


def test_tool_loop_then_separate_structured_answer(bundle) -> None:
    fake = FakeXai(
        [
            chat(tool_calls=[call("c1", "get_advisory", {"advisory_id": "CVE-2022-24999"})]),
            chat(
                tool_calls=[
                    call("c2", "check_candidate_version", {"component_id": QS, "version": "6.2.4"})
                ]
            ),
            chat("I have enough evidence."),
            chat(
                json.dumps(
                    draft(
                        claims=[
                            {
                                "claim": "fixed",
                                "kind": "verified_fact",
                                "evidence_refs": ["ev-4", "ev-5"],
                            }
                        ]
                    )
                )
            ),
        ]
    )
    result = run_agent(bundle, bundle.finding("finding:vuln-qs"), grok(fake, "low"), AgentLimits())
    assert result.status == "recommendation_ready", result.error
    rec = result.recommendation
    assert [t.name for t in rec.tool_trace] == ["get_advisory", "check_candidate_version"]
    assert rec.recommended_remediation.fixed_version_verified is True
    assert rec.model_metadata.provider == "xai" and rec.model_metadata.model == "grok-4.7"
    assert rec.model_metadata.input_tokens == 200 and rec.model_metadata.output_tokens == 40

    first, second, third, final = (r["body"] for r in fake.requests)
    assert fake.requests[0]["url"] == "https://api.x.ai/v1/chat/completions"
    assert fake.requests[0]["headers"]["Authorization"] == "Bearer xai-test-key"
    assert first["model"] == "grok-4.7" and first["reasoning_effort"] == "low"
    assert first["messages"][0]["role"] == "system"
    assert first["tool_choice"] == "auto" and "response_format" not in first
    assert {t["function"]["name"] for t in first["tools"]} == set(TOOLS)
    assert first["tools"][0]["type"] == "function"
    # Tool results go back as role=tool messages tied to the call id, as quoted data.
    tool_msg = second["messages"][-1]
    assert tool_msg["role"] == "tool" and tool_msg["tool_call_id"] == "c1"
    assert "<tool_data>" in tool_msg["content"]
    assert second["messages"][-2]["tool_calls"][0]["id"] == "c1"
    # The final call carries the JSON schema and no tools.
    assert "tools" not in final
    assert final["response_format"]["type"] == "json_schema"
    assert final["response_format"]["json_schema"]["strict"] is True
    assert final["messages"][-1]["content"].startswith("Investigation finished.")
    plain = FakeXai([chat("{}")])
    grok(plain, effort=None).complete("s", [], None)
    assert "reasoning_effort" not in plain.requests[0]["body"]  # unset uses xAI's default


def test_bad_tool_arguments_are_rejected_not_executed(bundle) -> None:
    bad = {
        "id": "c1",
        "type": "function",
        "function": {"name": "get_component", "arguments": "{oops"},
    }
    fake = FakeXai([chat(tool_calls=[bad]), chat("done"), chat(json.dumps(draft()))])
    result = run_agent(bundle, bundle.finding("finding:vuln-qs"), grok(fake), AgentLimits())
    assert [(t.name, t.status) for t in result.recommendation.tool_trace] == [
        ("get_component", "rejected")
    ]
    assert fake.requests[1]["body"]["messages"][-1]["content"].startswith("ERROR:")


@pytest.mark.parametrize(
    ("reply", "kind"),
    [
        ((401, {"error": "bad key"}), "auth"),
        ((404, {}), "invalid"),
        ((429, {}), "rate_limit"),
        ((400, {"error": {"message": "schema rejected"}}), "invalid"),
        ((503, {}), "unavailable"),
        (TimeoutError(), "timeout"),
        ((200, {"choices": []}), "invalid"),
        ((200, {"choices": [{"message": {"refusal": "no"}, "finish_reason": "stop"}]}), "refusal"),
    ],
)
def test_errors_are_mapped_without_leaking_the_key(reply, kind) -> None:
    provider = grok(FakeXai([reply]))
    with pytest.raises(ProviderError) as raised:
        provider.complete("system", [], None)
    assert raised.value.kind == kind
    assert "xai-test-key" not in str(raised.value)


def test_truncated_answer_is_reported(bundle) -> None:
    fake = FakeXai([chat("partial", finish="length")])
    provider = grok(fake)
    turn = provider.complete("s", [], None)
    assert turn.stop_reason == "max_tokens"
    fake = FakeXai([chat("thinking"), chat("{", finish="length")])
    result = run_agent(bundle, bundle.finding("finding:vuln-qs"), grok(fake), AgentLimits())
    assert result.status == "failed" and "cut off" in result.error


# ---------------------------------------------------------------------------
# Groq
# ---------------------------------------------------------------------------


def groq(fake, sleep=None):
    from app.ai.provider import GroqProvider

    return GroqProvider(
        "gsk_test_key",
        "openai/gpt-oss-120b",
        None,
        timeout=30,
        max_tokens=4000,
        post=fake,
        sleep=sleep or (lambda _s: None),
    )


def _walk(schema):
    """Yield every schema node (property-name maps are not nodes themselves)."""
    if isinstance(schema, dict):
        yield schema
        for key, value in schema.items():
            if key in ("properties", "$defs"):
                for sub in value.values():
                    yield from _walk(sub)
            else:
                yield from _walk(value)
    elif isinstance(schema, list):
        for value in schema:
            yield from _walk(value)


def test_groq_request_shape_and_strict_schema(bundle) -> None:
    fake = FakeXai(
        [
            chat(tool_calls=[call("c1", "get_advisory", {"advisory_id": "CVE-2022-24999"})]),
            chat("Enough evidence."),
            chat(json.dumps(draft(claims=[]))),
        ]
    )
    result = run_agent(
        bundle, bundle.finding("finding:vuln-qs"), groq(fake), AgentLimits(max_result_chars=3000)
    )
    assert result.status == "recommendation_ready", result.error
    first, _, final = (r["body"] for r in fake.requests)
    assert fake.requests[0]["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert fake.requests[0]["headers"]["Authorization"] == "Bearer gsk_test_key"
    assert first["model"] == "openai/gpt-oss-120b"
    assert first["max_completion_tokens"] == 4000 and "max_tokens" not in first
    assert "response_format" not in first and "tools" not in final
    schema = final["response_format"]["json_schema"]["schema"]
    for node in _walk(schema):
        assert not {"maxLength", "maxItems", "pattern", "title"} & set(node)
        if node.get("type") == "object" and "properties" in node:
            assert node["required"] == list(node["properties"])
            assert node["additionalProperties"] is False
    assert result.recommendation.model_metadata.provider == "groq"


def test_groq_retries_short_rate_limit_waits_only() -> None:
    waits = []
    fake = FakeXai([(429, {}, {"retry-after": "2"}), chat("{}")])
    turn = groq(fake, sleep=waits.append).complete("s", [], None)
    assert waits == [2.0] and turn.text == "{}"

    fake = FakeXai([(429, {}, {"retry-after": "120"})])  # too long to wait inside an analysis
    with pytest.raises(ProviderError) as raised:
        groq(fake, sleep=waits.append).complete("s", [], None)
    assert raised.value.kind == "rate_limit" and waits == [2.0]

    fake = FakeXai([(429, {}, {"retry-after": "1"})] * 7)
    with pytest.raises(ProviderError):
        groq(fake).complete("s", [], None)
    assert len(fake.requests) == 7  # one try plus six bounded retries

    waits.clear()
    fake = FakeXai([(429, {}, {"x-ratelimit-reset-tokens": "1m2.5s"})])
    with pytest.raises(ProviderError):  # 63 s exceeds the 60 s cap: reported, not waited
        groq(fake, sleep=waits.append).complete("s", [], None)
    assert waits == []
    fake = FakeXai([(429, {}, {"x-ratelimit-reset-tokens": "5.25s"}), chat("{}")])
    groq(fake, sleep=waits.append).complete("s", [], None)
    assert waits == [5.75]


def test_groq_is_the_default_provider(monkeypatch) -> None:
    from pydantic import SecretStr

    from app.ai import service
    from app.ai.provider import GroqProvider
    from app.config import settings

    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "ai_provider", "groq")
    monkeypatch.setattr(settings, "ai_model", None)
    monkeypatch.setattr(settings, "groq_api_key", SecretStr("gsk_test"))
    provider = service.build_provider(settings)
    assert isinstance(provider, GroqProvider) and provider.model == "openai/gpt-oss-120b"


def test_groq_unknown_tool_call_ends_the_tool_phase(bundle) -> None:
    unknown = (
        400,
        {
            "error": {
                "message": "Tool call validation failed: attempted to call tool 'json' "
                "which was not in request.tools",
                "type": "invalid_request_error",
                "code": "tool_use_failed",
            }
        },
    )
    fake = FakeXai(
        [
            chat(tool_calls=[call("c1", "get_advisory", {"advisory_id": "CVE-2022-24999"})]),
            unknown,
            chat(json.dumps(draft(claims=[]))),
        ]
    )
    result = run_agent(bundle, bundle.finding("finding:vuln-qs"), groq(fake), AgentLimits())
    assert result.status == "recommendation_ready", result.error
    assert [t.name for t in result.recommendation.tool_trace] == [
        "get_advisory"
    ]  # nothing ran for "json"
    final = fake.requests[-1]["body"]
    assert "tools" not in final and final["response_format"]["type"] == "json_schema"
    # The tool phase told the model to finish in plain text, not JSON.
    assert "plain-text sentence" in fake.requests[0]["body"]["messages"][0]["content"]
    # Other 400s still fail the analysis, and xAI does not get this leniency.
    with pytest.raises(ProviderError):
        groq(FakeXai([(400, {"error": {"message": "bad schema"}})])).complete("s", [], None)
    with pytest.raises(ProviderError):
        grok(FakeXai([unknown])).complete("s", [], None)
