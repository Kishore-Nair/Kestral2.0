"""LLM provider adapters. Business logic talks to ``Provider``, never to a vendor API.

- ``GroqProvider`` (default) and ``GrokProvider``: OpenAI-compatible Chat Completions
  APIs at Groq and xAI. Both document
  tool calling and JSON-schema structured outputs, but not both in one request with client
  tools, so the agent runs the tool loop first and then asks for the final answer in a
  separate call that enforces the schema (``structured_with_tools = False``).
- ``AnthropicProvider`` (optional): Claude Messages API with tools and a JSON-schema
  output format in the same request.

No automatic model fallback is configured: a refusal or error is reported, never silently
answered by a different model. API keys are never logged or included in error messages.
"""

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.schemas.ai import AiDraft

XAI_BASE_URL = "https://api.x.ai/v1"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class ProviderError(RuntimeError):
    """A provider call failed. ``kind`` is safe to show; the message never holds secrets."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        # not_configured | auth | rate_limit | timeout | unavailable | refusal | invalid
        self.kind = kind


@dataclass
class ToolRequest:
    id: str
    name: str
    input: Any


@dataclass
class ProviderTurn:
    stop_reason: str
    tool_requests: list[ToolRequest]
    text: str
    assistant_content: Any  # provider-specific; turned back into a message by the provider
    input_tokens: int = 0
    output_tokens: int = 0


class Provider(Protocol):
    name: str
    model: str
    effort: str | None
    structured_with_tools: bool

    def tool_specs(self, specs: list[dict]) -> list[dict]: ...

    def user_message(self, text: str) -> list[dict]: ...

    def assistant_message(self, turn: ProviderTurn) -> list[dict]: ...

    def tool_results(self, results: list[tuple[str, str, bool]]) -> list[dict]: ...

    def complete(
        self, system: str, messages: list[dict], tools: list[dict] | None
    ) -> ProviderTurn: ...


# ---------------------------------------------------------------------------
# Anthropic-style message shapes (also used by the test FakeProvider)
# ---------------------------------------------------------------------------


class _AnthropicFormat:
    structured_with_tools = True

    def tool_specs(self, specs: list[dict]) -> list[dict]:
        return [{**spec, "strict": True} for spec in specs]

    def user_message(self, text: str) -> list[dict]:
        return [{"role": "user", "content": text}]

    def assistant_message(self, turn: ProviderTurn) -> list[dict]:
        return [{"role": "assistant", "content": turn.assistant_content}]

    def tool_results(self, results: list[tuple[str, str, bool]]) -> list[dict]:
        blocks = []
        for tool_id, content, is_error in results:
            block: dict[str, Any] = {
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": content,
            }
            if is_error:
                block["is_error"] = True
            blocks.append(block)
        return [{"role": "user", "content": blocks}]


def anthropic_output_schema() -> dict:
    try:
        from anthropic.lib._parse._transform import transform_schema
    except ImportError:  # pragma: no cover - depends on SDK version
        return AiDraft.model_json_schema()
    return transform_schema(AiDraft)


class AnthropicProvider(_AnthropicFormat):
    name = "anthropic"

    def __init__(
        self, api_key: str, model: str, effort: str | None, timeout: int, max_tokens: int
    ) -> None:
        import anthropic

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key, timeout=float(timeout), max_retries=1)
        self.model = model
        self.effort = effort
        self._max_tokens = max_tokens
        self._schema = anthropic_output_schema()

    def complete(self, system: str, messages: list[dict], tools: list[dict] | None) -> ProviderTurn:
        a = self._anthropic
        output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": self._schema}}
        if self.effort:
            output_config["effort"] = self.effort
        extra: dict[str, Any] = {"tools": tools} if tools else {}
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=system,
                messages=messages,
                output_config=output_config,
                **extra,
            )
        except a.AuthenticationError:
            raise ProviderError("auth", "The AI provider rejected the configured API key") from None
        except a.PermissionDeniedError:
            raise ProviderError("auth", "The API key lacks permission for this model") from None
        except a.NotFoundError:
            raise ProviderError("invalid", f"Model {self.model!r} is not available") from None
        except a.RateLimitError:
            raise ProviderError("rate_limit", "AI provider rate limit or quota reached") from None
        except a.BadRequestError as exc:
            raise ProviderError("invalid", f"AI request rejected: {exc.message[:200]}") from None
        except a.APITimeoutError:
            raise ProviderError("timeout", "AI provider timed out") from None
        except a.APIStatusError as exc:
            raise ProviderError("unavailable", f"AI provider error ({exc.status_code})") from None
        except a.APIConnectionError:
            raise ProviderError("unavailable", "Could not reach the AI provider") from None
        if response.stop_reason == "refusal":
            raise ProviderError("refusal", "The model declined this request")
        tool_requests = [
            ToolRequest(b.id, b.name, b.input) for b in response.content if b.type == "tool_use"
        ]
        text = "".join(b.text for b in response.content if b.type == "text")
        return ProviderTurn(
            stop_reason=response.stop_reason or "",
            tool_requests=tool_requests,
            text=text,
            assistant_content=response.content,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )


# ---------------------------------------------------------------------------
# xAI Grok (OpenAI-compatible Chat Completions)
# ---------------------------------------------------------------------------

PostJson = Callable[[str, dict[str, str], dict, float], tuple]  # (status, payload[, headers])


def _post_json(url: str, headers: dict[str, str], body: dict, timeout: float) -> tuple:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed host
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(64 * 1024)
        status = exc.code
        response_headers = dict(exc.headers.items()) if exc.headers else {}
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError("invalid", "AI provider response too large")
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        payload = {}
    return status, payload, {k.lower(): v for k, v in response_headers.items()}


def _unknown_tool_call(payload: Any) -> bool:
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return False
    message = str(error.get("message") or "")
    return error.get("code") == "tool_use_failed" or "was not in request.tools" in message


def _error_detail(payload: Any) -> str:
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or "")[:200]
        if isinstance(error, str):
            return error[:200]
    return ""


_STRICT_KEYWORDS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "anyOf",
    "$defs",
    "$ref",
    "description",
}


def strict_subset(schema: Any) -> Any:
    """Keep only widely supported strict-schema keywords; every object lists all fields as
    required and forbids extras. Dropped limits (lengths, patterns, sizes) are still
    enforced locally when the answer is validated with Pydantic."""
    if isinstance(schema, list):
        return [strict_subset(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {}
    for key, value in schema.items():
        if key not in _STRICT_KEYWORDS:
            continue
        if key in ("properties", "$defs"):
            out[key] = {name: strict_subset(sub) for name, sub in value.items()}
        else:
            out[key] = strict_subset(value)
    if out.get("type") == "object" and "properties" in out:
        out["required"] = list(out["properties"])
        out["additionalProperties"] = False
    return out


class OpenAICompatibleProvider:
    """Chat Completions adapter shared by xAI and Groq (tool loop, then a schema-only call)."""

    name = "openai-compatible"
    base_url = ""
    structured_with_tools = False
    max_rate_limit_retries = 0
    max_retry_after_seconds = 0.0
    max_tokens_field = "max_tokens"
    finish_on_unknown_tool = False

    def __init__(
        self,
        api_key: str,
        model: str,
        effort: str | None,
        timeout: int,
        max_tokens: int,
        *,
        base_url: str | None = None,
        post: PostJson | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        import time

        self._api_key = api_key
        self.model = model
        self.effort = effort
        self._timeout = float(timeout)
        self._max_tokens = max_tokens
        self._url = (base_url or self.base_url).rstrip("/") + "/chat/completions"
        self._post = post or _post_json
        self._sleep = sleep or time.sleep
        self._schema = self.answer_schema()

    def answer_schema(self) -> dict:
        return AiDraft.model_json_schema()

    # message shapes -----------------------------------------------------------------

    def tool_specs(self, specs: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": spec["name"],
                    "description": spec["description"],
                    "parameters": spec["input_schema"],
                },
            }
            for spec in specs
        ]

    def user_message(self, text: str) -> list[dict]:
        return [{"role": "user", "content": text}]

    def assistant_message(self, turn: ProviderTurn) -> list[dict]:
        return [turn.assistant_content]

    def tool_results(self, results: list[tuple[str, str, bool]]) -> list[dict]:
        return [
            {
                "role": "tool",
                "tool_call_id": tool_id,
                "content": f"ERROR: {content}" if is_error else content,
            }
            for tool_id, content, is_error in results
        ]

    # request ------------------------------------------------------------------------

    def complete(self, system: str, messages: list[dict], tools: list[dict] | None) -> ProviderTurn:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            self.max_tokens_field: self._max_tokens,
        }
        if self.effort:
            body["reasoning_effort"] = self.effort
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        else:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "kestral_ai_draft", "schema": self._schema, "strict": True},
            }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": "kestral-ai-analyst",
        }
        attempt = 0
        while True:
            try:
                reply = self._post(self._url, headers, body, self._timeout)
            except TimeoutError:
                raise ProviderError("timeout", "AI provider timed out") from None
            except urllib.error.URLError:
                raise ProviderError("unavailable", "Could not reach the AI provider") from None
            status, payload = reply[0], reply[1]
            response_headers = reply[2] if len(reply) > 2 else {}
            wait = self._retry_after(response_headers)
            if status == 429 and attempt < self.max_rate_limit_retries and wait is not None:
                attempt += 1
                self._sleep(wait)
                continue
            break
        if status in (401, 403):
            raise ProviderError("auth", "The AI provider rejected the configured API key")
        if status == 404:
            raise ProviderError("invalid", f"Model {self.model!r} is not available")
        if status == 429:
            raise ProviderError("rate_limit", "AI provider rate limit or quota reached")
        if status == 400 and self.finish_on_unknown_tool and _unknown_tool_call(payload):
            # gpt-oss on Groq sometimes emits a call to a tool that does not exist (for
            # example "json") when it is ready to answer. Nothing is executed; treat it as
            # the end of the investigation so the schema-only final call follows.
            return ProviderTurn(
                "unknown_tool_call", [], "", {"role": "assistant", "content": "Ready to answer."}
            )
        if status == 400 or status == 422:
            raise ProviderError("invalid", f"AI request rejected: {_error_detail(payload)}")
        if status >= 500 or status != 200:
            raise ProviderError("unavailable", f"AI provider error ({status})")
        return self._turn(payload)

    def _retry_after(self, headers: dict) -> float | None:
        """Seconds to wait from ``retry-after`` or ``x-ratelimit-reset-tokens`` ("5.2s", "1m3s")."""
        wait = None
        try:
            wait = float(headers.get("retry-after", ""))
        except ValueError:
            reset = str(headers.get("x-ratelimit-reset-tokens", ""))
            matched = re.fullmatch(r"(?:(\d+)m)?(\d+(?:\.\d+)?)s", reset)
            if matched:
                wait = int(matched.group(1) or 0) * 60 + float(matched.group(2)) + 0.5
        if wait is None:
            return None
        return wait if 0 <= wait <= self.max_retry_after_seconds else None

    def _turn(self, payload: Any) -> ProviderTurn:
        try:
            choice = payload["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise ProviderError("invalid", "AI provider returned an unexpected response") from None
        if message.get("refusal"):
            raise ProviderError("refusal", "The model declined this request")
        tool_requests = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except json.JSONDecodeError:
                arguments = None  # rejected by the agent as invalid arguments
            tool_requests.append(
                ToolRequest(call.get("id", ""), function.get("name", ""), arguments)
            )
        usage = payload.get("usage") or {}
        finish = choice.get("finish_reason") or ""
        assistant: dict[str, Any] = {"role": "assistant", "content": message.get("content") or ""}
        if message.get("tool_calls"):
            assistant["tool_calls"] = message["tool_calls"]
        return ProviderTurn(
            stop_reason="max_tokens" if finish == "length" else finish,
            tool_requests=tool_requests,
            text=message.get("content") or "",
            assistant_content=assistant,
            input_tokens=int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
            output_tokens=int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
        )


class GrokProvider(OpenAICompatibleProvider):
    """xAI Grok (https://api.x.ai/v1)."""

    name = "xai"
    base_url = XAI_BASE_URL


class GroqProvider(OpenAICompatibleProvider):
    """Groq (https://api.groq.com/openai/v1). Groq documents that structured outputs cannot be
    combined with tool use, requires strict schemas to list every field as required, and has
    small free-tier token-per-minute limits, so short rate-limit waits are retried."""

    name = "groq"
    base_url = GROQ_BASE_URL
    max_rate_limit_retries = 6
    max_retry_after_seconds = 60.0
    max_tokens_field = "max_completion_tokens"
    finish_on_unknown_tool = True

    def answer_schema(self) -> dict:
        return strict_subset(AiDraft.model_json_schema())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@dataclass
class FakeProvider(_AnthropicFormat):
    """Scripted provider for tests: each call pops the next ProviderTurn (or raises it)."""

    turns: list[Any]
    name: str = "fake"
    model: str = "fake-model"
    effort: str | None = None
    calls: list[dict] = field(default_factory=list)

    def complete(self, system: str, messages: list[dict], tools: list[dict] | None) -> ProviderTurn:
        self.calls.append({"system": system, "messages": list(messages), "tools": tools})
        if not self.turns:
            raise ProviderError("invalid", "Fake provider has no more turns")
        turn = self.turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn
