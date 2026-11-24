import pytest

from app.ai import provider


@pytest.fixture(autouse=True)
def no_live_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """The test suite must never call a paid provider."""

    def refuse(*_args, **_kwargs):
        raise AssertionError("A test tried to construct the live Anthropic provider")

    monkeypatch.setattr(provider.AnthropicProvider, "__init__", refuse)
    monkeypatch.setattr(provider, "_post_json", refuse)
