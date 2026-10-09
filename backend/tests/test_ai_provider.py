from unittest.mock import Mock, patch

import httpx
import pytest
from app.ai import config
from app.ai.factory import get_provider
from app.ai.ollama_provider import OllamaProvider
from app.ai.provider import AIProviderError, AIProviderTimeout, AIProviderUnavailable


@pytest.fixture
def provider() -> OllamaProvider:
    return OllamaProvider("test-model")


def response(status_code: int = 200, payload: dict | None = None) -> Mock:
    result = Mock()
    result.status_code = status_code
    result.text = "server failure"
    result.json.return_value = payload or {"response": "model output"}
    return result


def test_generate_returns_raw_model_output(provider: OllamaProvider):
    with patch("app.ai.ollama_provider.httpx.post", return_value=response()) as post:
        assert provider.generate("investigate this") == "model output"

    post.assert_called_once_with(
        "http://localhost:11434/api/generate",
        json={
            "model": "test-model",
            "prompt": "investigate this",
            "stream": False,
            "think": False,
        },
        timeout=60.0,
    )


def test_generate_passes_system_prompt(provider: OllamaProvider):
    with patch("app.ai.ollama_provider.httpx.post", return_value=response()) as post:
        provider.generate("prompt", system="system guidance")

    assert post.call_args.kwargs["json"]["system"] == "system guidance"


def test_connection_refused_raises_unavailable(provider: OllamaProvider):
    with (
        patch(
            "app.ai.ollama_provider.httpx.post",
            side_effect=httpx.ConnectError("connection refused"),
        ),
        pytest.raises(AIProviderUnavailable),
    ):
        provider.generate("prompt")


def test_read_timeout_raises_timeout(provider: OllamaProvider):
    with (
        patch(
            "app.ai.ollama_provider.httpx.post",
            side_effect=httpx.ReadTimeout("timed out"),
        ),
        pytest.raises(AIProviderTimeout),
    ):
        provider.generate("prompt")


def test_http_error_raises_provider_error(provider: OllamaProvider):
    with (
        patch("app.ai.ollama_provider.httpx.post", return_value=response(500)),
        pytest.raises(AIProviderError, match="HTTP 500"),
    ):
        provider.generate("prompt")


def test_factory_returns_none_when_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "AI_ENABLED", False)
    assert get_provider() is None


def test_factory_returns_ollama_when_enabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "AI_ENABLED", True)
    monkeypatch.setattr(config, "AI_PROVIDER", "ollama")
    monkeypatch.setattr(config, "AI_MODEL", "configured-model")
    provider = get_provider()
    assert isinstance(provider, OllamaProvider)
    assert provider.model == "configured-model"


def test_factory_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "AI_ENABLED", True)
    monkeypatch.setattr(config, "AI_PROVIDER", "unknown")
    with pytest.raises(ValueError, match="Unknown AI provider: unknown"):
        get_provider()
