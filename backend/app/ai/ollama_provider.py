import logging
import time

import httpx

from app.ai.provider import (
    AIProvider,
    AIProviderError,
    AIProviderTimeout,
    AIProviderUnavailable,
)

logger = logging.getLogger(__name__)


class OllamaProvider(AIProvider):
    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        default_timeout: float = 60.0,
        temperature: float = 0.1,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._default_timeout = default_timeout
        self._temperature = temperature

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        timeout: float | None = None,
        response_format: dict | None = None,
    ) -> str:
        request_timeout = self._default_timeout if timeout is None else timeout
        payload: dict[str, object] = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {"temperature": self._temperature},
        }
        if system is not None:
            payload["system"] = system
        if response_format is not None:
            payload["format"] = response_format

        started_at = time.monotonic()
        try:
            response = httpx.post(
                f"{self._base_url}/api/generate",
                json=payload,
                timeout=request_timeout,
            )
        except httpx.ConnectTimeout as exc:
            self._log_outcome(started_at, "unavailable")
            raise AIProviderUnavailable("Ollama server is unavailable") from exc
        except httpx.ConnectError as exc:
            self._log_outcome(started_at, "unavailable")
            raise AIProviderUnavailable("Ollama server is unavailable") from exc
        except httpx.ReadTimeout as exc:
            self._log_outcome(started_at, "timeout")
            raise AIProviderTimeout("Ollama request timed out") from exc
        except httpx.RequestError as exc:
            self._log_outcome(started_at, "error")
            raise AIProviderError(f"Ollama request failed: {exc}") from exc

        if response.status_code != 200:
            self._log_outcome(started_at, "error")
            excerpt = response.text[:200]
            raise AIProviderError(f"Ollama returned HTTP {response.status_code}: {excerpt}")

        try:
            output = response.json()["response"]
            import os
            if os.getenv("TUCO_AI_DEBUG") == "1":
                import json as _json
                from pathlib import Path
                debug_dir = Path("/tmp/tuco-ai-debug")
                debug_dir.mkdir(exist_ok=True)
                (debug_dir / "last-request.json").write_text(
                    _json.dumps(payload, indent=2)
                )
                (debug_dir / "last-response.json").write_text(
                    _json.dumps(response.json(), indent=2)
                )
                (debug_dir / "last-raw-output.txt").write_text(output)
        except (ValueError, KeyError, TypeError) as exc:
            self._log_outcome(started_at, "error")
            raise AIProviderError("Ollama response did not contain raw output") from exc

        if not isinstance(output, str):
            self._log_outcome(started_at, "error")
            raise AIProviderError("Ollama response output was not a string")

        self._log_outcome(started_at, "success")
        return output

    def _log_outcome(self, started_at: float, outcome: str) -> None:
        duration = time.monotonic() - started_at
        logger.info(
            "AI provider request: model=%s duration=%.3fs outcome=%s",
            self._model,
            duration,
            outcome,
        )
