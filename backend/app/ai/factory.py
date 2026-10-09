from app.ai import config
from app.ai.ollama_provider import OllamaProvider
from app.ai.provider import AIProvider


def get_provider() -> AIProvider | None:
    if not config.AI_ENABLED:
        return None

    if config.AI_PROVIDER == "ollama":
        return OllamaProvider(
            model=config.AI_MODEL,
            base_url=config.AI_BASE_URL,
            default_timeout=config.AI_TIMEOUT,
        )

    raise ValueError(f"Unknown AI provider: {config.AI_PROVIDER}")
