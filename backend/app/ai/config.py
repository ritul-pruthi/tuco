import os


def _read_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


AI_ENABLED = _read_bool(os.getenv("TUCO_AI_ENABLED"))
AI_PROVIDER = os.getenv("TUCO_AI_PROVIDER", "ollama")
AI_MODEL = os.getenv("TUCO_AI_MODEL", "qwen3.5:4b")
AI_BASE_URL = os.getenv("TUCO_AI_BASE_URL", "http://localhost:11434")
AI_TIMEOUT = float(os.getenv("TUCO_AI_TIMEOUT", "60.0"))
