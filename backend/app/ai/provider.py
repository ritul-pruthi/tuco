from abc import ABC, abstractmethod


class AIProviderError(Exception):
    """Base error for AI provider failures."""


class AIProviderUnavailable(AIProviderError):
    """The provider server could not be reached."""


class AIProviderTimeout(AIProviderError):
    """The provider did not respond before the timeout."""


class AIProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Return the configured model name."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        timeout: float | None = None,
    ) -> str:
        """Generate raw model output for a prompt."""
