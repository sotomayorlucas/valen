"""LLM provider layer.

A thin, dependency-lazy wrapper over LiteLLM so the agent can target any
OpenAI-compatible endpoint (OpenAI/Anthropic "cyber" models, Ollama, vLLM, ...)
without code changes. If LiteLLM is not installed or no credentials are
configured, ``complete`` returns ``None`` and the agent falls back to its
deterministic heuristic hypothesizer.

Configuration (environment variables):

* ``MANIFOLD_LLM_MODEL``    — model name (e.g. ``gpt-4o-mini``, ``claude-3-5-sonnet-*``,
  ``ollama/llama3``). Default ``gpt-4o-mini``.
* ``MANIFOLD_LLM_API_KEY``  — API key (optional for local endpoints).
* ``MANIFOLD_LLM_BASE_URL`` — base URL (optional; used for local/self-hosted).
"""

from __future__ import annotations

import os
from typing import List, Optional

try:
    import litellm  # type: ignore

    _LITELLM_AVAILABLE = True
except ImportError:  # pragma: no cover
    litellm = None
    _LITELLM_AVAILABLE = False


class LLMClient:
    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.0,
    ) -> None:
        self.model = model or os.environ.get("MANIFOLD_LLM_MODEL", "gpt-4o-mini")
        self.api_key = api_key or os.environ.get("MANIFOLD_LLM_API_KEY")
        self.base_url = base_url or os.environ.get("MANIFOLD_LLM_BASE_URL")
        self.temperature = temperature

    @property
    def available(self) -> bool:
        """True if LiteLLM is importable (an actual call may still fail)."""
        return _LITELLM_AVAILABLE

    def complete(self, messages: List[dict]) -> Optional[str]:
        """Send a chat completion request; return the text or ``None`` on any
        failure (missing library, no credentials, network error, ...)."""
        if not _LITELLM_AVAILABLE:
            return None
        try:
            kwargs = {}
            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.base_url:
                kwargs["api_base"] = self.base_url
            response = litellm.completion(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                **kwargs,
            )
            content = response.choices[0].message.content
            return content if content else None
        except Exception:
            return None
