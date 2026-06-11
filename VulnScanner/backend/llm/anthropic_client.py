"""Azure OpenAI streaming client for report generation."""

import logging
import os
from collections.abc import AsyncIterator
from typing import Any

from openai import AsyncOpenAI, APIConnectionError, RateLimitError, APIStatusError

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOKENS = 4096
DEFAULT_TEMPERATURE = 0.2


class AnthropicStreamClient:
    """Streaming client for Azure AI Foundry (OpenAI-compatible endpoint)."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = DEFAULT_TEMPERATURE,
    ):
        self._api_key = api_key or os.environ.get("AZURE_FOUNDRY_API_KEY", "")
        self._endpoint = os.environ.get("AZURE_FOUNDRY_ENDPOINT", "")
        self._deployment = model or os.environ.get("AZURE_FOUNDRY_OPENAI_DEPLOYMENT", "gpt-4.1")
        self._max_tokens = max_tokens
        self._temperature = temperature

        self._client = AsyncOpenAI(
            api_key=self._api_key,
            base_url=self._endpoint,
        )

    async def stream_report(
        self,
        system_prompt: str,
        user_prompt: str,
        hld_content: list[dict] | None = None,
    ) -> AsyncIterator[str]:
        """
        Stream a report from Azure OpenAI.

        Yields text chunks as they arrive from the API.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
        ]

        # Build user message
        user_content = ""
        if hld_content:
            for block in hld_content:
                if block.get("type") == "text":
                    user_content += block["text"] + "\n\n"
        user_content += user_prompt

        messages.append({"role": "user", "content": user_content})

        try:
            stream = await self._client.chat.completions.create(
                model=self._deployment,
                messages=messages,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                stream=True,
            )

            async for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except APIConnectionError as e:
            logger.error("Azure OpenAI connection error: %s", e)
            yield f"\n\n[ERROR: Connection failed - {e}]"
        except RateLimitError as e:
            logger.error("Azure OpenAI rate limit hit: %s", e)
            yield "\n\n[ERROR: Rate limit exceeded. Please retry later.]"
        except APIStatusError as e:
            logger.error("Azure OpenAI API error: %s", e)
            yield f"\n\n[ERROR: API error - {e.message}]"
        except Exception as e:
            logger.error("Unexpected LLM error: %s", e)
            yield f"\n\n[ERROR: {e}]"

    async def generate_report(
        self,
        system_prompt: str,
        user_prompt: str,
        hld_content: list[dict] | None = None,
    ) -> str:
        """Non-streaming report generation. Returns full text."""
        chunks = []
        async for chunk in self.stream_report(system_prompt, user_prompt, hld_content):
            chunks.append(chunk)
        return "".join(chunks)
