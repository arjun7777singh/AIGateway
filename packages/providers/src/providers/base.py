"""Provider adapter protocol.

Every upstream LLM (Ollama, OpenAI, Anthropic, Bedrock, ...) implements this
interface. The gateway code is provider-agnostic; it just sees `Provider`.
"""
from __future__ import annotations

from typing import AsyncIterator, Optional, Protocol

from pydantic import BaseModel, Field


class ProviderRequest(BaseModel):
    """Normalized request shape passed to a provider adapter."""

    model: str
    messages: list[dict] = Field(default_factory=list)  # OpenAI-format messages
    stream: bool = False
    # Pass-through for provider-specific params (temperature, top_p, etc).
    extra: dict = Field(default_factory=dict)


class ProviderResponse(BaseModel):
    """Non-streaming response from a provider."""

    content: str
    model: str
    finish_reason: str = "stop"
    usage: Optional[dict] = None
    raw: Optional[dict] = None


class StreamChunk(BaseModel):
    """A single chunk from a streaming provider response."""

    delta: str = ""
    finish_reason: Optional[str] = None
    raw: Optional[dict] = None


class Provider(Protocol):
    """Provider adapters all conform to this shape."""

    name: str

    async def complete(self, req: ProviderRequest) -> ProviderResponse:
        """Non-streaming completion."""
        ...

    def stream(self, req: ProviderRequest) -> AsyncIterator[StreamChunk]:
        """Streaming completion. Returns an async iterator of chunks."""
        ...
