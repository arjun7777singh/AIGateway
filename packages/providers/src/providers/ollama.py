"""Ollama provider adapter.

For v1 we hit Ollama's OpenAI-compatible endpoint (/v1/chat/completions),
which means the adapter is nearly a passthrough — same wire format on both
sides. A future variant could use Ollama's native /api/chat for access to
Ollama-specific params (num_predict, mirostat, etc).
"""
from __future__ import annotations

import json
import logging
from typing import AsyncIterator

import httpx

from .base import ProviderRequest, ProviderResponse, StreamChunk

logger = logging.getLogger(__name__)


class OllamaProvider:
    """Calls a local or remote Ollama instance via its OpenAI-compatible API."""

    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def _chat_url(self) -> str:
        return f"{self.base_url}/v1/chat/completions"

    async def complete(self, req: ProviderRequest) -> ProviderResponse:
        payload: dict = {
            "model": req.model,
            "messages": req.messages,
            "stream": False,
            **req.extra,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(self._chat_url, json=payload)
            r.raise_for_status()
            data = r.json()

        choice = data["choices"][0]
        return ProviderResponse(
            content=choice["message"]["content"],
            model=data.get("model", req.model),
            finish_reason=choice.get("finish_reason") or "stop",
            usage=data.get("usage"),
            raw=data,
        )

    async def stream(self, req: ProviderRequest) -> AsyncIterator[StreamChunk]:
        payload: dict = {
            "model": req.model,
            "messages": req.messages,
            "stream": True,
            **req.extra,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", self._chat_url, json=payload) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line or not line.startswith("data: "):
                        continue
                    body = line[len("data: "):]
                    if body == "[DONE]":
                        break
                    try:
                        evt = json.loads(body)
                    except json.JSONDecodeError:
                        logger.warning("ollama: dropped non-json chunk: %r", body[:120])
                        continue
                    if not evt.get("choices"):
                        continue
                    choice = evt["choices"][0]
                    delta = choice.get("delta", {}).get("content", "") or ""
                    finish = choice.get("finish_reason")
                    if delta or finish:
                        yield StreamChunk(delta=delta, finish_reason=finish, raw=evt)
