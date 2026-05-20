"""OpenAI-compatible /v1/chat/completions endpoint.

For the skeleton this is a straight proxy to the upstream provider. The
screening pipeline will sit between this route and the provider call.
"""
from __future__ import annotations

import json
import time
from typing import AsyncIterator, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from providers import OllamaProvider, ProviderRequest

from gateway.config import settings

router = APIRouter(prefix="/v1")

# One provider for now. When we add policy-driven routing the gateway will
# resolve the provider per-request from the active policy.
_provider = OllamaProvider(base_url=settings.ollama_base_url)


class ChatCompletionRequest(BaseModel):
    """Minimal OpenAI-compatible request body."""

    model: Optional[str] = None
    messages: list[dict] = Field(default_factory=list)
    stream: bool = False
    # Forwarded to the provider as-is.
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None


def _wrap_response(content: str, model: str, finish_reason: str, usage: Optional[dict]) -> dict:
    """Shape a provider response into OpenAI's chat.completion JSON."""
    return {
        "id": f"chatcmpl-{uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": usage or {},
    }


def _wrap_chunk(delta: str, model: str, finish_reason: Optional[str]) -> dict:
    """Shape a stream chunk into OpenAI's chat.completion.chunk JSON."""
    return {
        "id": f"chatcmpl-{uuid4().hex}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": delta} if delta else {},
                "finish_reason": finish_reason,
            }
        ],
    }


def _build_provider_request(body: ChatCompletionRequest) -> ProviderRequest:
    if not body.messages:
        raise HTTPException(status_code=400, detail="messages must not be empty")

    extra: dict = {}
    if body.temperature is not None:
        extra["temperature"] = body.temperature
    if body.top_p is not None:
        extra["top_p"] = body.top_p
    if body.max_tokens is not None:
        extra["max_tokens"] = body.max_tokens

    return ProviderRequest(
        model=body.model or settings.default_model,
        messages=body.messages,
        stream=body.stream,
        extra=extra,
    )


@router.post("/chat/completions")
async def chat_completions(body: ChatCompletionRequest):
    preq = _build_provider_request(body)

    if not body.stream:
        resp = await _provider.complete(preq)
        return JSONResponse(_wrap_response(resp.content, resp.model, resp.finish_reason, resp.usage))

    async def event_stream() -> AsyncIterator[str]:
        async for chunk in _provider.stream(preq):
            payload = _wrap_chunk(chunk.delta, preq.model, chunk.finish_reason)
            yield f"data: {json.dumps(payload)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
