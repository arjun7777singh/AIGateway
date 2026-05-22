"""OpenAI-compatible /v1/chat/completions endpoint.

For the skeleton this is a straight proxy to the upstream provider. The
screening pipeline will sit between this route and the provider call.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncIterator, Optional
from uuid import uuid4

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from providers import OllamaProvider, ProviderRequest

from gateway import errors
from gateway.config import settings

logger = logging.getLogger(__name__)

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
        raise errors.InvalidRequest("messages must not be empty")

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


def _as_gateway_error(exc: BaseException) -> errors.GatewayError:
    """Coerce an httpx error into a typed gateway error, or wrap generic ones."""
    if isinstance(exc, errors.GatewayError):
        return exc
    mapped = errors.map_httpx_exception(exc, provider=_provider.name)
    if mapped is not None:
        return mapped
    return errors.GatewayError("internal error")


@router.post("/chat/completions")
async def chat_completions(request: Request, body: ChatCompletionRequest):
    preq = _build_provider_request(body)
    rid: Optional[str] = getattr(request.state, "request_id", None)

    # --- Non-streaming: errors propagate to the handlers in errors.py.
    if not body.stream:
        resp = await _provider.complete(preq)
        return JSONResponse(
            _wrap_response(resp.content, resp.model, resp.finish_reason, resp.usage)
        )

    # --- Streaming: peek at the first chunk so connect/timeout/upstream-status
    # errors return a proper HTTP error code BEFORE we commit to a 200 SSE
    # stream. Errors AFTER the first chunk are emitted in-band, then [DONE].
    agen = _provider.stream(preq)
    first: Optional[object] = None
    try:
        first = await agen.__anext__()
    except StopAsyncIteration:
        first = None  # empty stream — still send [DONE]
    except (httpx.HTTPError, errors.GatewayError) as exc:
        # Don't swallow: surface as a real HTTP error response.
        raise _as_gateway_error(exc) from exc

    async def event_stream() -> AsyncIterator[str]:
        try:
            if first is not None:
                yield f"data: {json.dumps(_wrap_chunk(first.delta, preq.model, first.finish_reason))}\n\n"  # type: ignore[attr-defined]
            async for chunk in agen:
                yield f"data: {json.dumps(_wrap_chunk(chunk.delta, preq.model, chunk.finish_reason))}\n\n"
        except asyncio.CancelledError:
            logger.info("client disconnected mid-stream", extra={"request_id": rid})
            raise
        except (httpx.HTTPError, errors.GatewayError) as exc:
            gw = _as_gateway_error(exc)
            logger.warning(
                "stream error after first chunk",
                extra={"request_id": rid, "error_type": gw.error_type},
            )
            yield f"data: {json.dumps(errors.error_chunk(gw, rid))}\n\n"
        except Exception:
            logger.exception("unexpected stream error", extra={"request_id": rid})
            gw = errors.GatewayError("internal error")
            yield f"data: {json.dumps(errors.error_chunk(gw, rid))}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")