"""OpenAI-compatible /v1/chat/completions endpoint.

Request lifecycle:
  1. Parse + validate the body.
  2. Resolve the active policy for the request's tenant.
  3. Run inbound screening on each message's text.
     - block  → raise PolicyBlocked (returns 403 with envelope)
     - redact → replace the message content with the redacted text
     - log/allow → continue
  4. Call the upstream provider.
  5. (Outbound screening — added in a later iteration.)

The peek-first pattern for streaming carries over from the error layer:
upfront failures get proper HTTP codes; in-stream failures get an in-band
error event followed by [DONE].
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncIterator, Optional
from uuid import uuid4

import httpx
from core import Content, RequestContext
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from providers import OllamaProvider, ProviderRequest

from gateway import errors, screening
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


# --- Shaping helpers (unchanged from the skeleton) ----------------------

def _wrap_response(content: str, model: str, finish_reason: str, usage: Optional[dict]) -> dict:
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
    if isinstance(exc, errors.GatewayError):
        return exc
    mapped = errors.map_httpx_exception(exc, provider=_provider.name)
    if mapped is not None:
        return mapped
    return errors.GatewayError("internal error")


# --- Screening glue ------------------------------------------------------

async def _run_inbound_screening(
    *,
    request: Request,
    ctx: RequestContext,
    messages: list[dict],
) -> list[dict]:
    """Screen every message; mutate (or replace) on redact, raise on block.

    Returns the (possibly-modified) messages list to forward to the provider.
    """
    store = getattr(request.app.state, "policy_store", None)
    registry = getattr(request.app.state, "detector_registry", None)
    if store is None or registry is None:
        # No screening configured — pass through. (Should only happen
        # before startup completes; tests that don't run the lifecycle
        # also land here.)
        return messages

    policy = store.get_for_tenant(ctx.tenant_id)
    if policy is None:
        return messages

    out: list[dict] = []
    for i, msg in enumerate(messages):
        text = msg.get("content")
        if not isinstance(text, str) or not text:
            out.append(msg)
            continue

        content = Content(direction="inbound", text=text)
        result = await screening.screen(
            content=content,
            policy=policy,
            ctx=ctx,
            registry=registry,
        )

        if result.skipped:
            out.append(msg)
            continue

        # Log the decision. Audit emitter lands in a later iteration; for
        # now structured logs are the breadcrumb.
        if result.findings:
            logger.info(
                "screening decision",
                extra={
                    "request_id": ctx.request_id,
                    "tenant": ctx.tenant_id,
                    "policy_id": policy.metadata.id,
                    "policy_mode": policy.metadata.mode,
                    "intended_action": result.intended_action,
                    "actual_action": result.actual_action,
                    "message_index": i,
                    "finding_categories": [f.category for f in result.findings],
                },
            )

        if result.blocked:
            raise errors.PolicyBlocked(
                result.block_message or "request blocked by policy",
                details={
                    "policy_id": policy.metadata.id,
                    "mode": policy.metadata.mode,
                    "categories": sorted({f.category for f in result.findings}),
                },
            )

        if result.actual_action == "redact" and result.redacted_text is not None:
            new_msg = dict(msg)
            new_msg["content"] = result.redacted_text
            out.append(new_msg)
        else:
            out.append(msg)

    return out


# --- Route ---------------------------------------------------------------

@router.post("/chat/completions")
async def chat_completions(request: Request, body: ChatCompletionRequest):
    rid: Optional[str] = getattr(request.state, "request_id", None)
    ctx = RequestContext(
        request_id=rid or f"req_{uuid4().hex}",
        tenant_id=settings.default_tenant,
    )

    # Inbound screening BEFORE we build the provider request, so we never
    # leak a redacted prompt back into the wire format we send upstream.
    body_messages = await _run_inbound_screening(
        request=request, ctx=ctx, messages=body.messages
    )
    body.messages = body_messages

    preq = _build_provider_request(body)

    # --- Non-streaming.
    if not body.stream:
        resp = await _provider.complete(preq)
        return JSONResponse(
            _wrap_response(resp.content, resp.model, resp.finish_reason, resp.usage)
        )

    # --- Streaming: peek at the first chunk so upstream errors return a
    # proper HTTP error code BEFORE we commit to a 200 SSE stream.
    agen = _provider.stream(preq)
    first: Optional[object] = None
    try:
        first = await agen.__anext__()
    except StopAsyncIteration:
        first = None
    except (httpx.HTTPError, errors.GatewayError) as exc:
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
