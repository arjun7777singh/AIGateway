"""Typed error envelope and exception handlers.

Every error response from the gateway has this shape:

    {
      "error": {
        "type": "upstream_unreachable",
        "message": "Could not reach ollama",
        "request_id": "req_abc...",
        "provider": "ollama",
        "details": {"underlying": "Connection refused"}
      }
    }

Modeled loosely on OpenAI's error shape so OpenAI-compatible clients
behave sensibly. The same envelope is used for in-stream errors emitted
mid-SSE — clients can rely on one shape regardless of where it appears.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# --- The error envelope --------------------------------------------------

class ErrorBody(BaseModel):
    type: str
    message: str
    request_id: Optional[str] = None
    provider: Optional[str] = None
    details: Optional[dict] = None


class ErrorResponse(BaseModel):
    error: ErrorBody


# --- Typed exceptions ----------------------------------------------------

class GatewayError(Exception):
    """Base class for gateway errors that map to a typed envelope."""

    status_code: int = 500
    error_type: str = "internal_error"

    def __init__(
        self,
        message: str,
        *,
        provider: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.details = details or None


class InvalidRequest(GatewayError):
    status_code = 400
    error_type = "invalid_request"


class UpstreamUnreachable(GatewayError):
    status_code = 502
    error_type = "upstream_unreachable"


class UpstreamTimeout(GatewayError):
    status_code = 504
    error_type = "upstream_timeout"


class UpstreamError(GatewayError):
    """Upstream returned a non-2xx response."""

    status_code = 502
    error_type = "upstream_error"


# Forward-looking for the policy engine. Not raised yet.
class PolicyBlocked(GatewayError):
    status_code = 403
    error_type = "policy.blocked"


# --- Mapping httpx errors → gateway errors ------------------------------

_TIMEOUT_TYPES = (
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.ConnectTimeout,
)


def map_httpx_exception(exc: BaseException, *, provider: str) -> Optional[GatewayError]:
    """Translate an httpx exception into a typed gateway error.

    Returns None if the exception isn't one we recognize — caller should
    re-raise so the generic handler can pick it up.
    """
    if isinstance(exc, _TIMEOUT_TYPES):
        return UpstreamTimeout(
            f"{provider} timed out",
            provider=provider,
            details={"underlying": str(exc) or exc.__class__.__name__},
        )
    if isinstance(exc, httpx.ConnectError):
        return UpstreamUnreachable(
            f"Could not reach {provider}",
            provider=provider,
            details={"underlying": str(exc) or "connection failed"},
        )
    if isinstance(exc, httpx.HTTPStatusError):
        upstream_msg: str
        try:
            body = exc.response.json()
            err = body.get("error") if isinstance(body, dict) else None
            if isinstance(err, dict) and "message" in err:
                upstream_msg = str(err["message"])
            elif isinstance(err, str):
                upstream_msg = err
            else:
                upstream_msg = str(body)[:300]
        except Exception:
            upstream_msg = exc.response.text[:300]
        return UpstreamError(
            f"{provider} returned {exc.response.status_code}",
            provider=provider,
            details={
                "upstream_status": exc.response.status_code,
                "upstream_message": upstream_msg,
            },
        )
    if isinstance(exc, httpx.RequestError):
        return UpstreamError(
            f"{provider} request failed",
            provider=provider,
            details={"underlying": str(exc) or exc.__class__.__name__},
        )
    return None


# --- Response construction ----------------------------------------------

def _envelope(exc: GatewayError, request_id: Optional[str]) -> dict:
    body = ErrorBody(
        type=exc.error_type,
        message=exc.message,
        request_id=request_id,
        provider=exc.provider,
        details=exc.details,
    )
    return jsonable_encoder(ErrorResponse(error=body), exclude_none=True)


def error_chunk(exc: GatewayError, request_id: Optional[str]) -> dict:
    """Shape used for an in-stream error event (mid-SSE)."""
    return _envelope(exc, request_id)


# --- Exception handlers --------------------------------------------------

def _request_id(request: Request) -> Optional[str]:
    return getattr(request.state, "request_id", None)


async def gateway_error_handler(request: Request, exc: GatewayError) -> JSONResponse:
    rid = _request_id(request)
    logger.warning(
        "gateway error",
        extra={
            "request_id": rid,
            "error_type": exc.error_type,
            "provider": exc.provider,
            "status_code": exc.status_code,
        },
    )
    return JSONResponse(status_code=exc.status_code, content=_envelope(exc, rid))


async def httpx_error_handler(request: Request, exc: httpx.HTTPError) -> JSONResponse:
    rid = _request_id(request)
    gw = map_httpx_exception(exc, provider="ollama")
    if gw is None:
        gw = UpstreamError("upstream request failed", provider="ollama")
    logger.warning(
        "upstream error",
        extra={"request_id": rid, "error_type": gw.error_type, "provider": gw.provider},
    )
    return JSONResponse(status_code=gw.status_code, content=_envelope(gw, rid))


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Convert FastAPI's HTTPException into our envelope shape."""
    rid = _request_id(request)
    err = InvalidRequest(str(exc.detail) if exc.detail else "bad request")
    err.status_code = exc.status_code  # preserve the original code
    err.error_type = "invalid_request" if 400 <= exc.status_code < 500 else "internal_error"
    return JSONResponse(status_code=exc.status_code, content=_envelope(err, rid))


async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    rid = _request_id(request)
    err = InvalidRequest("request validation failed", details={"errors": exc.errors()})
    return JSONResponse(status_code=422, content=_envelope(err, rid))


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = _request_id(request)
    logger.exception("unhandled exception", extra={"request_id": rid})
    err = GatewayError("internal error")
    return JSONResponse(status_code=500, content=_envelope(err, rid))


def install(app: FastAPI) -> None:
    """Register all exception handlers on the app."""
    app.add_exception_handler(GatewayError, gateway_error_handler) # type: ignore[arg-type]

    app.add_exception_handler(httpx.HTTPError, httpx_error_handler) # type: ignore[arg-type]

    app.add_exception_handler(HTTPException, http_exception_handler) # type: ignore[arg-type]

    app.add_exception_handler(RequestValidationError, validation_error_handler) # type: ignore[arg-type]

    app.add_exception_handler(Exception, unhandled_exception_handler)