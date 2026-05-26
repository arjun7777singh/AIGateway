"""Auth middleware.

Extracts an API key from the request, resolves it against the identity
store, and populates `request.state.context` with the authenticated
identity. Downstream code (the chat route, the screening orchestrator)
reads from there.

Behavior:
  - If the path is in `auth_exempt_paths` (e.g. /healthz), skip entirely.
  - If a key is presented and resolves → populate ctx with tenant/app/key.
  - If no key is presented:
      auth_required=False → ctx uses `default_tenant` (open mode)
      auth_required=True  → 401 with the standard error envelope
  - If a key is presented but doesn't resolve → 401 either way. A bad
    key is always an error; we don't silently fall back to default.

Key extraction order:
  1. Authorization: Bearer <key>
  2. X-Api-Key: <key>

The identity store is read from `request.app.state.identity_store` at
request time — set by the lifespan handler at boot. This lets the store
be reloaded (later) without restarting the middleware stack.
"""
from __future__ import annotations

import logging
from typing import Optional
from uuid import uuid4

from core import RequestContext
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from identity import IdentityStore, ResolvedIdentity
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


def _extract_key(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization")
    if auth:
        parts = auth.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
    api_key = request.headers.get("x-api-key")
    if api_key:
        return api_key.strip()
    return None


def _ctx_from_resolved(
    request: Request, resolved: ResolvedIdentity
) -> RequestContext:
    return RequestContext(
        request_id=getattr(request.state, "request_id", None) or f"req_{uuid4().hex}",
        tenant_id=resolved.tenant_id,
        application_id=resolved.application_id,
        api_key_id=resolved.key_id,
    )


def _ctx_default(request: Request, tenant_id: str) -> RequestContext:
    return RequestContext(
        request_id=getattr(request.state, "request_id", None) or f"req_{uuid4().hex}",
        tenant_id=tenant_id,
    )


def _unauthorized(
    request: Request, reason: str, *, presented_prefix: Optional[str]
) -> JSONResponse:
    rid = getattr(request.state, "request_id", None)
    details: dict = {"reason": reason}
    if presented_prefix:
        details["presented_key_prefix"] = presented_prefix
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "type": "auth.unauthorized",
                "message": "authentication required",
                "request_id": rid,
                "details": details,
            }
        },
        headers={"x-request-id": rid} if rid else {},
    )


class AuthMiddleware(BaseHTTPMiddleware):
    """Resolves API key → RequestContext; enforces auth_required."""

    def __init__(
        self,
        app,
        *,
        default_tenant: str,
        auth_required: bool,
        exempt_paths: tuple[str, ...],
    ):
        super().__init__(app)
        self._default_tenant = default_tenant
        self._auth_required = auth_required
        self._exempt = set(exempt_paths)

    async def dispatch(self, request: Request, call_next) -> Response:
        # Healthcheck and other exempt paths skip auth entirely.
        if request.url.path in self._exempt:
            return await call_next(request)

        store: Optional[IdentityStore] = getattr(
            request.app.state, "identity_store", None
        )
        # No store loaded (e.g. tests that don't run lifespan) → treat
        # as empty: behave as if no keys exist. With auth_required=True
        # this 401s every request, which is the correct strict default.
        # With auth_required=False it falls through to default tenant.

        raw_key = _extract_key(request)
        presented_prefix = raw_key[:16] if raw_key else None

        if raw_key is None:
            if self._auth_required:
                logger.info(
                    "auth: missing key",
                    extra={"request_id": getattr(request.state, "request_id", None)},
                )
                return _unauthorized(request, "missing api key", presented_prefix=None)
            request.state.context = _ctx_default(request, self._default_tenant)
            return await call_next(request)

        resolved = store.resolve(raw_key) if store is not None else None
        if resolved is None:
            logger.info(
                "auth: invalid key",
                extra={
                    "request_id": getattr(request.state, "request_id", None),
                    "presented_prefix": presented_prefix,
                },
            )
            return _unauthorized(
                request, "invalid api key", presented_prefix=presented_prefix
            )

        request.state.context = _ctx_from_resolved(request, resolved)
        logger.debug(
            "auth: resolved",
            extra={
                "request_id": request.state.context.request_id,
                "tenant": resolved.tenant_id,
                "application": resolved.application_id,
                "key_id": resolved.key_id,
            },
        )
        return await call_next(request)


def install(
    app: FastAPI,
    *,
    default_tenant: str,
    auth_required: bool,
    exempt_paths: tuple[str, ...],
) -> None:
    """Register the auth middleware. The identity store is looked up
    from app.state at request time, so it must be loaded by lifespan."""
    app.add_middleware(
        AuthMiddleware,
        default_tenant=default_tenant,
        auth_required=auth_required,
        exempt_paths=exempt_paths,
    )
