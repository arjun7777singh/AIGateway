"""Request ID middleware.

Generates (or accepts) a request_id per request, stashes it on
`request.state.request_id`, and echoes it in the `X-Request-Id`
response header. This becomes the traceability anchor for logs,
error envelopes, and (later) audit events.
"""
from __future__ import annotations

import logging
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


def _new_id() -> str:
    return f"req_{uuid4().hex}"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Honor a client-supplied X-Request-Id, or mint one."""

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id") or _new_id()
        request.state.request_id = rid
        try:
            response = await call_next(request)
        except Exception:
            # Let the exception bubble; exception handlers will read the id back.
            logger.debug("exception during request", extra={"request_id": rid})
            raise
        response.headers["x-request-id"] = rid
        return response