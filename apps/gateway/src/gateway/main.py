"""FastAPI app entrypoint."""
from __future__ import annotations

import logging

from fastapi import FastAPI

from gateway import errors
from gateway.config import settings
from gateway.middleware import RequestIdMiddleware
from gateway.routes import chat

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s",
)


# Make %(request_id)s safe even when callers don't pass it.
class _DefaultRequestId(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(_DefaultRequestId())


app = FastAPI(
    title="AI Gateway",
    version="0.0.1",
    description="Self-hosted AI gateway with policy-based screening (walking skeleton).",
)
app.add_middleware(RequestIdMiddleware)
errors.install(app)
app.include_router(chat.router)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "provider": settings.provider}