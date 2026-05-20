"""FastAPI app entrypoint."""
from __future__ import annotations

import logging

from fastapi import FastAPI

from gateway.config import settings
from gateway.routes import chat

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title="AI Gateway",
    version="0.0.1",
    description="Self-hosted AI gateway with policy-based screening (walking skeleton).",
)
app.include_router(chat.router)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "provider": settings.provider}
