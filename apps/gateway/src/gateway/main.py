"""FastAPI app entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from detectors import build_default_registry
from fastapi import FastAPI
from policy import PolicyStore, load_policy_dir

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


logger = logging.getLogger("gateway")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load policies and build the detector registry once at boot."""
    registry = build_default_registry()
    app.state.detector_registry = registry

    store = PolicyStore()
    try:
        policies = load_policy_dir(settings.policies_dir)
    except Exception as e:
        logger.error("policy load failed; starting with no policies: %s", e)
        policies = []
    store.replace_all(policies)
    app.state.policy_store = store

    logger.info(
        "boot: %d detectors registered, %d policies loaded from %s",
        len(registry.names()),
        len(store),
        settings.policies_dir,
    )

    yield

    # Nothing to clean up yet — DB pools, model server handles, audit
    # flush, etc. will go here as we add them.


app = FastAPI(
    title="AI Gateway",
    version="0.0.1",
    description="Self-hosted AI gateway with policy-based screening (walking skeleton).",
    lifespan=lifespan,
)
app.add_middleware(RequestIdMiddleware)
errors.install(app)
app.include_router(chat.router)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "ok",
        "provider": settings.provider,
        "detectors": app.state.detector_registry.names()
        if hasattr(app.state, "detector_registry")
        else [],
        "policies_loaded": len(app.state.policy_store)
        if hasattr(app.state, "policy_store")
        else 0,
    }
