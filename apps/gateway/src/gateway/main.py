"""FastAPI app entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from detectors import build_default_registry
from fastapi import FastAPI
from identity import IdentityFile, IdentityStore, load_identity_file_optional
from policy import PolicyStore, load_policy_dir

from gateway import auth, errors
from gateway.config import settings
from gateway.middleware import RequestIdMiddleware
from gateway.routes import chat

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s",
)


class _DefaultRequestId(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(_DefaultRequestId())


logger = logging.getLogger("gateway")


def _build_identity_store() -> IdentityStore:
    """Load identity.yaml if present; return an empty store otherwise."""
    store = IdentityStore()
    try:
        identity = load_identity_file_optional(settings.identity_file)
    except Exception as e:
        logger.error("identity load failed; starting with empty store: %s", e)
        identity = IdentityFile(tenants=[])
    if identity is not None:
        try:
            store.replace_all(identity)
        except Exception as e:
            logger.error("identity store rebuild failed: %s", e)
    return store


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load identity, policies, and detectors once at boot."""
    registry = build_default_registry()
    app.state.detector_registry = registry

    policy_store = PolicyStore()
    try:
        policies = load_policy_dir(settings.policies_dir)
    except Exception as e:
        logger.error("policy load failed; starting with no policies: %s", e)
        policies = []
    policy_store.replace_all(policies)
    app.state.policy_store = policy_store

    identity_store = _build_identity_store()
    app.state.identity_store = identity_store

    logger.info(
        "boot: %d detectors, %d policies (from %s), %d identity keys "
        "(auth_required=%s)",
        len(registry.names()),
        len(policy_store),
        settings.policies_dir,
        len(identity_store),
        settings.auth_required,
    )

    yield


app = FastAPI(
    title="AI Gateway",
    version="0.0.1",
    description="Self-hosted AI gateway with policy-based screening (walking skeleton).",
    lifespan=lifespan,
)

# Middleware: Starlette runs them in reverse registration order on the
# way in. We want: request_id → auth → route. So register auth FIRST,
# request_id LAST.
auth.install(
    app,
    default_tenant=settings.default_tenant,
    auth_required=settings.auth_required,
    exempt_paths=settings.auth_exempt_paths,
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
        "identity_keys": len(app.state.identity_store)
        if hasattr(app.state, "identity_store")
        else 0,
        "auth_required": settings.auth_required,
    }
