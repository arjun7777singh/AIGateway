"""Pytest fixtures."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway.main import app


@pytest.fixture(autouse=True)
def _reset_app_state():
    """Tests poke things into app.state directly (bypassing lifespan).
    Reset between tests so order doesn't matter and auth state from one
    test doesn't leak into another.
    """
    yield
    for attr in (
        "identity_store",
        "policy_store",
        "detector_registry",
    ):
        if hasattr(app.state, attr):
            delattr(app.state, attr)

    # Restore default middleware config — tests toggle auth_required.
    for mw in app.user_middleware:
        if mw.cls.__name__ == "AuthMiddleware":
            mw.kwargs["auth_required"] = False
    app.middleware_stack = app.build_middleware_stack()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
