"""End-to-end auth tests.

Exercises the auth middleware through the real FastAPI app:
  - open mode (auth_required=False) accepts requests with/without keys
  - strict mode (auth_required=True) requires a valid key
  - exempt paths (/healthz) bypass auth in either mode
  - the resolved tenant flows into the screening engine, so different
    keys can map to different policies
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx
import respx
from detectors import build_default_registry
from fastapi.testclient import TestClient
from identity import ApiKey, Application, IdentityFile, IdentityStore, Tenant, hash_key
from policy import PolicyStore, load_policy_file

from gateway.main import app

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
GW_URL = "/v1/chat/completions"

OLLAMA_OK = httpx.Response(
    200,
    json={
        "choices": [
            {"message": {"role": "assistant", "content": "ack"}, "finish_reason": "stop"}
        ],
        "model": "llama3.2:3b",
    },
)


def _install_one_key(raw_key: str, tenant: str = "acme") -> str:
    """Install an identity store with one key under one tenant.
    Returns the resolved tenant id."""
    f = IdentityFile(
        tenants=[
            Tenant(
                id=tenant, name=tenant,
                applications=[
                    Application(
                        id="app", name="App",
                        keys=[
                            ApiKey(
                                id="key_test",
                                hash=hash_key(raw_key),
                                prefix=raw_key[:16],
                                created_at=datetime.now(timezone.utc),
                                enabled=True,
                            )
                        ],
                    )
                ],
            )
        ]
    )
    store = IdentityStore()
    store.replace_all(f)
    app.state.identity_store = store

    # Also ensure policy + detector registry exist (lifespan would set
    # these; we're bypassing it).
    if not hasattr(app.state, "policy_store"):
        app.state.policy_store = PolicyStore()
    if not hasattr(app.state, "detector_registry"):
        app.state.detector_registry = build_default_registry()
    return tenant


def _reset_state():
    """Wipe app.state so each test starts clean."""
    for attr in ("identity_store", "policy_store", "detector_registry"):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


def _set_auth_required(value: bool) -> None:
    """Mutate the running middleware instance's flag."""
    for mw in app.user_middleware:
        if mw.cls.__name__ == "AuthMiddleware":
            mw.kwargs["auth_required"] = value
    # The instantiated middleware stack is cached after first request;
    # rebuild by clearing it so the next request picks up the new flag.
    app.middleware_stack = app.build_middleware_stack()


# --- Open mode (auth_required=False) -------------------------------------

@respx.mock
def test_open_mode_no_key_works():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(False)
    respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(GW_URL, json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200


@respx.mock
def test_open_mode_valid_key_works():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(False)
    respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"authorization": "Bearer gw_live_valid"},
    )
    assert r.status_code == 200


def test_open_mode_invalid_key_still_401s():
    """Even in open mode, a presented-but-bad key is an error.
    Silently falling back would mask config mistakes."""
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(False)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"authorization": "Bearer gw_live_wrong"},
    )
    assert r.status_code == 401
    body = r.json()
    assert body["error"]["type"] == "auth.unauthorized"
    assert body["error"]["details"]["reason"] == "invalid api key"
    assert body["error"]["details"]["presented_key_prefix"] == "gw_live_wrong"


# --- Strict mode (auth_required=True) ------------------------------------

def test_strict_mode_no_key_rejects():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(True)

    client = TestClient(app)
    r = client.post(GW_URL, json={"messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 401
    assert r.json()["error"]["details"]["reason"] == "missing api key"


def test_strict_mode_invalid_key_rejects():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(True)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"x-api-key": "gw_live_nope"},
    )
    assert r.status_code == 401


@respx.mock
def test_strict_mode_valid_key_accepts():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(True)
    respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"authorization": "Bearer gw_live_valid"},
    )
    assert r.status_code == 200


@respx.mock
def test_x_api_key_header_also_works():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(True)
    respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": "hi"}]},
        headers={"x-api-key": "gw_live_valid"},
    )
    assert r.status_code == 200


# --- Exempt paths --------------------------------------------------------

def test_healthz_works_without_key_in_strict_mode():
    _reset_state()
    _install_one_key("gw_live_valid")
    _set_auth_required(True)

    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200


# --- Per-tenant policy routing ------------------------------------------

@respx.mock
def test_authenticated_tenant_drives_policy_lookup(tmp_path):
    """The authenticated tenant should be what the screening engine uses
    to look up the active policy — not the default tenant."""
    _reset_state()
    _set_auth_required(True)

    # Two policies: tenant 'acme' blocks AWS keys; tenant 'beta' has no policy.
    acme_policy_path = tmp_path / "acme.yaml"
    acme_policy_path.write_text("""\
apiVersion: gateway.ai/v1
kind: Policy
metadata:
  id: pol_acme
  name: "Acme"
  tenant: acme
spec:
  inbound:
    - detector: secrets.regex
      config: { rulesets: [aws] }
      on_match:
        any: { action: block, message: "Acme: secret blocked" }
""")
    policies = [load_policy_file(acme_policy_path)]
    pstore = PolicyStore()
    pstore.replace_all(policies)
    app.state.policy_store = pstore

    # Two keys: one for acme, one for beta.
    acme_key = "gw_live_acme1234567890ab"
    beta_key = "gw_live_beta1234567890ab"
    now = datetime.now(timezone.utc)
    f = IdentityFile(
        tenants=[
            Tenant(
                id="acme", name="Acme",
                applications=[Application(
                    id="a", name="A",
                    keys=[ApiKey(id="k_acme", hash=hash_key(acme_key),
                                 prefix=acme_key[:16], created_at=now)],
                )],
            ),
            Tenant(
                id="beta", name="Beta",
                applications=[Application(
                    id="b", name="B",
                    keys=[ApiKey(id="k_beta", hash=hash_key(beta_key),
                                 prefix=beta_key[:16], created_at=now)],
                )],
            ),
        ]
    )
    istore = IdentityStore()
    istore.replace_all(f)
    app.state.identity_store = istore
    app.state.detector_registry = build_default_registry()

    respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)
    client = TestClient(app)

    prompt = "debug: AKIAIOSFODNN7EXAMPLE"

    # Acme key → blocked by Acme's policy.
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": prompt}]},
        headers={"authorization": f"Bearer {acme_key}"},
    )
    assert r.status_code == 403
    assert "Acme" in r.json()["error"]["message"]

    # Beta key → no policy for tenant 'beta', so the same prompt sails through.
    r = client.post(
        GW_URL,
        json={"messages": [{"role": "user", "content": prompt}]},
        headers={"authorization": f"Bearer {beta_key}"},
    )
    assert r.status_code == 200
