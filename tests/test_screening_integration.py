"""End-to-end screening tests through the HTTP layer.

These mount a real FastAPI app with a real policy + detector registry,
intercept the upstream Ollama call with respx, and verify that:
  - clean prompts proxy through to the upstream
  - prompts containing secrets are blocked with the policy envelope
  - dry_run mode passes through but records the intended action
  - redact action rewrites the message content before forwarding
"""
from __future__ import annotations

import httpx
import respx
from detectors import build_default_registry
from fastapi.testclient import TestClient
from policy import PolicyLoadError, load_policy_file
from policy import PolicyStore

from gateway.main import app

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
GW_URL = "/v1/chat/completions"

# A canonical Ollama success response, used by all "passthrough" cases.
OLLAMA_OK = httpx.Response(
    200,
    json={
        "choices": [
            {
                "message": {"role": "assistant", "content": "ack"},
                "finish_reason": "stop",
            }
        ],
        "model": "llama3.2:3b",
    },
)


def _install_policy(yaml_text: str, tmp_path) -> None:
    """Write a policy to disk, load it, and install on app.state."""
    p = tmp_path / "test.yaml"
    p.write_text(yaml_text)
    policy = load_policy_file(p)
    store = PolicyStore()
    store.replace_all([policy])
    app.state.policy_store = store
    app.state.detector_registry = build_default_registry()


BLOCK_POLICY = """\
apiVersion: gateway.ai/v1
kind: Policy
metadata:
  id: pol_test_block
  name: "Block secrets"
  tenant: default
spec:
  inbound:
    - detector: secrets.regex
      config: { rulesets: [aws] }
      on_match:
        any: { action: block, message: "blocked: secret detected" }
"""


@respx.mock
def test_clean_prompt_passes_through(tmp_path):
    _install_policy(BLOCK_POLICY, tmp_path)
    route = respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={
            "model": "llama3.2:3b",
            "messages": [{"role": "user", "content": "What's the weather?"}],
        },
    )
    assert r.status_code == 200
    assert route.called
    assert r.json()["choices"][0]["message"]["content"] == "ack"


@respx.mock
def test_aws_key_in_prompt_blocked(tmp_path):
    _install_policy(BLOCK_POLICY, tmp_path)
    route = respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={
            "model": "llama3.2:3b",
            "messages": [
                {"role": "user", "content": "fix my script: aws key AKIAIOSFODNN7EXAMPLE"},
            ],
        },
    )
    assert r.status_code == 403
    body = r.json()
    assert body["error"]["type"] == "policy.blocked"
    assert "secret" in body["error"]["message"].lower()
    assert body["error"]["details"]["policy_id"] == "pol_test_block"
    assert "secret.aws_access_key_id" in body["error"]["details"]["categories"]
    # And critically: the upstream was NEVER called.
    assert not route.called


DRY_RUN_POLICY = """\
apiVersion: gateway.ai/v1
kind: Policy
metadata:
  id: pol_test_dryrun
  name: "Dry run secrets"
  tenant: default
  mode: dry_run
spec:
  inbound:
    - detector: secrets.regex
      config: { rulesets: [aws] }
      on_match:
        any: { action: block, message: "would block" }
"""


@respx.mock
def test_dry_run_passes_through_but_logs(tmp_path, caplog):
    _install_policy(DRY_RUN_POLICY, tmp_path)
    route = respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    with caplog.at_level("INFO"):
        r = client.post(
            GW_URL,
            json={
                "model": "llama3.2:3b",
                "messages": [
                    {"role": "user", "content": "AKIAIOSFODNN7EXAMPLE"},
                ],
            },
        )
    assert r.status_code == 200
    assert route.called  # NOT blocked
    # The screening log line records what WOULD have happened.
    decisions = [
        rec for rec in caplog.records if rec.message == "screening decision"
    ]
    assert decisions, "expected a screening decision log line"
    rec = decisions[-1]
    assert getattr(rec, "intended_action", None) == "block"
    assert getattr(rec, "actual_action", None) == "allow"


REDACT_POLICY = """\
apiVersion: gateway.ai/v1
kind: Policy
metadata:
  id: pol_test_redact
  name: "Redact secrets"
  tenant: default
spec:
  inbound:
    - detector: secrets.regex
      config: { rulesets: [aws] }
      on_match:
        any: { action: redact }
"""


@respx.mock
def test_redact_action_rewrites_before_upstream(tmp_path):
    _install_policy(REDACT_POLICY, tmp_path)
    route = respx.post(OLLAMA_URL).mock(return_value=OLLAMA_OK)

    client = TestClient(app)
    r = client.post(
        GW_URL,
        json={
            "model": "llama3.2:3b",
            "messages": [
                {"role": "user", "content": "key is AKIAIOSFODNN7EXAMPLE please help"},
            ],
        },
    )
    assert r.status_code == 200
    assert route.called

    # Inspect what we actually sent upstream — the secret must be gone,
    # replaced with the redaction template.
    forwarded = route.calls.last.request
    sent = forwarded.read().decode()
    assert "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "<AWS_ACCESS_KEY>" in sent
