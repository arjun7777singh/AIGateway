# AI Gateway

Self-hosted AI gateway with policy-based screening. Sits between client applications and LLM providers, enforces per-tenant policies on inbound prompts (outbound coming soon), and emits a structured decision log for every request.

## Status

End-to-end policy enforcement working:

- OpenAI-compatible front door at `/v1/chat/completions`
- Ollama upstream adapter (uses Ollama's OpenAI-compatible endpoint)
- Streaming and non-streaming both work end-to-end
- Hardened error layer: typed envelope, request_id propagation, peek-pattern for streaming connect/timeout errors
- **Policy engine: YAML-defined policies, hot-loadable, per-tenant**
- **Detector framework: pluggable `Detector` ABC + registry**
- **First detector: `secrets.regex` (AWS, GitHub, OpenAI, Anthropic, JWT, PEM private keys, Google API keys)**
- **Screening orchestrator: parallel detector dispatch, severity → action mapping, redaction, dry-run support**

Not yet:

- API key auth + tenant resolution (currently uses `default` tenant for all traffic)
- ML-based detectors (prompt injection, PII via Presidio, safety classifier)
- Outbound streaming evaluator (algorithm designed; implementation pending)
- Audit event emission (decisions are logged but not stored in a queryable form yet)
- Postgres + Redis

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for package management
- A running [Ollama](https://ollama.com/) with at least one model pulled (default: `llama3.2:3b`)

## Run

```sh
uv sync
cp .env.example .env             # optional, defaults are fine
uv run uvicorn gateway.main:app --reload --port 8080
```

The startup log line tells you how many detectors and policies were loaded:

```
INFO gateway [-] boot: 1 detectors registered, 1 policies loaded from ./policies
```

Health check (shows what's loaded):

```sh
curl -s http://localhost:8080/healthz | jq
# {
#   "status": "ok",
#   "provider": "ollama",
#   "detectors": ["secrets.regex"],
#   "policies_loaded": 1
# }
```

## See the policy engine fire

Clean prompt — passes through:

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages": [{"role": "user", "content": "Say hello."}]}' | jq
```

Prompt with an AWS access key — blocked with a 403:

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages": [{"role": "user", "content": "debug: AKIAIOSFODNN7EXAMPLE"}]}' | jq
# {
#   "error": {
#     "type": "policy.blocked",
#     "message": "Request blocked: credential or API key detected in prompt",
#     "request_id": "req_...",
#     "details": {
#       "policy_id": "pol_default_baseline",
#       "mode": "enforce",
#       "categories": ["secret.aws_access_key_id"]
#     }
#   }
# }
```

To observe-without-enforcing, edit `policies/default.yaml` and change `mode: enforce` to `mode: dry_run`. The same request will now pass through, but you'll see a structured log line recording `intended_action=block actual_action=allow`.

## Test

```sh
uv run pytest -v
# 31 passed
```

## Layout

```
ai-gateway/
├── apps/
│   └── gateway/                       # data plane (FastAPI)
│       └── src/gateway/
│           ├── main.py                # lifespan loads policies + registry
│           ├── config.py
│           ├── errors.py              # typed envelope + handlers
│           ├── middleware.py          # request_id
│           ├── screening.py           # orchestrator
│           └── routes/chat.py
├── packages/
│   ├── core/                          # Finding, Content, RequestContext, ...
│   ├── providers/                     # Ollama adapter
│   ├── policy/                        # PolicyV1 schema, YAML loader, store
│   └── detectors/                     # Detector ABC, registry, secrets.regex
├── policies/
│   └── default.yaml                   # baseline: block secrets
├── deploy/                            # docker-compose, helm (later)
└── tests/
    ├── test_failure_modes.py          # 12 tests
    ├── test_policy_schema.py          # 7 tests
    ├── test_secrets_detector.py       # 8 tests
    └── test_screening_integration.py  # 4 tests (HTTP-level)
```
