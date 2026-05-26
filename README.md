# AI Gateway

Self-hosted AI gateway with policy-based screening and per-tenant API key auth. Sits between client applications and LLM providers, enforces per-tenant policies on inbound prompts, and emits a structured decision log for every request.

## Status

- OpenAI-compatible front door at `/v1/chat/completions`
- Ollama upstream adapter (uses Ollama's OpenAI-compatible endpoint)
- Streaming and non-streaming both work end-to-end
- Hardened error layer: typed envelope, request_id propagation, peek-pattern for streaming connect/timeout errors
- Policy engine: YAML-defined policies, hot-loadable, per-tenant
- Detector framework: pluggable `Detector` ABC + registry
- First detector: `secrets.regex` (AWS, GitHub, OpenAI, Anthropic, JWT, PEM private keys, Google API keys)
- Screening orchestrator: parallel detector dispatch, severity → action mapping, redaction, dry-run support
- **API key auth: tenants → applications → keys, two-header support, open + strict modes, exempt paths**
- **Per-tenant policy routing: each key resolves to a tenant, which selects the active policy**

Not yet:

- ML-based detectors (prompt injection via classifier, PII via Presidio)
- Outbound streaming evaluator (algorithm designed; implementation pending)
- Audit event emission (decisions are logged but not stored in a queryable form yet)
- Postgres + Redis (everything in-memory from YAML)

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- A running [Ollama](https://ollama.com/) with at least one model pulled (default: `llama3.2:3b`)

## Run

```sh
uv sync
cp .env.example .env             # optional, defaults are fine
uv run uvicorn gateway.main:app --reload --port 8080
```

Boot log:

```
INFO gateway [-] boot: 1 detectors, 1 policies (from ./policies), 0 identity keys (auth_required=False)
```

Health check:

```sh
curl -s http://localhost:8080/healthz | jq
```

## Auth modes

The gateway has two operating modes for auth, controlled by `GW_AUTH_REQUIRED`:

**Open mode** (`GW_AUTH_REQUIRED=false`, the default for local dev): requests without a key are accepted and mapped to the `default` tenant. A presented-but-invalid key is still rejected with 401 — silent fallback would mask config mistakes.

**Strict mode** (`GW_AUTH_REQUIRED=true`): every non-exempt request must present a valid key. Exempt paths (currently `/healthz`) bypass auth regardless.

## Adding API keys

Generate a key:

```sh
uv run python -m identity.gen --description "Production chatbot key"
```

The raw key is printed to stderr **once** and cannot be recovered later — copy it to your secret manager. The YAML snippet that prints (on stdout) goes under an application's `keys:` list in `identity.yaml`:

```yaml
tenants:
  - id: acme
    name: "Acme Corp"
    applications:
      - id: chatbot
        name: "Customer Chatbot"
        keys:
          - id: key_4c32cc71bd3c41fb
            hash: "sha256:2b97ae9728..."
            prefix: "gw_live_a6a565fd"
            created_at: "2026-05-24T05:32:13.973715+00:00"
            enabled: true
            description: "Production chatbot key"
```

Start `identity.yaml` from the example:

```sh
cp identity.yaml.example identity.yaml
# then paste your generated keys under an application
```

Restart the gateway. New keys are loaded at boot (hot reload coming later).

Tenant `id` in `identity.yaml` must match `metadata.tenant` in a policy file. If a key resolves to a tenant with no matching policy, screening is skipped — the request passes through unchecked. Use this intentionally (a tenant in observe-mode-by-omission) or set up a default policy.

## See it fire

Clean prompt, no key (open mode):

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"Say hello."}]}' | jq
```

Same, with an AWS key — blocked:

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"messages":[{"role":"user","content":"debug: AKIAIOSFODNN7EXAMPLE"}]}' | jq
```

With auth (strict mode on, valid key):

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer gw_live_<your_key>' \
  -d '{"messages":[{"role":"user","content":"Say hello."}]}' | jq
```

`X-Api-Key` works too, for clients that can't set `Authorization`.

## Test

```sh
uv run pytest -v
# 55 passed
```

## Layout

```
ai-gateway/
├── apps/gateway/src/gateway/
│   ├── main.py                    # lifespan loads everything
│   ├── config.py
│   ├── errors.py                  # typed envelope + handlers
│   ├── middleware.py              # request_id
│   ├── auth.py                    # API key resolution
│   ├── screening.py               # orchestrator
│   └── routes/chat.py
├── packages/
│   ├── core/                      # Finding, Content, RequestContext, ...
│   ├── providers/                 # Ollama adapter
│   ├── policy/                    # PolicyV1 schema, YAML loader, store
│   ├── detectors/                 # Detector ABC, registry, secrets.regex
│   └── identity/                  # Tenant/App/ApiKey schema, store, key generator
├── policies/
│   └── default.yaml               # baseline: block secrets
├── identity.yaml.example          # template for tenants + keys
└── tests/                         # 55 tests
```
