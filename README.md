# AI Gateway

Self-hosted AI gateway with policy-based screening. Sits between client applications and LLM providers, enforces per-tenant policies on inbound prompts and outbound responses, and emits an audit event for every request.

## Status

Walking skeleton:

- OpenAI-compatible front door at `/v1/chat/completions`
- Ollama upstream adapter (uses Ollama's OpenAI-compatible endpoint)
- Streaming and non-streaming both work end-to-end
- No auth, no policy engine, no detectors yet — those land in the next iterations

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) for package management
- A running [Ollama](https://ollama.com/) with at least one model pulled

## Run

```sh
# install
uv sync

# (optional) override Ollama URL or default model
cp .env.example .env
# edit .env if needed

# start the gateway
uv run uvicorn gateway.main:app --reload --port 8080
```

Health check:

```sh
curl -s http://localhost:8080/healthz
# {"status":"ok","provider":"ollama"}
```

## Test

Non-streaming:

```sh
curl -s http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "qwen3:14b",
    "messages": [{"role": "user", "content": "Say hello in one sentence."}]
  }' | jq
```

Streaming:

```sh
curl -N http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "qwen3:14b",
    "stream": true,
    "messages": [{"role": "user", "content": "Count to five slowly."}]
  }'
```

Substitute whatever model tag you have pulled in Ollama.

## Layout

```
ai-gateway/
├── apps/
│   └── gateway/                 # data plane (FastAPI)
├── packages/
│   ├── core/                    # shared types (Finding, RequestContext, ...)
│   └── providers/               # upstream adapters (Ollama for now)
└── deploy/                      # docker-compose, helm later
```
