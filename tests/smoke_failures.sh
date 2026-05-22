#!/usr/bin/env bash
# Ad-hoc failure smoke tests. Run against a live gateway:
#   uv run uvicorn gateway.main:app --port 8080
# Then in another shell:
#   bash tests/smoke_failures.sh
#
# These exercise real failure paths (no mocking). Some require you to
# stop/start Ollama between cases — instructions inline.

set -u
GW="${GW:-http://localhost:8080}"

hr() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }
show() {
  printf '\nstatus: %s\n' "$1"
  printf 'body:\n%s\n' "$2" | head -c 1000
}

# ---------------------------------------------------------------------------
hr "1. Healthy baseline (should be 200)"
out=$(curl -s -o /tmp/gw.body -w '%{http_code}' "$GW/healthz")
show "$out" "$(cat /tmp/gw.body)"

# ---------------------------------------------------------------------------
hr "2. Empty messages array (should be 400 from Pydantic/our check)"
out=$(curl -s -o /tmp/gw.body -w '%{http_code}' \
  -X POST "$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d '{"messages": []}')
show "$out" "$(cat /tmp/gw.body)"

# ---------------------------------------------------------------------------
hr "3. Malformed JSON (should be 422)"
out=$(curl -s -o /tmp/gw.body -w '%{http_code}' \
  -X POST "$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d '{not valid json')
show "$out" "$(cat /tmp/gw.body)"

# ---------------------------------------------------------------------------
hr "4. Model that is not pulled (Ollama returns 404 — gateway currently leaks 500)"
out=$(curl -s -o /tmp/gw.body -w '%{http_code}' \
  -X POST "$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d '{"model": "definitely-not-a-real-model:9999b", "messages": [{"role":"user","content":"hi"}]}')
show "$out" "$(cat /tmp/gw.body)"

# ---------------------------------------------------------------------------
hr "5. Upstream unreachable"
echo "MANUAL STEP: stop Ollama in another shell now (e.g. 'pkill ollama' or stop the service),"
echo "then press Enter to run the request."
read -r _
out=$(curl -s -o /tmp/gw.body -w '%{http_code}' \
  -X POST "$GW/v1/chat/completions" \
  -H 'content-type: application/json' \
  -d '{"model":"qwen3:14b","messages":[{"role":"user","content":"hi"}]}')
show "$out" "$(cat /tmp/gw.body)"
echo "Now restart Ollama before continuing."
read -p "Press Enter when Ollama is back up..." _

# ---------------------------------------------------------------------------
hr "6. Mid-stream upstream failure"
echo "This one needs two shells. In one:"
echo "  curl -N $GW/v1/chat/completions -H 'content-type: application/json' \\"
echo "       -d '{\"model\":\"qwen3:14b\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Write a long essay about clouds.\"}]}'"
echo "Wait until tokens start streaming, then in another shell:"
echo "  pkill -9 ollama"
echo "Observe: stream gets cut without a graceful '[DONE]'. Currently the client just sees the connection close."

# ---------------------------------------------------------------------------
hr "7. Client disconnect mid-stream (server-side observation)"
echo "Send a streaming request and Ctrl+C it after a few tokens:"
echo "  curl -N $GW/v1/chat/completions -H 'content-type: application/json' \\"
echo "       -d '{\"model\":\"qwen3:14b\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"Count to 200.\"}]}'"
echo "Watch the gateway logs — you should see the request task get cancelled."
echo "Currently we don't log this cleanly; we should."
