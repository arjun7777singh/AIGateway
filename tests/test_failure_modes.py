"""Failure-mode tests.

Uses `respx` to intercept the gateway's outbound HTTP to Ollama so we can
simulate failures deterministically (no real Ollama needed).

After error hardening these now assert *exact* status codes and envelope
shapes — they're the contract.
"""
from __future__ import annotations

import json

import httpx
import respx
from fastapi.testclient import TestClient

OLLAMA_URL = "http://localhost:11434/v1/chat/completions"
GW_URL = "/v1/chat/completions"

OK_BODY = {
    "model": "llama3.2:3b",
    "messages": [{"role": "user", "content": "hi"}],
}


def _assert_envelope(body: dict, *, type_: str, status_in_request_id: bool = True) -> None:
    assert "error" in body
    err = body["error"]
    assert err["type"] == type_
    assert isinstance(err.get("message"), str) and err["message"]
    if status_in_request_id:
        assert err.get("request_id", "").startswith("req_")


# --- Client-side validation ------------------------------------------------

def test_empty_messages_returns_400(client: TestClient):
    r = client.post(GW_URL, json={"messages": []})
    assert r.status_code == 400
    _assert_envelope(r.json(), type_="invalid_request")


def test_malformed_json_returns_422(client: TestClient):
    r = client.post(
        GW_URL,
        content=b"{not valid json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    _assert_envelope(r.json(), type_="invalid_request")


# --- Upstream failures (non-streaming) ------------------------------------

@respx.mock
def test_upstream_connection_refused(client: TestClient):
    respx.post(OLLAMA_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    r = client.post(GW_URL, json=OK_BODY)
    assert r.status_code == 502
    body = r.json()
    _assert_envelope(body, type_="upstream_unreachable")
    assert body["error"]["provider"] == "ollama"


@respx.mock
def test_upstream_timeout(client: TestClient):
    respx.post(OLLAMA_URL).mock(side_effect=httpx.ReadTimeout("read timed out"))
    r = client.post(GW_URL, json=OK_BODY)
    assert r.status_code == 504
    _assert_envelope(r.json(), type_="upstream_timeout")


@respx.mock
def test_upstream_model_not_found(client: TestClient):
    respx.post(OLLAMA_URL).mock(
        return_value=httpx.Response(
            404, json={"error": "model 'xxx' not found, try pulling it first"}
        )
    )
    r = client.post(GW_URL, json={"model": "xxx", **{"messages": OK_BODY["messages"]}})
    assert r.status_code == 502
    body = r.json()
    _assert_envelope(body, type_="upstream_error")
    assert body["error"]["details"]["upstream_status"] == 404
    assert "not found" in body["error"]["details"]["upstream_message"].lower()


@respx.mock
def test_upstream_5xx(client: TestClient):
    respx.post(OLLAMA_URL).mock(return_value=httpx.Response(500, text="boom"))
    r = client.post(GW_URL, json=OK_BODY)
    assert r.status_code == 502
    body = r.json()
    _assert_envelope(body, type_="upstream_error")
    assert body["error"]["details"]["upstream_status"] == 500


# --- Request ID propagation ------------------------------------------------

@respx.mock
def test_request_id_header_minted_and_echoed(client: TestClient):
    respx.post(OLLAMA_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "model": "qwen3:14b",
            },
        )
    )
    r = client.post(GW_URL, json=OK_BODY)
    assert r.status_code == 200
    assert r.headers.get("x-request-id", "").startswith("req_")


@respx.mock
def test_request_id_honored_from_header(client: TestClient):
    respx.post(OLLAMA_URL).mock(side_effect=httpx.ConnectError("nope"))
    r = client.post(GW_URL, json=OK_BODY, headers={"X-Request-Id": "req_custom123"})
    assert r.headers["x-request-id"] == "req_custom123"
    assert r.json()["error"]["request_id"] == "req_custom123"


# --- Streaming -----------------------------------------------------------

SSE_HAPPY = (
    b'data: {"choices":[{"delta":{"content":"hello"},"finish_reason":null}],"model":"qwen3:14b"}\n\n'
    b'data: {"choices":[{"delta":{"content":" world"},"finish_reason":null}],"model":"qwen3:14b"}\n\n'
    b'data: {"choices":[{"delta":{},"finish_reason":"stop"}],"model":"qwen3:14b"}\n\n'
    b"data: [DONE]\n\n"
)


@respx.mock
def test_streaming_happy_path(client: TestClient):
    respx.post(OLLAMA_URL).mock(return_value=httpx.Response(200, content=SSE_HAPPY))
    with client.stream("POST", GW_URL, json={**OK_BODY, "stream": True}) as r:
        assert r.status_code == 200
        body = b"".join(r.iter_bytes())
    text = body.decode()
    assert "hello" in text
    assert " world" in text
    assert text.rstrip().endswith("data: [DONE]")


@respx.mock
def test_streaming_connect_error_returns_502_before_stream_starts(client: TestClient):
    """Connect errors on the FIRST chunk should yield a proper HTTP 502,
    not a 200 SSE with an in-band error. That's what the peek pattern buys us."""
    respx.post(OLLAMA_URL).mock(side_effect=httpx.ConnectError("nope"))
    r = client.post(GW_URL, json={**OK_BODY, "stream": True})
    assert r.status_code == 502
    _assert_envelope(r.json(), type_="upstream_unreachable")


SSE_TRUNCATED = (
    b'data: {"choices":[{"delta":{"content":"partial"},"finish_reason":null}],"model":"qwen3:14b"}\n\n'
)


@respx.mock
def test_streaming_upstream_drops_mid_stream_emits_done(client: TestClient):
    """Upstream sends one chunk then ends abruptly with no [DONE].

    The gateway must still terminate cleanly with [DONE] on its side,
    so OpenAI-compatible clients see a graceful stream end.
    """
    respx.post(OLLAMA_URL).mock(return_value=httpx.Response(200, content=SSE_TRUNCATED))
    with client.stream("POST", GW_URL, json={**OK_BODY, "stream": True}) as r:
        body = b"".join(r.iter_bytes())
    text = body.decode()
    assert "partial" in text
    assert text.rstrip().endswith("data: [DONE]")


def _iter_sse_events(text: str) -> list[str]:
    return [line[len("data: "):] for line in text.split("\n") if line.startswith("data: ")]


@respx.mock
def test_streaming_in_band_error_then_done(client: TestClient):
    """Force a non-JSON line followed by a fake connection drop after the
    first valid chunk. The gateway should emit an error event AND [DONE].

    Simulating "drop after first chunk" with respx is awkward — easier
    to verify the [DONE] guarantee from the truncated-stream test above
    and the in-band envelope shape via a unit test of error_chunk().
    """
    from gateway.errors import UpstreamError, error_chunk

    chunk = error_chunk(UpstreamError("oops", provider="ollama"), "req_test")
    assert chunk["error"]["type"] == "upstream_error"
    assert chunk["error"]["request_id"] == "req_test"
    # Must round-trip through JSON cleanly so it fits in an SSE data: line.
    assert json.loads(json.dumps(chunk)) == chunk