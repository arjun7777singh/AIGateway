"""Tests for the secrets regex detector."""
from __future__ import annotations

import hashlib

import pytest
from core import Content, RequestContext
from detectors import SecretsRegexDetector


@pytest.fixture
def det() -> SecretsRegexDetector:
    return SecretsRegexDetector()


@pytest.fixture
def ctx() -> RequestContext:
    return RequestContext(tenant_id="test")


async def test_aws_access_key_detected(det: SecretsRegexDetector, ctx: RequestContext):
    text = "Here is my key: AKIAIOSFODNN7EXAMPLE for the dev account"
    result = await det.detect(Content(direction="inbound", text=text), {}, ctx)
    assert result.error is None
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "secret.aws_access_key_id"
    assert f.severity == "high"
    assert f.redaction == "<AWS_ACCESS_KEY>"
    assert f.span is not None
    start, end = f.span
    assert text[start:end] == "AKIAIOSFODNN7EXAMPLE"


async def test_value_hash_not_value(det: SecretsRegexDetector, ctx: RequestContext):
    """Findings must never carry the raw value — only a hash."""
    text = "key: AKIAIOSFODNN7EXAMPLE"
    result = await det.detect(Content(direction="inbound", text=text), {}, ctx)
    f = result.findings[0]
    assert f.value_hash is not None
    expected = "sha256:" + hashlib.sha256(b"AKIAIOSFODNN7EXAMPLE").hexdigest()
    assert f.value_hash == expected
    # And no field carries the value itself.
    dumped = f.model_dump()
    for v in dumped.values():
        if isinstance(v, str):
            assert "AKIAIOSFODNN7EXAMPLE" not in v


async def test_multiple_secret_types(det: SecretsRegexDetector, ctx: RequestContext):
    text = (
        "openai key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD\n"
        "github: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n"
        "aws: AKIAIOSFODNN7EXAMPLE\n"
    )
    result = await det.detect(Content(direction="inbound", text=text), {}, ctx)
    assert result.error is None
    categories = sorted(f.category for f in result.findings)
    assert "secret.aws_access_key_id" in categories
    assert "secret.github_pat" in categories
    assert "secret.openai_api_key" in categories


async def test_rulesets_filter(det: SecretsRegexDetector, ctx: RequestContext):
    """Only configured rulesets should fire."""
    text = "openai sk-abcdefghijklmnopqrstuvwxyz1234 and aws AKIAIOSFODNN7EXAMPLE"
    result = await det.detect(
        Content(direction="inbound", text=text),
        {"rulesets": ["aws"]},
        ctx,
    )
    assert result.error is None
    categories = {f.category for f in result.findings}
    assert categories == {"secret.aws_access_key_id"}


async def test_unknown_ruleset_errors(det: SecretsRegexDetector, ctx: RequestContext):
    """Unknown ruleset names are a config bug — surface via DetectorError."""
    result = await det.detect(
        Content(direction="inbound", text="anything"),
        {"rulesets": ["aws", "nonexistent"]},
        ctx,
    )
    assert result.error is not None
    assert "nonexistent" in result.error.message


async def test_no_secrets_clean_text(det: SecretsRegexDetector, ctx: RequestContext):
    result = await det.detect(
        Content(direction="inbound", text="Hello, what's the weather today?"),
        {},
        ctx,
    )
    assert result.error is None
    assert result.findings == []


async def test_redaction_span_replaces_correctly(
    det: SecretsRegexDetector, ctx: RequestContext
):
    """The span must point at the secret itself, not surrounding context."""
    text = "before AKIAIOSFODNN7EXAMPLE after"
    result = await det.detect(Content(direction="inbound", text=text), {}, ctx)
    f = result.findings[0]
    start, end = f.span
    redacted = text[:start] + f.redaction + text[end:]
    assert redacted == "before <AWS_ACCESS_KEY> after"


async def test_private_key_header_detected(det: SecretsRegexDetector, ctx: RequestContext):
    text = (
        "Help me parse this:\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADAN...\n"
    )
    result = await det.detect(Content(direction="inbound", text=text), {}, ctx)
    cats = {f.category for f in result.findings}
    assert "secret.pem_private_key" in cats
