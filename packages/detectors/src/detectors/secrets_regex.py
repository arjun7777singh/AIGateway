"""Secrets detector: regex-based credential and key detection.

Always emits findings at `high` severity — a real secret in a prompt is
unambiguously bad regardless of which kind. Findings carry a SHA-256
hash of the matched value (NEVER the value itself) so the audit log can
correlate the same leaked key across requests without storing it.

The redaction template uses the rule name so downstream models still
get readable context (`<AWS_ACCESS_KEY>` vs an opaque `[REDACTED]`).

Available rulesets:
  - aws           AWS access key IDs
  - github        GitHub personal access tokens (new and classic)
  - openai        OpenAI API keys
  - anthropic     Anthropic API keys
  - jwt           JSON Web Tokens
  - private_key   PEM-encoded private key headers
  - google        Google API keys

Enable per-policy via `config: { rulesets: [aws, github, ...] }`.
Omit to enable all.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import ClassVar

from core import Content, DetectionResult, DetectorError, Finding, RequestContext

from .base import Detector


# Each ruleset: list of (rule_name, compiled_pattern, redaction_template).
# Patterns are intentionally conservative — false positives in production
# would erode trust faster than the occasional miss.
_RULESETS: dict[str, list[tuple[str, re.Pattern[str], str]]] = {
    "aws": [
        (
            "aws_access_key_id",
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "<AWS_ACCESS_KEY>",
        ),
        (
            "aws_secret_access_key",
            # Heuristic: 40-char base64-ish, anchored on an "aws_secret"
            # hint or just preceded by a likely assignment. Standalone
            # 40-char base64 strings are way too common to flag as-is.
            re.compile(
                r"(?i)aws[_\- ]?secret[_\- ]?(?:access[_\- ]?)?key"
                r"\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            ),
            "<AWS_SECRET_KEY>",
        ),
    ],
    "github": [
        ("github_pat",         re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "<GITHUB_PAT>"),
        ("github_oauth",       re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "<GITHUB_OAUTH>"),
        ("github_user_token",  re.compile(r"\bghu_[A-Za-z0-9]{36}\b"), "<GITHUB_USER_TOKEN>"),
        ("github_server_token",re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "<GITHUB_SERVER_TOKEN>"),
        ("github_refresh",     re.compile(r"\bghr_[A-Za-z0-9]{36,255}\b"), "<GITHUB_REFRESH>"),
    ],
    "openai": [
        ("openai_api_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b"), "<OPENAI_KEY>"),
    ],
    "anthropic": [
        ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "<ANTHROPIC_KEY>"),
    ],
    "jwt": [
        (
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
            "<JWT>",
        ),
    ],
    "private_key": [
        (
            "pem_private_key",
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
            ),
            "<PRIVATE_KEY>",
        ),
    ],
    "google": [
        ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "<GOOGLE_API_KEY>"),
    ],
}


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class SecretsRegexDetector(Detector):
    """Regex-based detection of credentials and API keys."""

    name: ClassVar[str] = "secrets.regex"
    direction: ClassVar = "both"
    version: ClassVar[str] = "0.1.0"

    async def detect(
        self,
        content: Content,
        config: dict,
        ctx: RequestContext,
    ) -> DetectionResult:
        started = time.perf_counter()
        try:
            requested = config.get("rulesets")
            if requested is None:
                enabled_sets = list(_RULESETS.keys())
            elif not isinstance(requested, list) or not all(isinstance(x, str) for x in requested):
                return DetectionResult(
                    detector=self.name,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=DetectorError(
                        detector=self.name,
                        message="config.rulesets must be a list of strings",
                    ),
                )
            else:
                unknown = [r for r in requested if r not in _RULESETS]
                if unknown:
                    return DetectionResult(
                        detector=self.name,
                        duration_ms=(time.perf_counter() - started) * 1000,
                        error=DetectorError(
                            detector=self.name,
                            message=f"unknown rulesets: {unknown}",
                        ),
                    )
                enabled_sets = requested

            findings: list[Finding] = []
            text = content.text

            for ruleset in enabled_sets:
                for rule_name, pattern, redaction in _RULESETS[ruleset]:
                    for m in pattern.finditer(text):
                        # If the pattern has a capture group, prefer the
                        # captured span over the whole match. That lets
                        # the aws_secret rule highlight just the key,
                        # not the surrounding `aws_secret_key=...`.
                        if m.groups():
                            value = m.group(1)
                            span = m.span(1)
                        else:
                            value = m.group(0)
                            span = m.span(0)
                        findings.append(
                            Finding(
                                detector=self.name,
                                category=f"secret.{rule_name}",
                                severity="high",
                                confidence=1.0,
                                span=span,
                                redaction=redaction,
                                value_hash=_hash(value),
                                metadata={"ruleset": ruleset},
                            )
                        )

            return DetectionResult(
                detector=self.name,
                findings=findings,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception as exc:  # pragma: no cover — defensive
            return DetectionResult(
                detector=self.name,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=DetectorError(detector=self.name, message=str(exc)),
            )
