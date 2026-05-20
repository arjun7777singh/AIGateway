"""Shared types used across the gateway.

These mirror the contracts we agreed on in the design pass — Finding,
DetectionResult, RequestContext. The screening pipeline (next iteration)
will live around these.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

# --- Enums (kept as Literals so they show up cleanly in JSON schemas) ---

Severity = Literal["low", "medium", "high", "critical"]
Direction = Literal["inbound", "outbound", "both"]
Action = Literal["allow", "log", "redact", "block"]
FailureMode = Literal["fail_open", "fail_closed"]

# Hardcoded precedence — higher wins. Used when reducing many findings to one action.
ACTION_PRECEDENCE: dict[Action, int] = {"allow": 0, "log": 1, "redact": 2, "block": 3}


# --- Identity / request context ---

class RequestContext(BaseModel):
    """Travels with every request through the screening pipeline."""

    request_id: str = Field(default_factory=lambda: f"req_{uuid4().hex}")
    trace_id: Optional[str] = None
    tenant_id: str = "default"
    team_id: Optional[str] = None
    application_id: Optional[str] = None
    api_key_id: Optional[str] = None
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# --- Content (what flows between client and provider) ---

class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    name: Optional[str] = None


class Content(BaseModel):
    """Direction-agnostic content for screening."""

    direction: Direction
    text: str
    messages: Optional[list[ChatMessage]] = None


# --- Findings and detection results ---

class Finding(BaseModel):
    detector: str
    category: str
    severity: Severity
    confidence: float = 1.0
    span: Optional[tuple[int, int]] = None
    redaction: Optional[str] = None
    # Hash of the matched substring — never the raw value, per the audit rules.
    value_hash: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class DetectorError(BaseModel):
    detector: str
    message: str


class DetectionResult(BaseModel):
    detector: str
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: float = 0.0
    error: Optional[DetectorError] = None
