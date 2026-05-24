"""Policy schema (apiVersion: gateway.ai/v1).

Direct translation of the YAML contract we agreed on:

  - metadata: id, name, tenant, scope, enabled, mode
  - spec.defaultAction / defaultFailureMode
  - spec.inbound / spec.outbound: list of detector configurations
  - spec.streaming: window config (defaults provided; outbound evaluator
    consumes this in a later iteration)

The schema is intentionally additive — new fields go in as Optional with
defaults so old policies keep loading. `apiVersion` is the breaking-change
escape hatch.
"""
from __future__ import annotations

from typing import Literal, Optional

from core import Action, FailureMode, Severity
from pydantic import BaseModel, ConfigDict, Field

PolicyMode = Literal["enforce", "dry_run", "disabled"]


class PolicyScope(BaseModel):
    """Which traffic a policy applies to. Honored loosely in v1 — only
    `tenant` from metadata is used for resolution today; teams/applications/
    routes are accepted so policies don't break when scope expands."""

    teams: list[str] = Field(default_factory=lambda: ["*"])
    applications: list[str] = Field(default_factory=lambda: ["*"])
    routes: list[str] = Field(default_factory=lambda: ["*"])


class PolicyMetadata(BaseModel):
    id: str
    name: str
    tenant: str
    scope: PolicyScope = Field(default_factory=PolicyScope)
    enabled: bool = True
    mode: PolicyMode = "enforce"
    description: Optional[str] = None


class OnMatchEntry(BaseModel):
    """A single severity → action mapping. The optional `message` rides
    into the error envelope so security teams can customize what blocked
    clients see (without leaking the matched value)."""

    model_config = ConfigDict(extra="forbid")

    action: Action
    message: Optional[str] = None


# Per-severity action mapping. Use `any` as a wildcard.
OnMatchKey = Literal["any", "low", "medium", "high", "critical"]


class DetectorSection(BaseModel):
    """One detector entry inside `spec.inbound` or `spec.outbound`."""

    model_config = ConfigDict(extra="forbid")

    detector: str                           # e.g. "secrets.regex"
    enabled: bool = True
    failureMode: Optional[FailureMode] = None  # overrides spec.defaultFailureMode
    config: dict = Field(default_factory=dict)
    on_match: dict[OnMatchKey, OnMatchEntry] = Field(default_factory=dict)

    def action_for(self, severity: Severity) -> Optional[OnMatchEntry]:
        """Look up the action for a given severity, falling back to `any`."""
        if severity in self.on_match:
            return self.on_match[severity]  # type: ignore[index]
        return self.on_match.get("any")


class StreamingWindow(BaseModel):
    max_tokens: int = 128
    max_ms: int = 300


class StreamingFirstWindow(BaseModel):
    max_tokens: int = 32
    max_ms: int = 100


class StreamingConfig(BaseModel):
    first_window: StreamingFirstWindow = Field(default_factory=StreamingFirstWindow)
    window: StreamingWindow = Field(default_factory=StreamingWindow)
    overlap_tokens: int = 32
    on_block: dict = Field(
        default_factory=lambda: {"mode": "cut_stream", "replacement": None}
    )


class PolicySpec(BaseModel):
    defaultAction: Action = "allow"
    defaultFailureMode: FailureMode = "fail_closed"
    inbound: list[DetectorSection] = Field(default_factory=list)
    outbound: list[DetectorSection] = Field(default_factory=list)
    streaming: StreamingConfig = Field(default_factory=StreamingConfig)


class Policy(BaseModel):
    apiVersion: Literal["gateway.ai/v1"] = "gateway.ai/v1"
    kind: Literal["Policy"] = "Policy"
    metadata: PolicyMetadata
    spec: PolicySpec

    def sections(self, direction: Literal["inbound", "outbound"]) -> list[DetectorSection]:
        return self.spec.inbound if direction == "inbound" else self.spec.outbound
