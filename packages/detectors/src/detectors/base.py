"""Detector protocol.

Every detector (PII, secrets, prompt injection, URL policy, safety
classifier, ...) conforms to this interface. The screening orchestrator
runs them in parallel, aggregates findings, and decides the action.

`config` is the raw dict from the policy file. Each detector validates
its own config — keeps detector-specific schema *with* the detector
rather than spreading it across the policy schema.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Literal

from core import Content, DetectionResult, RequestContext


class Detector(ABC):
    """Abstract base for all detectors."""

    # Class-level metadata. Subclasses MUST set these.
    name: ClassVar[str] = ""
    direction: ClassVar[Literal["inbound", "outbound", "both"]] = "both"
    version: ClassVar[str] = "0.1.0"

    @abstractmethod
    async def detect(
        self,
        content: Content,
        config: dict,
        ctx: RequestContext,
    ) -> DetectionResult:
        """Run this detector on `content`. Return findings (possibly empty).

        Implementations should:
          - Validate `config` (raise on bad config — bad config is a
            deployment bug, not a runtime fail-mode).
          - Never raise on detection misses. Empty findings is success.
          - Catch their own expected runtime errors and surface them via
            DetectionResult.error, so the orchestrator can apply failure
            mode.
        """
        ...
