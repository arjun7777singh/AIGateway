"""Screening orchestrator.

Given content, a policy, and a registry of detectors, this module:
  1. Selects enabled detectors for the content's direction.
  2. Runs them concurrently with asyncio.gather.
  3. Handles per-detector errors via failure mode (fail_open/fail_closed).
  4. Maps each finding's severity to an action via `on_match`.
  5. Reduces all actions to one via precedence (block > redact > log > allow).
  6. Honors policy `mode`: dry_run forces `actual_action = allow` and
     records `intended_action`.

The result is a `ScreeningResult` carrying everything the route needs to
decide what to do: the final action, the message to surface on block,
all findings (for the audit event), and the redactions to apply when
`action == "redact"`.

Audit emission lives next door — this module's job is the decision, not
the recording. Both run on the hot path; both must stay fast.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

from core import (
    ACTION_PRECEDENCE,
    Action,
    Content,
    DetectionResult,
    DetectorError,
    Finding,
    RequestContext,
)
from detectors import Detector, DetectorRegistry
from policy import DetectorSection, Policy

logger = logging.getLogger(__name__)


@dataclass
class ScreeningResult:
    """Output of `screen()` — drives the route's behavior."""

    actual_action: Action
    intended_action: Action            # may differ when mode=dry_run
    findings: list[Finding] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)
    block_message: Optional[str] = None
    redacted_text: Optional[str] = None
    skipped: bool = False              # True when policy disabled / no policy

    @property
    def blocked(self) -> bool:
        return self.actual_action == "block"


# --- Helpers --------------------------------------------------------------

def _resolve_failure_mode(section: DetectorSection, policy: Policy) -> str:
    return section.failureMode or policy.spec.defaultFailureMode


def _synthetic_error_finding(detector_name: str, err: DetectorError) -> Finding:
    """Used when fail_closed converts a detector error into a blocking finding."""
    return Finding(
        detector=detector_name,
        category="detector.error",
        severity="critical",
        confidence=1.0,
        metadata={"error": err.message},
    )


def _apply_redactions(text: str, findings: list[Finding]) -> str:
    """Apply redactions right-to-left so earlier spans stay valid.

    Findings without a span or without a redaction template are skipped.
    """
    candidates = [
        f for f in findings if f.span is not None and f.redaction is not None
    ]
    if not candidates:
        return text
    candidates.sort(key=lambda f: f.span[0], reverse=True)  # type: ignore[index]
    out = text
    for f in candidates:
        start, end = f.span  # type: ignore[misc]
        out = out[:start] + (f.redaction or "") + out[end:]
    return out


def _max_action(actions: list[Action]) -> Action:
    if not actions:
        return "allow"
    return max(actions, key=lambda a: ACTION_PRECEDENCE[a])


# --- The orchestrator -----------------------------------------------------

async def screen(
    *,
    content: Content,
    policy: Optional[Policy],
    ctx: RequestContext,
    registry: DetectorRegistry,
) -> ScreeningResult:
    """Run the screening pipeline."""

    # No policy / disabled mode → nothing to do.
    if policy is None or not policy.metadata.enabled or policy.metadata.mode == "disabled":
        return ScreeningResult(
            actual_action=policy.spec.defaultAction if policy else "allow",
            intended_action=policy.spec.defaultAction if policy else "allow",
            skipped=True,
        )

    sections = policy.sections(content.direction)  # type: ignore[arg-type]
    runnable: list[tuple[DetectorSection, Detector]] = []
    for section in sections:
        if not section.enabled:
            continue
        detector = registry.get(section.detector)
        if detector is None:
            # Unknown detector named in policy. Treat as configuration bug;
            # log loudly but do NOT silently allow — that's the worst failure
            # mode for a security tool.
            logger.error(
                "policy references unknown detector",
                extra={"request_id": ctx.request_id, "detector": section.detector},
            )
            # Honor defaultFailureMode for this case too.
            if policy.spec.defaultFailureMode == "fail_closed":
                return ScreeningResult(
                    actual_action="block",
                    intended_action="block",
                    findings=[
                        Finding(
                            detector=section.detector,
                            category="detector.unknown",
                            severity="critical",
                            metadata={"reason": "detector not registered"},
                        )
                    ],
                    block_message=f"unknown detector configured: {section.detector}",
                )
            continue
        runnable.append((section, detector))

    if not runnable:
        return ScreeningResult(
            actual_action=policy.spec.defaultAction,
            intended_action=policy.spec.defaultAction,
        )

    # Run all detectors concurrently.
    results: list[DetectionResult] = await asyncio.gather(
        *(d.detect(content, s.config, ctx) for s, d in runnable),
        return_exceptions=False,  # detectors should swallow their own exceptions
    )

    all_findings: list[Finding] = []
    actions: list[Action] = []
    block_message: Optional[str] = None
    redactable_findings: list[Finding] = []

    for (section, _), result in zip(runnable, results):
        # Handle detector errors via failure mode.
        if result.error is not None:
            mode = _resolve_failure_mode(section, policy)
            logger.warning(
                "detector error",
                extra={
                    "request_id": ctx.request_id,
                    "detector": section.detector,
                    "failure_mode": mode,
                    "error": result.error.message,
                },
            )
            if mode == "fail_closed":
                synthetic = _synthetic_error_finding(section.detector, result.error)
                all_findings.append(synthetic)
                entry = section.action_for("critical") or section.action_for("high")
                if entry is not None:
                    actions.append(entry.action)
                    if entry.action == "block" and entry.message and not block_message:
                        block_message = entry.message
                else:
                    # No mapping for critical/high → conservatively block.
                    actions.append("block")
                    if not block_message:
                        block_message = f"detector error: {section.detector}"
            # fail_open: ignore this detector's vote
            continue

        # Map findings → actions.
        for finding in result.findings:
            all_findings.append(finding)
            entry = section.action_for(finding.severity)
            if entry is None:
                continue
            actions.append(entry.action)
            if entry.action == "block" and entry.message and not block_message:
                block_message = entry.message
            if entry.action == "redact":
                redactable_findings.append(finding)

    intended = _max_action(actions) if actions else policy.spec.defaultAction
    actual = intended
    if policy.metadata.mode == "dry_run":
        actual = "allow"

    redacted_text: Optional[str] = None
    # Only compute redacted text when we'll actually use it.
    if actual == "redact":
        redacted_text = _apply_redactions(content.text, redactable_findings)

    return ScreeningResult(
        actual_action=actual,
        intended_action=intended,
        findings=all_findings,
        detections=results,
        block_message=block_message,
        redacted_text=redacted_text,
    )
