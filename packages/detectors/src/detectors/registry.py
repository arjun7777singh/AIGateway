"""Detector registry.

A simple name → instance mapping. Detectors are typically stateless and
cheap to construct, so one instance per process is fine. When a detector
needs heavy resources (a model in memory), instantiate it once and
register the constructed instance.
"""
from __future__ import annotations

from typing import Optional

from .base import Detector


class DetectorRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, Detector] = {}

    def register(self, detector: Detector) -> None:
        if not detector.name:
            raise ValueError(f"detector {type(detector).__name__} has empty name")
        if detector.name in self._by_name:
            raise ValueError(f"detector already registered: {detector.name}")
        self._by_name[detector.name] = detector

    def get(self, name: str) -> Optional[Detector]:
        return self._by_name.get(name)

    def names(self) -> list[str]:
        return sorted(self._by_name.keys())


def build_default_registry() -> DetectorRegistry:
    """Wire up the detectors shipped in this package.

    Kept tiny on purpose — new detectors get added here (or via a plugin
    discovery layer later).
    """
    from .secrets_regex import SecretsRegexDetector

    reg = DetectorRegistry()
    reg.register(SecretsRegexDetector())
    return reg