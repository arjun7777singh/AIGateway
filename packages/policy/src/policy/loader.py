"""YAML loader for policy files.

A policy file is a single YAML document conforming to PolicyV1. The
loader is intentionally strict: any unknown field is rejected so typos
in `failure_mode` (instead of `failureMode`) don't silently no-op.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import yaml
from pydantic import ValidationError

from .schema import Policy


class PolicyLoadError(Exception):
    """Raised when a policy file fails to parse or validate."""


def load_policy_file(path: str | Path) -> Policy:
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"{p}: invalid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"{p}: top-level must be a mapping, got {type(raw).__name__}")
    try:
        return Policy.model_validate(raw)
    except ValidationError as e:
        raise PolicyLoadError(f"{p}: schema validation failed: {e}") from e


def load_policy_dir(path: str | Path) -> list[Policy]:
    """Load every *.yaml / *.yml under a directory (non-recursive)."""
    p = Path(path)
    if not p.exists():
        return []
    if not p.is_dir():
        raise PolicyLoadError(f"{p}: not a directory")
    files: Iterable[Path] = sorted(
        list(p.glob("*.yaml")) + list(p.glob("*.yml"))
    )
    return [load_policy_file(f) for f in files]