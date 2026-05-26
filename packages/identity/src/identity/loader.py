"""YAML loader for identity.yaml.

Strict (extra='forbid') to surface typos at load time rather than at
runtime when an operator wonders why their key doesn't work.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from .schema import IdentityFile


class IdentityLoadError(Exception):
    """Raised when identity.yaml fails to parse or validate."""


def load_identity_file(path: str | Path) -> IdentityFile:
    p = Path(path)
    if not p.exists():
        raise IdentityLoadError(f"{p}: does not exist")
    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise IdentityLoadError(f"{p}: invalid YAML: {e}") from e
    if raw is None:
        # Empty file is allowed — treat as no tenants.
        return IdentityFile(tenants=[])
    if not isinstance(raw, dict):
        raise IdentityLoadError(
            f"{p}: top-level must be a mapping, got {type(raw).__name__}"
        )
    try:
        return IdentityFile.model_validate(raw)
    except ValidationError as e:
        raise IdentityLoadError(f"{p}: schema validation failed: {e}") from e


def load_identity_file_optional(path: str | Path) -> Optional[IdentityFile]:
    """Load if present, else return None. Used for optional identity files."""
    if not Path(path).exists():
        return None
    return load_identity_file(path)
