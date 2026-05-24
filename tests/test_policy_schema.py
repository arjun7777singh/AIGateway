"""Tests for the policy schema and YAML loader."""
from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from policy import Policy, PolicyLoadError, load_policy_dir, load_policy_file


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(dedent(content).lstrip())
    return p


MINIMAL = """\
apiVersion: gateway.ai/v1
kind: Policy
metadata:
  id: pol_test
  name: "Test"
  tenant: acme
spec:
  inbound:
    - detector: secrets.regex
      on_match:
        any: { action: block, message: "blocked" }
"""


def test_loads_minimal_policy(tmp_path: Path):
    p = write(tmp_path, "ok.yaml", MINIMAL)
    pol = load_policy_file(p)
    assert isinstance(pol, Policy)
    assert pol.metadata.id == "pol_test"
    assert pol.metadata.tenant == "acme"
    assert pol.metadata.mode == "enforce"          # default
    assert pol.spec.defaultAction == "allow"       # default
    assert pol.spec.defaultFailureMode == "fail_closed"
    assert len(pol.spec.inbound) == 1
    section = pol.spec.inbound[0]
    assert section.detector == "secrets.regex"
    assert section.enabled is True
    assert section.action_for("high").action == "block"   # via "any"
    assert section.action_for("medium").action == "block"  # via "any"


def test_per_severity_on_match(tmp_path: Path):
    p = write(tmp_path, "sev.yaml", """\
        apiVersion: gateway.ai/v1
        kind: Policy
        metadata:
          id: pol_sev
          name: "sev"
          tenant: t
        spec:
          inbound:
            - detector: pii.presidio
              on_match:
                high:   { action: block, message: "no PII" }
                medium: { action: redact }
                low:    { action: log }
    """)
    pol = load_policy_file(p)
    section = pol.spec.inbound[0]
    assert section.action_for("high").action == "block"
    assert section.action_for("high").message == "no PII"
    assert section.action_for("medium").action == "redact"
    assert section.action_for("low").action == "log"
    assert section.action_for("critical") is None  # not mapped, no "any"


def test_unknown_field_rejected(tmp_path: Path):
    """Strictness: a typo like `failure_mode` should fail loudly."""
    p = write(tmp_path, "typo.yaml", """\
        apiVersion: gateway.ai/v1
        kind: Policy
        metadata:
          id: pol_typo
          name: "typo"
          tenant: t
        spec:
          inbound:
            - detector: secrets.regex
              failure_mode: fail_open      # WRONG: should be failureMode
              on_match:
                any: { action: block }
    """)
    with pytest.raises(PolicyLoadError, match="failure_mode"):
        load_policy_file(p)


def test_dry_run_mode_accepted(tmp_path: Path):
    p = write(tmp_path, "dr.yaml", """\
        apiVersion: gateway.ai/v1
        kind: Policy
        metadata:
          id: pol_dr
          name: "dr"
          tenant: t
          mode: dry_run
        spec:
          inbound: []
    """)
    pol = load_policy_file(p)
    assert pol.metadata.mode == "dry_run"


def test_load_directory_skips_non_yaml(tmp_path: Path):
    write(tmp_path, "a.yaml", MINIMAL)
    write(tmp_path, "b.yml", MINIMAL.replace("pol_test", "pol_other"))
    write(tmp_path, "readme.md", "# not a policy")
    pols = load_policy_dir(tmp_path)
    assert {p.metadata.id for p in pols} == {"pol_test", "pol_other"}


def test_load_missing_directory_is_empty(tmp_path: Path):
    assert load_policy_dir(tmp_path / "nonexistent") == []


def test_invalid_yaml_raises(tmp_path: Path):
    p = write(tmp_path, "bad.yaml", "not: valid: yaml: [")
    with pytest.raises(PolicyLoadError):
        load_policy_file(p)
