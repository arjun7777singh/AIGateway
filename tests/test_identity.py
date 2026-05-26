"""Tests for the identity package: schema, loader, store, generator."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent

import pytest
from identity import (
    ApiKey,
    Application,
    IdentityFile,
    IdentityLoadError,
    IdentityStore,
    Tenant,
    hash_key,
    load_identity_file,
    load_identity_file_optional,
)
from identity.gen import generate_key


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(dedent(content).lstrip())
    return p


# --- hash_key -----------------------------------------------------------

def test_hash_key_deterministic():
    assert hash_key("gw_live_abc") == hash_key("gw_live_abc")


def test_hash_key_differs_per_input():
    assert hash_key("gw_live_abc") != hash_key("gw_live_abd")


def test_hash_key_format():
    h = hash_key("gw_live_abc")
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64  # hex sha256


# --- generate_key -------------------------------------------------------

def test_generate_key_shape():
    raw, key_id, h, prefix = generate_key()
    assert raw.startswith("gw_live_")
    assert len(raw) == len("gw_live_") + 32   # 32 hex chars
    assert key_id.startswith("key_")
    assert h == hash_key(raw)
    assert prefix == raw[:16]


def test_generate_key_uniqueness():
    keys = {generate_key()[0] for _ in range(50)}
    assert len(keys) == 50


# --- loader -------------------------------------------------------------

MIN_YAML = """\
tenants:
  - id: acme
    name: "Acme"
    applications:
      - id: chatbot
        name: "Chatbot"
        keys:
          - id: key_aaa
            hash: "sha256:abc"
            prefix: "gw_live_aaaaaaaa"
            created_at: "2026-01-01T00:00:00Z"
            enabled: true
"""


def test_loads_minimal(tmp_path: Path):
    p = write(tmp_path, "id.yaml", MIN_YAML)
    f = load_identity_file(p)
    assert len(f.tenants) == 1
    assert f.tenants[0].id == "acme"
    assert f.tenants[0].applications[0].id == "chatbot"
    assert f.tenants[0].applications[0].keys[0].id == "key_aaa"


def test_empty_file_is_ok(tmp_path: Path):
    p = write(tmp_path, "id.yaml", "")
    f = load_identity_file(p)
    assert f.tenants == []


def test_missing_file_optional_returns_none(tmp_path: Path):
    assert load_identity_file_optional(tmp_path / "absent.yaml") is None


def test_missing_file_strict_raises(tmp_path: Path):
    with pytest.raises(IdentityLoadError):
        load_identity_file(tmp_path / "absent.yaml")


def test_unknown_field_rejected(tmp_path: Path):
    p = write(tmp_path, "id.yaml", """\
        tenants:
          - id: acme
            name: "Acme"
            applications: []
            unknown_field: oops
    """)
    with pytest.raises(IdentityLoadError):
        load_identity_file(p)


# --- store --------------------------------------------------------------

def _store_with_one_key(raw: str) -> tuple[IdentityStore, str]:
    """Build a store containing exactly one enabled key. Returns (store, key_id)."""
    h = hash_key(raw)
    f = IdentityFile(
        tenants=[
            Tenant(
                id="acme",
                name="Acme",
                applications=[
                    Application(
                        id="chatbot",
                        name="Chatbot",
                        keys=[
                            ApiKey(
                                id="key_aaa",
                                hash=h,
                                prefix=raw[:16],
                                created_at=datetime.now(timezone.utc),
                                enabled=True,
                            )
                        ],
                    )
                ],
            )
        ]
    )
    store = IdentityStore()
    store.replace_all(f)
    return store, "key_aaa"


def test_store_resolves_known_key():
    store, key_id = _store_with_one_key("gw_live_abc123")
    r = store.resolve("gw_live_abc123")
    assert r is not None
    assert r.tenant_id == "acme"
    assert r.application_id == "chatbot"
    assert r.key_id == key_id


def test_store_misses_unknown_key():
    store, _ = _store_with_one_key("gw_live_abc123")
    assert store.resolve("gw_live_other") is None
    assert store.resolve("") is None


def test_store_skips_disabled_keys():
    raw = "gw_live_disabled"
    f = IdentityFile(
        tenants=[
            Tenant(
                id="acme", name="Acme",
                applications=[
                    Application(
                        id="app", name="App",
                        keys=[
                            ApiKey(
                                id="key_x",
                                hash=hash_key(raw),
                                prefix=raw[:16],
                                created_at=datetime.now(timezone.utc),
                                enabled=False,    # disabled
                            )
                        ],
                    )
                ],
            )
        ]
    )
    store = IdentityStore()
    store.replace_all(f)
    assert store.resolve(raw) is None
    assert len(store) == 0


def test_store_rejects_duplicate_hashes():
    raw = "gw_live_dup"
    h = hash_key(raw)
    now = datetime.now(timezone.utc)
    f = IdentityFile(
        tenants=[
            Tenant(
                id="acme", name="Acme",
                applications=[
                    Application(
                        id="app1", name="A1",
                        keys=[ApiKey(id="k1", hash=h, prefix=raw[:16], created_at=now)],
                    ),
                    Application(
                        id="app2", name="A2",
                        keys=[ApiKey(id="k2", hash=h, prefix=raw[:16], created_at=now)],
                    ),
                ],
            )
        ]
    )
    store = IdentityStore()
    with pytest.raises(ValueError, match="duplicate"):
        store.replace_all(f)


def test_store_replace_all_is_atomic_swap():
    """After replace_all, the OLD keys must no longer resolve."""
    store, _ = _store_with_one_key("gw_live_old")
    assert store.resolve("gw_live_old") is not None

    # Now replace with a different key set.
    raw2 = "gw_live_new"
    f = IdentityFile(
        tenants=[
            Tenant(
                id="other", name="Other",
                applications=[
                    Application(
                        id="app", name="App",
                        keys=[
                            ApiKey(
                                id="key_new",
                                hash=hash_key(raw2),
                                prefix=raw2[:16],
                                created_at=datetime.now(timezone.utc),
                            )
                        ],
                    )
                ],
            )
        ]
    )
    store.replace_all(f)
    assert store.resolve("gw_live_old") is None
    assert store.resolve("gw_live_new") is not None
