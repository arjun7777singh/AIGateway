"""In-memory identity store.

Hot-path operation: given a raw API key from the Authorization header,
return (tenant_id, application_id, key_id) or None. Must be O(1).

We index on the sha256 of the raw key. The raw key never lives in
memory after the lookup either — we hash, lookup, discard.

Thread-safety: single-writer (loader at boot + admin reloads later),
many-readers (every request). We swap the index atomically.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from .schema import IdentityFile


def hash_key(raw_key: str) -> str:
    """Compute the canonical storage hash for a raw API key."""
    return "sha256:" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResolvedIdentity:
    """Outcome of a successful key lookup."""

    tenant_id: str
    application_id: str
    key_id: str
    key_prefix: str          # for logging; never expose raw key


class IdentityStore:
    def __init__(self) -> None:
        # hash → ResolvedIdentity
        self._by_hash: dict[str, ResolvedIdentity] = {}

    def replace_all(self, identity: IdentityFile) -> None:
        """Atomically rebuild the lookup index from an IdentityFile."""
        new: dict[str, ResolvedIdentity] = {}
        for tenant in identity.tenants:
            for app in tenant.applications:
                for key in app.keys:
                    if not key.enabled:
                        continue
                    if key.hash in new:
                        # Duplicate hash across tenants is almost certainly
                        # a config mistake (or the same key reused). Raise
                        # at load time, not request time.
                        existing = new[key.hash]
                        raise ValueError(
                            f"duplicate key hash: key {key.id} (tenant={tenant.id} "
                            f"app={app.id}) collides with key {existing.key_id} "
                            f"(tenant={existing.tenant_id} app={existing.application_id})"
                        )
                    new[key.hash] = ResolvedIdentity(
                        tenant_id=tenant.id,
                        application_id=app.id,
                        key_id=key.id,
                        key_prefix=key.prefix,
                    )
        self._by_hash = new

    def resolve(self, raw_key: str) -> Optional[ResolvedIdentity]:
        """Look up a raw key. Returns None on miss (key invalid/unknown/disabled)."""
        if not raw_key:
            return None
        return self._by_hash.get(hash_key(raw_key))

    def __len__(self) -> int:
        return len(self._by_hash)
