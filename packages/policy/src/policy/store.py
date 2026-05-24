"""In-memory policy store.

Keyed by tenant for v1. Scope-hierarchy resolution (api_key → app → team
→ tenant) lives in the resolver, which calls this store.

Thread-safety: the store assumes single-writer (the loader at startup
and the admin API later) and many-readers (the request hot path). We
swap the dict atomically on reload so readers never observe a partial
state.
"""
from __future__ import annotations

from typing import Optional

from .schema import Policy


class PolicyStore:
    def __init__(self) -> None:
        self._by_tenant: dict[str, Policy] = {}

    def replace_all(self, policies: list[Policy]) -> None:
        """Atomic swap of the entire policy set. Used for hot reload."""
        new: dict[str, Policy] = {}
        for p in policies:
            new[p.metadata.tenant] = p
        self._by_tenant = new

    def get_for_tenant(self, tenant_id: str) -> Optional[Policy]:
        return self._by_tenant.get(tenant_id)

    def all(self) -> list[Policy]:
        return list(self._by_tenant.values())

    def __len__(self) -> int:
        return len(self._by_tenant)
