"""Identity schema: tenants, applications, API keys.

A tenant owns applications. An application owns API keys. A key
authenticates an inbound request and resolves to (tenant, app, key_id).

On disk we never store the raw key — only its sha256 hash, the key_id,
and metadata. The raw value is shown exactly once at generation time
and cannot be recovered from the file.

YAML shape:

    tenants:
      - id: acme
        name: "Acme Corp"
        applications:
          - id: chatbot
            name: "Customer Chatbot"
            keys:
              - id: key_01HXYZ...
                hash: "sha256:abcdef..."
                prefix: "gw_live_a1b2c3d4"
                created_at: "2026-05-22T10:00:00Z"
                enabled: true
                description: "Production key for chatbot"
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ApiKey(BaseModel):
    """Stored representation of an API key. Raw value is never persisted."""

    model_config = ConfigDict(extra="forbid")

    id: str                              # key_id, e.g. "key_01HXYZ..."
    hash: str                            # "sha256:<hex>" of the raw key
    prefix: str                          # first 16 chars of raw key, for ops debugging
    created_at: datetime
    enabled: bool = True
    description: Optional[str] = None


class Application(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str                              # e.g. "chatbot"
    name: str
    keys: list[ApiKey] = Field(default_factory=list)


class Tenant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str                              # e.g. "acme" — matches policy.metadata.tenant
    name: str
    applications: list[Application] = Field(default_factory=list)


class IdentityFile(BaseModel):
    """Top-level shape of identity.yaml."""

    model_config = ConfigDict(extra="forbid")

    tenants: list[Tenant] = Field(default_factory=list)
