"""AgentHub Identity SDK type definitions."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentIdentity:
    agent_id: str
    owner: str
    status: str
    created_at: str
    metadata: dict[str, str] = field(default_factory=dict)
    scopes: list[str] = field(default_factory=list)


@dataclass
class Credential:
    credential_id: str
    agent_id: str
    credential_type: str
    status: str
    created_at: str
    expires_at: str
    secret: str | None = None  # Only set on initial creation
    scopes: list[str] = field(default_factory=list)


@dataclass
class DelegationToken:
    token: str
    issuer_agent_id: str
    subject_agent_id: str
    scopes: list[str]
    issued_at: int
    expires_at: int
    chain_depth: int = 0


@dataclass
class LifecycleStatus:
    agent_id: str
    status: str
    credential_type: str
    provisioned_at: float
    last_rotation: float | None = None
    auto_rotate: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustScore:
    agent_id: str
    composite_score: float
    trust_tier: str
    signals: dict[str, Any] = field(default_factory=dict)
