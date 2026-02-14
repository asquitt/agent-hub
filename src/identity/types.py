from __future__ import annotations

from typing import TypedDict


class AgentIdentity(TypedDict):
    agent_id: str
    owner: str
    credential_type: str
    status: str
    public_key_pem: str | None
    metadata: dict[str, str] | None
    human_principal_id: str | None
    configuration_checksum: str | None
    created_at: str
    updated_at: str


class AgentCredential(TypedDict):
    credential_id: str
    agent_id: str
    scopes: list[str]
    issued_at_epoch: int
    expires_at_epoch: int
    rotation_parent_id: str | None
    status: str
    revoked_at: str | None
    revocation_reason: str | None
    created_at: str


class CredentialIssuanceResult(TypedDict):
    credential_id: str
    agent_id: str
    secret: str
    scopes: list[str]
    expires_at_epoch: int
    status: str


class CredentialVerification(TypedDict):
    valid: bool
    agent_id: str
    credential_id: str
    scopes: list[str]
    expires_at_epoch: int


class ActiveSessions(TypedDict):
    agent_id: str
    credentials: list[AgentCredential]
