"""AgentHub Identity SDK — Python client for agent identity management.

Usage:
    from agenthub_identity import IdentityClient

    client = IdentityClient(base_url="https://api.agenthub.dev", api_key="your-key")

    # Register an agent identity
    identity = client.register_agent("my-agent", scopes=["read", "write"])

    # Issue a credential
    cred = client.issue_credential("my-agent", credential_type="api_key", ttl_seconds=3600)

    # Verify a credential
    result = client.verify_credential(cred.credential_id)

    # Get trust score
    score = client.get_trust_score("my-agent")
"""
from __future__ import annotations

import json
import logging
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sdk.identity.exceptions import (
    AgentHubError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from sdk.identity.types import (
    AgentIdentity,
    Credential,
    DelegationToken,
    LifecycleStatus,
    TrustScore,
)

_log = logging.getLogger("agenthub.sdk.identity")

DEFAULT_TIMEOUT = 30


class IdentityClient:
    """Client for the AgentHub Identity API."""

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:8000",
        api_key: str,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the AgentHub API."""
        url = f"{self._base_url}{path}"
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query}"

        headers = {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        data = json.dumps(body).encode("utf-8") if body else None
        req = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(req, timeout=self._timeout) as resp:
                response_body = resp.read().decode("utf-8")
                return json.loads(response_body) if response_body else {}
        except HTTPError as exc:
            status = exc.code
            detail = ""
            try:
                detail = exc.read().decode("utf-8")
            except Exception:
                pass

            if status == 401:
                raise AuthenticationError("authentication failed", status_code=status, detail=detail) from exc
            elif status == 403:
                raise AuthorizationError("authorization failed", status_code=status, detail=detail) from exc
            elif status == 404:
                raise NotFoundError("resource not found", status_code=status, detail=detail) from exc
            elif status == 422 or status == 400:
                raise ValidationError("validation failed", status_code=status, detail=detail) from exc
            elif status == 429:
                raise RateLimitError("rate limit exceeded", status_code=status, detail=detail) from exc
            elif status >= 500:
                raise ServerError("server error", status_code=status, detail=detail) from exc
            else:
                raise AgentHubError(f"HTTP {status}", status_code=status, detail=detail) from exc

    # ── Agent Identity ────────────────────────────────────────────

    def register_agent(
        self,
        agent_id: str,
        *,
        scopes: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> AgentIdentity:
        """Register a new agent identity."""
        body: dict[str, Any] = {"agent_id": agent_id}
        if scopes:
            body["scopes"] = scopes
        if metadata:
            body["metadata"] = metadata

        data = self._request("POST", "/v1/identity/agents", body=body)
        return AgentIdentity(
            agent_id=data.get("agent_id", agent_id),
            owner=data.get("owner", ""),
            status=data.get("status", "active"),
            created_at=data.get("created_at", ""),
            metadata=data.get("metadata", {}),
            scopes=data.get("scopes", []),
        )

    def get_agent(self, agent_id: str) -> AgentIdentity:
        """Get an agent identity."""
        data = self._request("GET", f"/v1/identity/agents/{agent_id}")
        return AgentIdentity(
            agent_id=data.get("agent_id", agent_id),
            owner=data.get("owner", ""),
            status=data.get("status", ""),
            created_at=data.get("created_at", ""),
            metadata=data.get("metadata", {}),
            scopes=data.get("scopes", []),
        )

    # ── Credentials ───────────────────────────────────────────────

    def issue_credential(
        self,
        agent_id: str,
        *,
        credential_type: str = "api_key",
        scopes: list[str] | None = None,
        ttl_seconds: int = 86400,
    ) -> Credential:
        """Issue a new credential for an agent."""
        body: dict[str, Any] = {
            "credential_type": credential_type,
            "ttl_seconds": ttl_seconds,
        }
        if scopes:
            body["scopes"] = scopes

        data = self._request("POST", f"/v1/identity/agents/{agent_id}/credentials", body=body)
        return Credential(
            credential_id=data.get("credential_id", ""),
            agent_id=data.get("agent_id", agent_id),
            credential_type=data.get("credential_type", credential_type),
            status=data.get("status", "active"),
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
            secret=data.get("secret"),
            scopes=data.get("scopes", []),
        )

    def verify_credential(self, credential_id: str) -> dict[str, Any]:
        """Verify a credential's status."""
        return self._request("GET", f"/v1/identity/credentials/{credential_id}")

    def rotate_credential(self, credential_id: str) -> Credential:
        """Rotate a credential."""
        data = self._request("POST", f"/v1/identity/credentials/{credential_id}/rotate")
        return Credential(
            credential_id=data.get("credential_id", ""),
            agent_id=data.get("agent_id", ""),
            credential_type=data.get("credential_type", ""),
            status=data.get("status", "active"),
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
            secret=data.get("secret"),
            scopes=data.get("scopes", []),
        )

    def revoke_credential(self, credential_id: str, *, reason: str = "manual") -> dict[str, Any]:
        """Revoke a credential."""
        return self._request("POST", f"/v1/identity/credentials/{credential_id}/revoke", body={"reason": reason})

    # ── Delegation ────────────────────────────────────────────────

    def issue_delegation_token(
        self,
        *,
        issuer_agent_id: str,
        subject_agent_id: str,
        scopes: list[str],
        ttl_seconds: int = 3600,
    ) -> DelegationToken:
        """Issue a delegation token."""
        body = {
            "issuer_agent_id": issuer_agent_id,
            "subject_agent_id": subject_agent_id,
            "scopes": scopes,
            "ttl_seconds": ttl_seconds,
        }
        data = self._request("POST", "/v1/identity/delegation-tokens", body=body)
        return DelegationToken(
            token=data.get("token", ""),
            issuer_agent_id=data.get("issuer_agent_id", issuer_agent_id),
            subject_agent_id=data.get("subject_agent_id", subject_agent_id),
            scopes=data.get("scopes", scopes),
            issued_at=data.get("issued_at", 0),
            expires_at=data.get("expires_at", 0),
            chain_depth=data.get("chain_depth", 0),
        )

    def verify_delegation_token(self, token: str) -> dict[str, Any]:
        """Verify a delegation token."""
        return self._request("POST", "/v1/identity/delegation-tokens/verify", body={"token": token})

    # ── Lifecycle ─────────────────────────────────────────────────

    def provision_agent(
        self,
        agent_id: str,
        *,
        credential_type: str = "api_key",
        scopes: list[str] | None = None,
        ttl_seconds: int = 86400,
        auto_rotate: bool = False,
    ) -> dict[str, Any]:
        """Full provisioning workflow."""
        body: dict[str, Any] = {
            "agent_id": agent_id,
            "credential_type": credential_type,
            "ttl_seconds": ttl_seconds,
            "auto_rotate": auto_rotate,
        }
        if scopes:
            body["scopes"] = scopes
        return self._request("POST", "/v1/identity/lifecycle/provision", body=body)

    def get_lifecycle_status(self, agent_id: str) -> LifecycleStatus:
        """Get lifecycle status for an agent."""
        data = self._request("GET", f"/v1/identity/lifecycle/agents/{agent_id}/status")
        return LifecycleStatus(
            agent_id=data.get("agent_id", agent_id),
            status=data.get("status", ""),
            credential_type=data.get("credential_type", ""),
            provisioned_at=data.get("provisioned_at", 0),
            last_rotation=data.get("last_rotation"),
            auto_rotate=data.get("auto_rotate", False),
        )

    def deprovision_agent(self, agent_id: str, *, reason: str = "manual") -> dict[str, Any]:
        """Deprovision an agent."""
        return self._request("POST", f"/v1/identity/lifecycle/agents/{agent_id}/deprovision", body={"reason": reason})

    # ── Trust ─────────────────────────────────────────────────────

    def get_trust_score(self, agent_id: str) -> TrustScore:
        """Get the composite trust score for an agent."""
        data = self._request("GET", f"/v1/agents/{agent_id}/trust/v2")
        return TrustScore(
            agent_id=data.get("agent_id", agent_id),
            composite_score=data.get("composite_score", 0.0),
            trust_tier=data.get("trust_tier", "unknown"),
            signals=data.get("signals", {}),
        )

    def attest_peer(
        self,
        agent_id: str,
        *,
        attester_agent_id: str,
        attestation_type: str = "positive",
        confidence: float = 0.8,
    ) -> dict[str, Any]:
        """Record a peer attestation."""
        return self._request(
            "POST",
            f"/v1/agents/{agent_id}/trust/attestation",
            body={
                "attester_agent_id": attester_agent_id,
                "attestation_type": attestation_type,
                "confidence": confidence,
            },
        )
