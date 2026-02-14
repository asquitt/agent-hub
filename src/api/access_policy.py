from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Literal

from fastapi.routing import APIRoute

_log = logging.getLogger("agenthub.access_policy")


AccessClassification = Literal["public", "authenticated", "tenant_scoped", "admin_scoped"]
AccessMode = Literal["warn", "enforce"]

DEFAULT_OWNER_TENANTS = {
    "owner-platform": ["*"],
    "owner-dev": ["*"],
    "owner-partner": ["tenant-default", "tenant-partner"],
}

PUBLIC_ROUTES = {
    ("GET", "/healthz"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/.well-known/agent.json"),
    ("GET", "/.well-known/oauth-protected-resource"),
    ("GET", "/.well-known/oauth-authorization-server"),
    ("GET", "/operator"),
    ("GET", "/operator/versioning"),
    ("GET", "/customer"),
    ("GET", "/v1/identity/tokens/jwt/jwks"),
    # OAuth token endpoint uses client_credentials (not API key auth)
    ("POST", "/v1/oauth/token"),
}

TENANT_SCOPED_PATTERNS = (
    re.compile(r"^/v1/agents$"),
    re.compile(r"^/v1/agents/[^/]+$"),
    re.compile(r"^/v1/agents/[^/]+/versions$"),
    re.compile(r"^/v1/agents/[^/]+/versions/[^/]+$"),
    re.compile(r"^/v1/agents/[^/]+/versions/[^/]+/behavioral-diff/[^/]+$"),
    re.compile(r"^/v1/agents/[^/]+/compare/[^/]+/[^/]+$"),
    re.compile(r"^/v1/agents/[^/]+/capabilities$"),
    re.compile(r"^/v1/agents/[^/]+/trust$"),
    re.compile(r"^/v1/agents/[^/]+/trust/usage$"),
    re.compile(r"^/v1/namespaces/[^/]+$"),
    re.compile(r"^/v1/discovery/agent-manifest$"),
    re.compile(r"^/v1/delegations/[^/]+/status$"),
    # Runtime routes require tenant scoping
    re.compile(r"^/v1/runtime/profiles"),
    re.compile(r"^/v1/runtime/sandboxes"),
    re.compile(r"^/v1/runtime/audit"),
)

ADMIN_SCOPED_PATTERNS = (
    re.compile(r"^/v1/compliance/evidence/export$"),
    re.compile(r"^/v1/compliance/evidence$"),
    re.compile(r"^/v1/federation/attestations/export$"),
    re.compile(r"^/v1/system/startup-diagnostics$"),
)

IDENTITY_PATTERNS = (
    re.compile(r"^/v1/identity/agents$"),
    re.compile(r"^/v1/identity/agents/[^/]+$"),
    re.compile(r"^/v1/identity/agents/[^/]+/credentials$"),
    re.compile(r"^/v1/identity/agents/[^/]+/active-sessions$"),
    re.compile(r"^/v1/identity/credentials/[^/]+$"),
    re.compile(r"^/v1/identity/credentials/[^/]+/rotate$"),
    re.compile(r"^/v1/identity/credentials/[^/]+/revoke$"),
    re.compile(r"^/v1/identity/delegation-tokens$"),
    re.compile(r"^/v1/identity/delegation-tokens/verify$"),
    re.compile(r"^/v1/identity/delegation-tokens/[^/]+/chain$"),
    re.compile(r"^/v1/identity/delegation-tokens/[^/]+/revoke$"),
    re.compile(r"^/v1/identity/revocations$"),
    re.compile(r"^/v1/identity/revocations/bulk$"),
    re.compile(r"^/v1/identity/agents/[^/]+/revoke$"),
    re.compile(r"^/v1/identity/trust-registry/domains$"),
    re.compile(r"^/v1/identity/trust-registry/domains/[^/]+$"),
    re.compile(r"^/v1/identity/agents/[^/]+/attest$"),
    re.compile(r"^/v1/identity/attestations/[^/]+/verify$"),
    re.compile(r"^/v1/identity/agents/[^/]+/human-principal$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum/verify$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum/compute$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum/integrity$"),
    re.compile(r"^/v1/identity/agents/[^/]+/blended$"),
    re.compile(r"^/v1/identity/agents/[^/]+/on-behalf-of/verify$"),
    re.compile(r"^/v1/identity/agents/[^/]+/spiffe-id$"),
    re.compile(r"^/v1/identity/agents/[^/]+/svid$"),
    re.compile(r"^/v1/identity/spiffe/verify$"),
    re.compile(r"^/v1/identity/spiffe/bundle$"),
    re.compile(r"^/v1/identity/capability-tokens/issue$"),
    re.compile(r"^/v1/identity/capability-tokens/attenuate$"),
    re.compile(r"^/v1/identity/capability-tokens/verify$"),
    re.compile(r"^/v1/identity/capability-tokens/third-party-block$"),
    re.compile(r"^/v1/identity/lifecycle/provision$"),
    re.compile(r"^/v1/identity/lifecycle/agents/[^/]+/rotate$"),
    re.compile(r"^/v1/identity/lifecycle/alerts/expiry$"),
    re.compile(r"^/v1/identity/lifecycle/alerts/rotation$"),
    re.compile(r"^/v1/identity/lifecycle/agents/[^/]+/status$"),
    re.compile(r"^/v1/identity/lifecycle/agents/[^/]+/deprovision$"),
    re.compile(r"^/v1/identity/tokens/jwt$"),
    re.compile(r"^/v1/identity/tokens/jwt/verify$"),
    re.compile(r"^/v1/identity/tokens/jwt/jwks$"),
    # OAuth endpoints
    re.compile(r"^/v1/oauth/register$"),
    re.compile(r"^/v1/oauth/token$"),
)

# Endpoints with local write semantics where idempotency is intentionally optional.
IDEMPOTENCY_OPTIONAL_PATTERNS = (
    re.compile(r"^/v1/auth/tokens$"),
    re.compile(r"^/v1/provenance/manifests/sign$"),
    re.compile(r"^/v1/provenance/manifests/verify$"),
    re.compile(r"^/v1/provenance/artifacts/sign$"),
    re.compile(r"^/v1/provenance/artifacts/verify$"),
    re.compile(r"^/v1/capabilities/search$"),
    re.compile(r"^/v1/capabilities/match$"),
    re.compile(r"^/v1/capabilities/recommend$"),
    re.compile(r"^/v1/discovery/search$"),
    re.compile(r"^/v1/discovery/contract-match$"),
    re.compile(r"^/v1/discovery/compatibility$"),
    re.compile(r"^/v1/operator/refresh$"),
    re.compile(r"^/v1/billing/invoices/[^/]+/reconcile$"),
    # Delegation uses its own durable idempotency store and reservation contract.
    re.compile(r"^/v1/delegations$"),
    # Identity endpoints use their own credential-based safety model.
    re.compile(r"^/v1/identity/agents$"),
    re.compile(r"^/v1/identity/agents/[^/]+/credentials$"),
    re.compile(r"^/v1/identity/credentials/[^/]+/rotate$"),
    re.compile(r"^/v1/identity/credentials/[^/]+/revoke$"),
    # Delegation tokens use their own chain-based safety model.
    re.compile(r"^/v1/identity/delegation-tokens$"),
    re.compile(r"^/v1/identity/delegation-tokens/verify$"),
    re.compile(r"^/v1/identity/delegation-tokens/[^/]+/revoke$"),
    # Revocation endpoints use their own audit model.
    re.compile(r"^/v1/identity/revocations/bulk$"),
    re.compile(r"^/v1/identity/agents/[^/]+/revoke$"),
    # Federation trust registry and attestations.
    re.compile(r"^/v1/identity/trust-registry/domains$"),
    re.compile(r"^/v1/identity/agents/[^/]+/attest$"),
    # Blended identity and config checksum are idempotent PUT operations.
    re.compile(r"^/v1/identity/agents/[^/]+/human-principal$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum$"),
    # Blended identity and config integrity are read/verify operations.
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum/compute$"),
    re.compile(r"^/v1/identity/agents/[^/]+/configuration-checksum/integrity$"),
    re.compile(r"^/v1/identity/agents/[^/]+/on-behalf-of/verify$"),
    # SPIFFE endpoints are stateless generation/verification.
    re.compile(r"^/v1/identity/agents/[^/]+/svid$"),
    re.compile(r"^/v1/identity/spiffe/verify$"),
    re.compile(r"^/v1/identity/spiffe/bundle$"),
    # Capability token endpoints are stateless operations.
    re.compile(r"^/v1/identity/capability-tokens/issue$"),
    re.compile(r"^/v1/identity/capability-tokens/attenuate$"),
    re.compile(r"^/v1/identity/capability-tokens/verify$"),
    re.compile(r"^/v1/identity/capability-tokens/third-party-block$"),
    # Lifecycle endpoints manage provisioning workflows.
    re.compile(r"^/v1/identity/lifecycle/provision$"),
    re.compile(r"^/v1/identity/lifecycle/agents/[^/]+/rotate$"),
    re.compile(r"^/v1/identity/lifecycle/agents/[^/]+/deprovision$"),
    # JWT token endpoints are stateless.
    re.compile(r"^/v1/identity/tokens/jwt$"),
    re.compile(r"^/v1/identity/tokens/jwt/verify$"),
    # OAuth endpoints use client_credentials auth, not idempotency keys.
    re.compile(r"^/v1/oauth/register$"),
    re.compile(r"^/v1/oauth/token$"),
    # Federation execution uses domain-token-based auth.
    re.compile(r"^/v1/federation/execute$"),
    # Runtime sandbox endpoints use their own lifecycle model.
    re.compile(r"^/v1/runtime/profiles$"),
    re.compile(r"^/v1/runtime/profiles/[^/]+$"),
    re.compile(r"^/v1/runtime/sandboxes$"),
    re.compile(r"^/v1/runtime/sandboxes/[^/]+$"),
    re.compile(r"^/v1/runtime/sandboxes/[^/]+/execute$"),
    re.compile(r"^/v1/runtime/sandboxes/[^/]+/complete$"),
    re.compile(r"^/v1/runtime/sandboxes/[^/]+/terminate$"),
    re.compile(r"^/v1/runtime/sandboxes/delegated$"),
    re.compile(r"^/v1/runtime/sandboxes/leased$"),
    re.compile(r"^/v1/runtime/audit/evidence$"),
)


@dataclass(frozen=True)
class AccessViolation:
    code: str
    message: str


def access_mode() -> AccessMode:
    mode = str(os.getenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")).strip().lower()
    if mode == "warn":
        return "warn"
    return "enforce"


def classify_route(method: str, path: str) -> AccessClassification:
    normalized_method = method.upper()
    if (normalized_method, path) in PUBLIC_ROUTES:
        return "public"
    if any(pattern.match(path) for pattern in ADMIN_SCOPED_PATTERNS):
        return "admin_scoped"
    if any(pattern.match(path) for pattern in TENANT_SCOPED_PATTERNS):
        return "tenant_scoped"
    if path.startswith("/v1/"):
        return "authenticated"
    return "public"


def requires_idempotency(method: str, path: str) -> bool:
    normalized_method = method.upper()
    if normalized_method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    if not path.startswith("/v1/"):
        return False
    if any(pattern.match(path) for pattern in IDEMPOTENCY_OPTIONAL_PATTERNS):
        return False
    return True


def _owner_tenants() -> dict[str, list[str]]:
    raw = os.getenv("AGENTHUB_OWNER_TENANTS_JSON")
    if not raw:
        return dict(DEFAULT_OWNER_TENANTS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("AGENTHUB_OWNER_TENANTS_JSON is malformed, falling back to defaults")
        return dict(DEFAULT_OWNER_TENANTS)
    if not isinstance(parsed, dict):
        _log.warning("AGENTHUB_OWNER_TENANTS_JSON is not a JSON object, falling back to defaults")
        return dict(DEFAULT_OWNER_TENANTS)

    out: dict[str, list[str]] = {}
    for owner, tenants in parsed.items():
        if not isinstance(owner, str):
            continue
        if isinstance(tenants, list):
            normalized = [str(item).strip() for item in tenants if str(item).strip()]
            if normalized:
                out[owner] = normalized
    if not out:
        return dict(DEFAULT_OWNER_TENANTS)
    return out


def _tenant_allowed(owner: str, tenant_id: str) -> bool:
    owner_map = _owner_tenants()
    allowed = owner_map.get(owner)
    if not allowed:
        # Unknown identities are constrained to tenant-default unless explicitly mapped.
        return tenant_id == "tenant-default"
    return "*" in allowed or tenant_id in allowed


def evaluate_access(
    *,
    classification: AccessClassification,
    owner: str | None,
    tenant_id: str,
) -> AccessViolation | None:
    if classification == "public":
        return None
    if owner is None:
        return AccessViolation(code="auth.required", message="authentication required")
    if classification == "admin_scoped" and owner not in {"owner-dev", "owner-platform"}:
        return AccessViolation(code="auth.admin_required", message="admin role required")
    if classification == "tenant_scoped" and not _tenant_allowed(owner=owner, tenant_id=tenant_id):
        return AccessViolation(code="tenant.forbidden", message="owner is not allowed for tenant scope")
    return None


def route_policy_map(routes: list[object]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted(route.methods or []):
            if method in {"HEAD", "OPTIONS"}:
                continue
            rows.append(
                {
                    "method": method,
                    "path": route.path,
                    "classification": classify_route(method, route.path),
                    "requires_idempotency": "true" if requires_idempotency(method, route.path) else "false",
                }
            )
    rows.sort(key=lambda item: (item["path"], item["method"]))
    return rows
