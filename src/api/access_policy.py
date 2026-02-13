from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Literal

from fastapi.routing import APIRoute


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
    ("GET", "/operator"),
    ("GET", "/operator/versioning"),
    ("GET", "/customer"),
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
)

ADMIN_SCOPED_PATTERNS = (
    re.compile(r"^/v1/compliance/evidence/export$"),
    re.compile(r"^/v1/compliance/evidence$"),
    re.compile(r"^/v1/federation/attestations/export$"),
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
        return dict(DEFAULT_OWNER_TENANTS)
    if not isinstance(parsed, dict):
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
