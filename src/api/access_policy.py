from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Literal

from fastapi.routing import APIRoute

from src.api.access_policy_patterns import (
    ADMIN_SCOPED_PATTERNS,
    IDENTITY_PATTERNS,
    IDEMPOTENCY_OPTIONAL_PATTERNS,
    PUBLIC_ROUTES,
    TENANT_SCOPED_PATTERNS,
)

_log = logging.getLogger("agenthub.access_policy")


AccessClassification = Literal["public", "authenticated", "tenant_scoped", "admin_scoped"]
AccessMode = Literal["warn", "enforce"]

DEFAULT_OWNER_TENANTS = {
    "owner-platform": ["*"],
    "owner-dev": ["*"],
    "owner-partner": ["tenant-default", "tenant-partner"],
}

# Re-export pattern constants for backward compatibility
__all__ = [
    "PUBLIC_ROUTES",
    "TENANT_SCOPED_PATTERNS",
    "ADMIN_SCOPED_PATTERNS",
    "IDENTITY_PATTERNS",
    "IDEMPOTENCY_OPTIONAL_PATTERNS",
    "AccessClassification",
    "AccessMode",
    "AccessViolation",
    "access_mode",
    "classify_route",
    "evaluate_access",
    "requires_idempotency",
    "route_policy_map",
]


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
    if path.startswith("/v1/") or path.startswith("/scim/v2/"):
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
