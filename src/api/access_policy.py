from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from fastapi.routing import APIRoute

from src.api.access_policy_patterns import (
    ADMIN_SCOPED_PATTERNS,
    AUTHENTICATED_ROUTE_FAMILIES,
    IDENTITY_PATTERNS,
    IDEMPOTENCY_OPTIONAL_PATTERNS,
    PUBLIC_ROUTES,
    TENANT_SCOPED_PATTERNS,
)
from src.api.auth import AuthContext

_log = logging.getLogger("agenthub.access_policy")


AccessClassification = Literal["public", "authenticated", "tenant_scoped", "admin_scoped", "denied"]
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
    "RouteAccess",
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


class RouteAccess(str):
    """String-compatible route policy with the context needed for enforcement."""

    classification: AccessClassification
    method: str
    path: str
    resource: str | None
    required_scopes: tuple[str, ...]

    def __new__(
        cls,
        classification: AccessClassification,
        *,
        method: str,
        path: str,
        resource: str | None = None,
        required_scopes: tuple[str, ...] = (),
    ) -> RouteAccess:
        policy = str.__new__(cls, classification)
        policy.classification = classification
        policy.method = method
        policy.path = path
        policy.resource = resource
        policy.required_scopes = required_scopes
        return policy


def access_mode() -> AccessMode:
    mode = str(os.getenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "enforce")).strip().lower()
    if mode == "warn":
        return "warn"
    return "enforce"


def _route_family(path: str) -> str | None:
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] == "v1" and parts[2]:
        return parts[2]
    if path.startswith("/scim/v2/"):
        return "scim"
    return None


_ACTION_SUFFIX = re.compile(
    r"/(access|activate|attenuate|check|complete|consume|deactivate|decide|disable|execute|promote|"
    r"reconcile|refresh|refund|register|remove|revoke|rotate|settle|sign|terminate|unregister|verify|vote)$"
)


def _required_scopes(method: str, path: str, resource: str | None) -> tuple[str, ...]:
    if resource is None:
        return ()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return (f"{resource}.read", "read")
    action_match = _ACTION_SUFFIX.search(path)
    action = action_match.group(1) if action_match else "write"
    scopes = [f"{resource}.{action}"]
    if action != "write":
        scopes.append(action)
    scopes.extend((f"{resource}.write", "write"))
    return tuple(dict.fromkeys(scopes))


def _route_access(classification: AccessClassification, method: str, path: str) -> RouteAccess:
    resource = _route_family(path)
    scopes = () if classification in {"public", "denied"} else _required_scopes(method, path, resource)
    return RouteAccess(
        classification,
        method=method,
        path=path,
        resource=resource,
        required_scopes=scopes,
    )


def classify_route(method: str, path: str) -> RouteAccess:
    normalized_method = method.upper()
    if (normalized_method, path) in PUBLIC_ROUTES:
        return _route_access("public", normalized_method, path)
    if any(pattern.match(path) for pattern in ADMIN_SCOPED_PATTERNS):
        return _route_access("admin_scoped", normalized_method, path)
    if any(pattern.match(path) for pattern in TENANT_SCOPED_PATTERNS):
        return _route_access("tenant_scoped", normalized_method, path)
    if any(pattern.match(path) for pattern in IDENTITY_PATTERNS):
        return _route_access("tenant_scoped", normalized_method, path)
    family = _route_family(path)
    if family in AUTHENTICATED_ROUTE_FAMILIES:
        return _route_access("authenticated", normalized_method, path)
    return _route_access("denied", normalized_method, path)


def requires_idempotency(method: str, path: str) -> bool:
    normalized_method = method.upper()
    if normalized_method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    if not path.startswith("/v1/"):
        return False
    if any(pattern.match(path) for pattern in IDEMPOTENCY_OPTIONAL_PATTERNS):
        return False
    return True


def _owner_tenants() -> dict[str, list[str]] | None:
    raw = os.getenv("AGENTHUB_OWNER_TENANTS_JSON")
    if not raw:
        return dict(DEFAULT_OWNER_TENANTS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.error("AGENTHUB_OWNER_TENANTS_JSON is malformed; denying tenant-scoped access")
        return None
    if not isinstance(parsed, dict):
        _log.error("AGENTHUB_OWNER_TENANTS_JSON is not a JSON object; denying tenant-scoped access")
        return None

    out: dict[str, list[str]] = {}
    for owner, tenants in parsed.items():
        if not isinstance(owner, str):
            continue
        if isinstance(tenants, list):
            normalized = [str(item).strip() for item in tenants if str(item).strip()]
            if normalized:
                out[owner] = normalized
    return out


def _tenant_allowed(owner: str, tenant_id: str) -> bool:
    owner_map = _owner_tenants()
    if owner_map is None:
        return False
    allowed = owner_map.get(owner)
    if not allowed:
        # Preserve the legacy tenant-default only when no explicit policy exists.
        # Once a policy is configured, omitted owners are denied rather than inferred.
        return not os.getenv("AGENTHUB_OWNER_TENANTS_JSON") and tenant_id == "tenant-default"
    return "*" in allowed or tenant_id in allowed


def _as_context(owner: str | AuthContext | None) -> AuthContext | None:
    if owner is None:
        return None
    if isinstance(owner, AuthContext):
        return owner
    roles = ("admin",) if owner in {"owner-dev", "owner-platform"} else ("member",)
    return AuthContext(owner, scopes=("*",), roles=roles, auth_method="api_key")


def _identity_path_agent_id(path: str) -> str | None:
    match = re.match(r"^/v1/identity/agents/([^/]+)(?:/.*)?$", path)
    return match.group(1) if match else None


def _resource_owner(path: str) -> tuple[str | None, bool]:
    """Return (owner, lookup_failed); missing resources are left to the route's 404."""
    agent_id = _identity_path_agent_id(path)
    try:
        if agent_id is not None:
            from src.identity.storage import get_agent_identity

            return str(get_agent_identity(agent_id)["owner"]), False

        credential_match = re.match(r"^/v1/identity/credentials/([^/]+)(?:/.*)?$", path)
        if credential_match:
            from src.identity.storage import IDENTITY_STORAGE

            credential = IDENTITY_STORAGE.get_credential(credential_match.group(1))
            identity = IDENTITY_STORAGE.get_identity(credential["agent_id"])
            return str(identity["owner"]), False
    except KeyError:
        return None, False
    except (OSError, RuntimeError, sqlite3.Error):
        _log.exception("authorization resource ownership lookup failed for %s", path)
        return None, True
    return None, False


def evaluate_access(
    *,
    classification: AccessClassification | RouteAccess,
    owner: str | AuthContext | None,
    tenant_id: str,
) -> AccessViolation | None:
    route = classification if isinstance(classification, RouteAccess) else None
    classification_value = route.classification if route is not None else classification
    if classification_value == "public":
        return None
    if classification_value == "denied":
        return AccessViolation(code="route.unclassified", message="route has no explicit access policy")
    context = _as_context(owner)
    if context is None:
        return AccessViolation(code="auth.required", message="authentication required")
    if not _tenant_allowed(owner=context.owner, tenant_id=tenant_id):
        return AccessViolation(code="tenant.forbidden", message="owner is not allowed for tenant scope")
    if classification_value == "admin_scoped" and "admin" not in context.roles:
        return AccessViolation(code="auth.admin_required", message="admin role required")
    if route is not None and route.required_scopes:
        if not any(context.allows_scope(scope) for scope in route.required_scopes):
            return AccessViolation(
                code="scope.forbidden",
                message=f"missing required scope; expected one of: {', '.join(route.required_scopes)}",
            )
        resource_owner, lookup_failed = _resource_owner(route.path)
        if lookup_failed:
            return AccessViolation(code="authz.unavailable", message="resource authorization is unavailable")
        if resource_owner is not None and resource_owner != context.owner:
            return AccessViolation(code="owner.forbidden", message="resource belongs to another owner")
        agent_id = _identity_path_agent_id(route.path)
        if context.agent_id is not None and agent_id is not None and context.agent_id != agent_id:
            return AccessViolation(code="agent.forbidden", message="agent credential cannot access another agent")
    return None


def route_policy_map(routes: Sequence[object]) -> list[dict[str, str]]:
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
