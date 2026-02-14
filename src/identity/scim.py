"""SCIM 2.0 Agent Provisioning — automated agent lifecycle via SCIM protocol.

Implements RFC 7643/7644 SCIM (System for Cross-domain Identity Management)
for agent identities, enabling enterprise IdP integration:
- GET /Users (list agents)
- GET /Users/{id} (get agent)
- POST /Users (create agent)
- PUT /Users/{id} (replace agent)
- PATCH /Users/{id} (update agent)
- DELETE /Users/{id} (deactivate agent)
- POST /Bulk (bulk operations)
- GET /ServiceProviderConfig
- GET /Schemas
- GET /ResourceTypes
"""
from __future__ import annotations

import logging
import time
from typing import Any

from src.identity.constants import STATUS_ACTIVE, STATUS_SUSPENDED, VALID_IDENTITY_STATUSES
from src.identity.storage import (
    get_agent_identity,
    list_agent_identities,
    register_agent_identity,
    update_agent_identity_status,
)

_log = logging.getLogger("agenthub.scim")

# SCIM schema URNs
SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
SCHEMA_AGENTHUB = "urn:ietf:params:scim:schemas:extension:agenthub:2.0:Agent"
SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCHEMA_BULK_REQUEST = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
SCHEMA_BULK_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"

# SCIM status mapping
STATUS_MAP_TO_SCIM = {
    "active": True,
    "suspended": False,
    "revoked": False,
}
STATUS_MAP_FROM_SCIM: dict[bool, str] = {
    True: "active",
    False: "suspended",
}


def identity_to_scim(identity: dict[str, Any]) -> dict[str, Any]:
    """Convert an AgentHub identity to SCIM User resource."""
    agent_id = identity["agent_id"]
    return {
        "schemas": [SCHEMA_USER, SCHEMA_AGENTHUB],
        "id": agent_id,
        "externalId": agent_id,
        "userName": agent_id,
        "displayName": agent_id,
        "active": STATUS_MAP_TO_SCIM.get(identity.get("status", "active"), True),
        "meta": {
            "resourceType": "User",
            "created": identity.get("created_at"),
            "lastModified": identity.get("updated_at", identity.get("created_at")),
            "location": f"/scim/v2/Users/{agent_id}",
        },
        SCHEMA_AGENTHUB: {
            "credentialType": identity.get("credential_type"),
            "owner": identity.get("owner"),
            "humanPrincipalId": identity.get("human_principal_id"),
            "configurationChecksum": identity.get("configuration_checksum"),
        },
    }


def scim_list_users(
    *,
    owner: str,
    start_index: int = 1,
    count: int = 100,
    filter_expr: str | None = None,
) -> dict[str, Any]:
    """SCIM list users (agents)."""
    identities = list_agent_identities(owner)
    identity_dicts = [dict(i) for i in identities]

    # Basic filter support
    if filter_expr:
        identity_dicts = _apply_filter(identity_dicts, filter_expr)

    total = len(identity_dicts)
    start = max(0, start_index - 1)
    page = identity_dicts[start: start + count]

    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(page),
        "Resources": [identity_to_scim(i) for i in page],
    }


def scim_get_user(agent_id: str) -> dict[str, Any]:
    """SCIM get user (agent) by ID."""
    identity = get_agent_identity(agent_id)
    return identity_to_scim(dict(identity))


def scim_create_user(
    *,
    scim_resource: dict[str, Any],
    owner: str,
) -> dict[str, Any]:
    """SCIM create user (agent)."""
    agent_id = scim_resource.get("userName") or scim_resource.get("externalId")
    if not agent_id:
        raise ValueError("userName or externalId required")

    ext = scim_resource.get(SCHEMA_AGENTHUB, {})
    credential_type = ext.get("credentialType", "api_key")
    human_principal_id = ext.get("humanPrincipalId")

    identity = register_agent_identity(
        agent_id=agent_id,
        owner=owner,
        credential_type=credential_type,
        human_principal_id=human_principal_id,
    )
    return identity_to_scim(dict(identity))


def scim_replace_user(
    *,
    agent_id: str,
    scim_resource: dict[str, Any],
) -> dict[str, Any]:
    """SCIM replace user (full update)."""
    active = scim_resource.get("active", True)
    new_status = STATUS_MAP_FROM_SCIM.get(active, STATUS_ACTIVE)

    identity = get_agent_identity(agent_id)
    current_status = identity.get("status", STATUS_ACTIVE)

    if current_status != new_status and new_status in VALID_IDENTITY_STATUSES:
        identity = update_agent_identity_status(agent_id, new_status)

    return identity_to_scim(dict(identity))


def scim_patch_user(
    *,
    agent_id: str,
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    """SCIM patch user (partial update via operations)."""
    for op in operations:
        op_type = op.get("op", "").lower()
        path = op.get("path", "").lower()
        value = op.get("value")

        if path == "active" and op_type in {"replace", "add"}:
            new_status = STATUS_MAP_FROM_SCIM.get(bool(value), STATUS_ACTIVE)
            if new_status in VALID_IDENTITY_STATUSES:
                update_agent_identity_status(agent_id, new_status)

    identity = get_agent_identity(agent_id)
    return identity_to_scim(dict(identity))


def scim_delete_user(agent_id: str) -> None:
    """SCIM delete user (deactivate agent)."""
    update_agent_identity_status(agent_id, STATUS_SUSPENDED)
    _log.info("SCIM deactivated agent: %s", agent_id)


def scim_bulk_operations(
    *,
    operations: list[dict[str, Any]],
    owner: str,
) -> dict[str, Any]:
    """Process SCIM bulk operations."""
    results: list[dict[str, Any]] = []

    for op in operations:
        method = op.get("method", "").upper()
        path = op.get("path", "")
        data = op.get("data", {})
        bulk_id = op.get("bulkId", "")

        try:
            if method == "POST" and path == "/Users":
                result = scim_create_user(scim_resource=data, owner=owner)
                results.append({
                    "method": method,
                    "bulkId": bulk_id,
                    "status": "201",
                    "response": result,
                })
            elif method == "PUT" and path.startswith("/Users/"):
                aid = path.split("/Users/")[1]
                result = scim_replace_user(agent_id=aid, scim_resource=data)
                results.append({
                    "method": method,
                    "bulkId": bulk_id,
                    "status": "200",
                    "response": result,
                })
            elif method == "DELETE" and path.startswith("/Users/"):
                aid = path.split("/Users/")[1]
                scim_delete_user(aid)
                results.append({
                    "method": method,
                    "bulkId": bulk_id,
                    "status": "204",
                })
            else:
                results.append({
                    "method": method,
                    "bulkId": bulk_id,
                    "status": "400",
                    "response": _scim_error(400, f"unsupported: {method} {path}"),
                })
        except (KeyError, ValueError) as exc:
            results.append({
                "method": method,
                "bulkId": bulk_id,
                "status": "400",
                "response": _scim_error(400, str(exc)),
            })

    return {
        "schemas": [SCHEMA_BULK_RESPONSE],
        "Operations": results,
    }


def scim_service_provider_config() -> dict[str, Any]:
    """SCIM ServiceProviderConfig."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://docs.agenthub.dev/scim",
        "patch": {"supported": True},
        "bulk": {"supported": True, "maxOperations": 100, "maxPayloadSize": 1048576},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "httpbasic",
                "name": "API Key",
                "description": "Authentication via X-API-Key header",
            }
        ],
    }


def scim_schemas() -> dict[str, Any]:
    """SCIM Schemas endpoint."""
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": 2,
        "Resources": [
            {
                "id": SCHEMA_USER,
                "name": "User",
                "description": "SCIM User (Agent)",
            },
            {
                "id": SCHEMA_AGENTHUB,
                "name": "AgentHub Agent Extension",
                "description": "AgentHub-specific agent attributes",
            },
        ],
    }


def scim_resource_types() -> dict[str, Any]:
    """SCIM ResourceTypes endpoint."""
    return {
        "schemas": [SCHEMA_LIST],
        "totalResults": 1,
        "Resources": [
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/scim/v2/Users",
                "schema": SCHEMA_USER,
                "schemaExtensions": [
                    {"schema": SCHEMA_AGENTHUB, "required": False},
                ],
            },
        ],
    }


def _apply_filter(identities: list[dict[str, Any]], expr: str) -> list[dict[str, Any]]:
    """Basic SCIM filter support: 'userName eq "value"' or 'active eq true'."""
    expr = expr.strip()
    parts = expr.split(" ", 2)
    if len(parts) != 3:
        return identities

    attr, op, val = parts[0].lower(), parts[1].lower(), parts[2].strip('"').strip("'")

    if op != "eq":
        return identities

    if attr == "username":
        return [i for i in identities if i.get("agent_id") == val]
    if attr == "active":
        is_active = val.lower() == "true"
        return [
            i for i in identities
            if STATUS_MAP_TO_SCIM.get(i.get("status", "active"), True) == is_active
        ]
    if attr == "externalid":
        return [i for i in identities if i.get("agent_id") == val]

    return identities


def _scim_error(status: int, detail: str) -> dict[str, Any]:
    """Build a SCIM error response."""
    return {
        "schemas": [SCHEMA_ERROR],
        "status": str(status),
        "detail": detail,
    }
