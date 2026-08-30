from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from src.api.access_policy import classify_route

Maturity = str

_DEFERRED_PREFIXES = (
    "/v1/billing",
    "/v1/marketplace",
    "/v1/procurement",
)

_STUB_PREFIXES = (
    "/v1/runtime",
    "/v1/delegations",
    "/v1/federation/execute",
    "/v1/audit/webhooks",
    "/v1/audit/deliveries",
    "/v1/audit/dead-letters",
)


def operation_maturity(path: str) -> tuple[Maturity, str]:
    """Return an evidence-bounded implementation label for an API path."""
    if path.startswith("/v1/relay"):
        return (
            "prototype",
            "one operator-attested, server-declared read-only MCP target is proven locally; "
            "distributed production operation is not proven",
        )
    if path.startswith(_DEFERRED_PREFIXES):
        return (
            "deferred",
            "financial mutations are disabled pending transactional integrity proof",
        )
    if path.startswith(_STUB_PREFIXES):
        return (
            "stub",
            "local control-plane or simulation behavior; no remote workload execution is proven",
        )
    return (
        "prototype",
        "locally tested control-plane behavior; production deployment is not proven",
    )


def install_openapi_contract(app: FastAPI) -> None:
    def build_schema() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=(
                "AgentHub local control-plane prototype. Operation maturity labels distinguish "
                "tested local behavior from simulators and deferred financial surfaces."
            ),
            routes=app.routes,
        )
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.update(
            {
                "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
                "AgentCredentialAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "Authorization",
                    "description": "AgentCredential scheme",
                },
                "DelegationTokenAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Delegation-Token",
                },
            }
        )

        for path, path_item in schema.get("paths", {}).items():
            maturity, boundary = operation_maturity(path)
            for method, operation in path_item.items():
                if method.lower() not in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "options",
                    "head",
                    "trace",
                }:
                    continue
                operation["x-agenthub-maturity"] = maturity
                operation["x-agenthub-evidence-boundary"] = boundary
                access = classify_route(method, path)
                operation["x-agenthub-access"] = access.classification
                if access.classification == "public":
                    operation["security"] = []
                elif path == "/v1/relay/mcp/call":
                    operation["security"] = [
                        {"BearerAuth": []},
                        {"AgentCredentialAuth": []},
                        {"DelegationTokenAuth": []},
                    ]
                else:
                    operation["security"] = [
                        {"ApiKeyAuth": []},
                        {"BearerAuth": []},
                        {"AgentCredentialAuth": []},
                        {"DelegationTokenAuth": []},
                    ]

        schema["x-agenthub-production-ready"] = False
        schema["x-agenthub-deployment-boundary"] = (
            "single-process SQLite development deployment"
        )
        app.openapi_schema = schema
        return schema

    app.openapi = build_schema
