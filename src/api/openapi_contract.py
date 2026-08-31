from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from src.api.access_policy import classify_route

Maturity = str

_PROTOTYPE_PATHS = frozenset(
    {
        "/",
        "/.well-known/agent-card.json",
        "/.well-known/agent.json",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/customer",
        "/healthz",
        "/mcp",
        "/operator",
        "/operator/versioning",
        "/readyz",
    }
)

_PROTOTYPE_PREFIXES = (
    "/scim/v2",
    "/v1/a2a",
    "/v1/access-review",
    "/v1/activity",
    "/v1/agents",
    "/v1/approval",
    "/v1/audit",
    "/v1/auth",
    "/v1/capabilities",
    "/v1/chain-viz",
    "/v1/compliance",
    "/v1/consents",
    "/v1/cost",
    "/v1/credential-bindings",
    "/v1/devhub",
    "/v1/discovery",
    "/v1/entitlements",
    "/v1/environments",
    "/v1/eval",
    "/v1/federation",
    "/v1/grants",
    "/v1/groups",
    "/v1/identity",
    "/v1/intent",
    "/v1/ip-rules",
    "/v1/keys",
    "/v1/knowledge",
    "/v1/namespaces",
    "/v1/oauth",
    "/v1/operator",
    "/v1/policy",
    "/v1/policy-sim",
    "/v1/provenance",
    "/v1/quotas",
    "/v1/rate-policies",
    "/v1/rbac",
    "/v1/reliability",
    "/v1/scope-narrowing",
    "/v1/sessions",
    "/v1/system",
    "/v1/threat-intel",
    "/v1/vault",
)

_DEFERRED_PREFIXES = (
    "/v1/billing",
    "/v1/marketplace",
    "/v1/procurement",
)

_PQC_BOUNDARY = (
    "deterministic HMAC and SHA3 simulation with in-memory keys; "
    "no NIST post-quantum implementation or durable key custody is proven"
)
_SPIFFE_BOUNDARY = (
    "SPIFFE-compatible identifiers and self-signed metadata only; "
    "no SPIRE workload attestation or CA-issued X.509 SVID is proven"
)
_OAUTH_AUTHORIZE_BOUNDARY = (
    "endpoint only rejects unsupported interactive grants; no authorization-code, "
    "user-consent, redirect, or PKCE flow is implemented"
)

_STUB_PATH_BOUNDARIES = {
    "/v1/identity/agents/{agent_id}/spiffe-id": _SPIFFE_BOUNDARY,
    "/v1/identity/agents/{agent_id}/svid": _SPIFFE_BOUNDARY,
    "/v1/identity/spiffe/bundle": _SPIFFE_BOUNDARY,
    "/v1/identity/spiffe/verify": _SPIFFE_BOUNDARY,
    "/v1/oauth/authorize": _OAUTH_AUTHORIZE_BOUNDARY,
}

_STUB_PREFIX_BOUNDARIES = (
    ("/v1/identity/pqc", _PQC_BOUNDARY),
    (
        "/v1/runtime",
        "local state simulation; no isolated remote workload execution is proven",
    ),
    (
        "/v1/delegations",
        "local delegation control-plane behavior; no autonomous remote execution is proven",
    ),
    (
        "/v1/federation/execute",
        "local federation simulation; no cross-domain remote execution is proven",
    ),
    (
        "/v1/audit/webhooks",
        "local webhook configuration simulation; no external delivery is proven",
    ),
    (
        "/v1/audit/deliveries",
        "local delivery-state simulation; no external webhook delivery is proven",
    ),
    (
        "/v1/audit/dead-letters",
        "local dead-letter state simulation; no external retry delivery is proven",
    ),
)


def _matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def operation_maturity(path: str) -> tuple[Maturity, str]:
    """Return an evidence-bounded implementation label for an API path."""
    if path in _STUB_PATH_BOUNDARIES:
        return "stub", _STUB_PATH_BOUNDARIES[path]
    for prefix, boundary in _STUB_PREFIX_BOUNDARIES:
        if _matches_prefix(path, prefix):
            return "stub", boundary
    if any(_matches_prefix(path, prefix) for prefix in _DEFERRED_PREFIXES):
        return (
            "deferred",
            "financial mutations are disabled pending transactional integrity proof",
        )
    if _matches_prefix(path, "/v1/relay"):
        return (
            "prototype",
            "one operator-attested, server-declared read-only MCP target is proven locally; "
            "distributed production operation is not proven",
        )
    if path in _PROTOTYPE_PATHS or any(
        _matches_prefix(path, prefix) for prefix in _PROTOTYPE_PREFIXES
    ):
        return (
            "prototype",
            "locally tested control-plane behavior; production deployment is not proven",
        )
    return (
        "stub",
        "unclassified route; no local behavior or production evidence has been accepted",
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
