from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.identity.jwt_tokens import verify_jwt
from src.identity.oauth_clients import OAUTH_CLIENT_STORE
from src.registry.store import STORE


BASE_URL = "https://agenthub.test"
MCP_RESOURCE = f"{BASE_URL}/mcp"
MCP_ACCEPT = "application/json, text/event-stream"
MCP_VERSION = "2025-11-25"


@pytest.fixture(autouse=True)
def isolate_protocol_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    original_registry_db = STORE.db_path
    identity_db = tmp_path / "identity.db"
    registry_db = tmp_path / "registry.db"

    monkeypatch.setenv("AGENTHUB_BASE_URL", BASE_URL)
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(identity_db))
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "s164-mcp-signing-secret-at-least-32-bytes")
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(tmp_path / "billing.db"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_MCP_ALLOWED_ORIGINS_JSON", json.dumps(["https://client.example"]))
    monkeypatch.setenv(
        "AGENTHUB_API_KEYS_JSON",
        json.dumps(
            {
                "platform-key": {
                    "owner": "owner-platform",
                    "scopes": ["*"],
                    "roles": ["admin"],
                },
                "mcp-registrar-key": {
                    "owner": "owner-mcp",
                    "scopes": ["oauth.register", "discovery.read", "discovery.search"],
                    "roles": ["member"],
                },
            }
        ),
    )
    monkeypatch.setenv(
        "AGENTHUB_OWNER_TENANTS_JSON",
        json.dumps({"owner-platform": ["*"], "owner-mcp": ["tenant-a"]}),
    )

    OAUTH_CLIENT_STORE.reset_for_tests(db_path=identity_db)
    STORE.reset_for_tests(db_path=registry_db)
    STORE.reserve_namespace("@tenant-b", "owner-platform", tenant_id="tenant-b")
    STORE.register_agent(
        "@tenant-b",
        {
            "identity": {"id": "private-agent", "name": "Private Agent", "version": "1.0.0"},
            "capabilities": [],
        },
        "owner-platform",
        tenant_id="tenant-b",
    )

    yield

    STORE.reconfigure(db_path=original_registry_db)


def _oauth_registration(
    client: TestClient,
    *,
    scope: str = "discovery.read discovery.search",
) -> dict[str, Any]:
    response = client.post(
        "/v1/oauth/register",
        json={
            "client_name": "MCP discovery client",
            "grant_types": ["client_credentials"],
            "scope": scope,
        },
        headers={"X-API-Key": "mcp-registrar-key", "X-Tenant-ID": "tenant-a"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _oauth_token(
    client: TestClient,
    registration: dict[str, Any],
    *,
    resource: str | None,
    scope: str = "discovery.read discovery.search",
) -> Any:
    form = {
        "grant_type": "client_credentials",
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "scope": scope,
    }
    if resource is not None:
        form["resource"] = resource
    return client.post("/v1/oauth/token", data=form)


def _mcp_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": "tenant-a",
        "Origin": "https://client.example",
        "Accept": MCP_ACCEPT,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MCP_VERSION,
    }


def _rpc(method: str, *, request_id: int | str | None = 1, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return message


def _initialize() -> dict[str, Any]:
    return _rpc(
        "initialize",
        params={
            "protocolVersion": MCP_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agenthub-test-client", "version": "1.0.0"},
        },
    )


def _official_sdk_initialize() -> dict[str, Any]:
    return _rpc(
        "initialize",
        params={
            "protocolVersion": MCP_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp", "version": "0.1.0"},
            "_meta": {},
        },
    )


def test_mcp_auth_discovery_and_resource_bound_oauth() -> None:
    with TestClient(app) as client:
        prm = client.get("/.well-known/oauth-protected-resource")
        metadata = client.get("/.well-known/oauth-authorization-server")
        unsupported_authorize = client.get(
            "/v1/oauth/authorize",
            params={"response_type": "code", "client_id": "not-supported"},
        )
        unauthenticated = client.post(
            "/mcp",
            json=_initialize(),
            headers={"Accept": MCP_ACCEPT, "Origin": "https://client.example"},
        )

        registration = _oauth_registration(client)
        targeted = _oauth_token(client, registration, resource=MCP_RESOURCE)
        invalid_target = _oauth_token(client, registration, resource="https://attacker.example/mcp")
        untargeted = _oauth_token(client, registration, resource=None)

    assert prm.status_code == 200
    assert prm.json()["resource"] == MCP_RESOURCE
    assert prm.json()["authorization_servers"] == [BASE_URL]
    assert metadata.status_code == 200
    assert metadata.json()["issuer"] == prm.json()["authorization_servers"][0]
    assert metadata.json()["authorization_endpoint"] == f"{BASE_URL}/v1/oauth/authorize"
    assert metadata.json()["token_endpoint"] == f"{BASE_URL}/v1/oauth/token"
    assert metadata.json()["response_types_supported"] == []
    assert unsupported_authorize.status_code == 400
    assert unsupported_authorize.json()["detail"]["error"] == "unsupported_response_type"

    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource", '
        'scope="discovery.read discovery.search"'
    )

    assert targeted.status_code == 200, targeted.text
    claims = verify_jwt(
        targeted.json()["access_token"],
        audience=MCP_RESOURCE,
        issuer=metadata.json()["issuer"],
    )
    assert claims["aud"] == MCP_RESOURCE
    assert claims["scopes"] == ["discovery.read", "discovery.search"]

    assert invalid_target.status_code == 400
    assert invalid_target.json()["detail"]["error"] == "invalid_target"
    assert "access_token" not in invalid_target.json()

    assert untargeted.status_code == 200
    untargeted_token = untargeted.json()["access_token"]
    with TestClient(app) as client:
        denied = client.post("/mcp", json=_initialize(), headers=_mcp_headers(untargeted_token))
    assert denied.status_code == 401


def test_mcp_lifecycle_and_real_discovery_tool_calls() -> None:
    with TestClient(app) as client:
        registration = _oauth_registration(client)
        token_response = _oauth_token(client, registration, resource=MCP_RESOURCE)
        token = token_response.json()["access_token"]
        headers = _mcp_headers(token)

        initialized = client.post("/mcp", json=_initialize(), headers=headers)
        official_sdk_initialized = client.post(
            "/mcp",
            json=_official_sdk_initialize(),
            headers=headers,
        )
        notification = client.post(
            "/mcp",
            json=_rpc("notifications/initialized", request_id=None),
            headers=headers,
        )
        tools = client.post("/mcp", json=_rpc("tools/list", request_id="tools"), headers=headers)
        search = client.post(
            "/mcp",
            json=_rpc(
                "tools/call",
                request_id="search",
                params={
                    "name": "search_capabilities",
                    "arguments": {
                        "query": "extract invoice totals",
                        "constraints": {"max_cost_usd": 0.02, "min_trust_score": 0.8},
                    },
                    "_meta": {},
                },
            ),
            headers=headers,
        )
        cross_tenant_manifest = client.post(
            "/mcp",
            json=_rpc(
                "tools/call",
                request_id="manifest",
                params={
                    "name": "get_agent_manifest",
                    "arguments": {"agent_id": "@tenant-b:private-agent"},
                },
            ),
            headers=headers,
        )

    assert initialized.status_code == 200, initialized.text
    assert initialized.headers["mcp-protocol-version"] == MCP_VERSION
    assert initialized.json() == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": MCP_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "agenthub-discovery",
                "version": "0.1.0",
                "description": "Policy-governed AgentHub capability discovery.",
            },
            "instructions": "Use tools to discover and inspect policy-compliant agent capabilities.",
        },
    }
    assert official_sdk_initialized.status_code == 200, official_sdk_initialized.text
    assert official_sdk_initialized.json()["result"]["protocolVersion"] == MCP_VERSION

    assert notification.status_code == 202
    assert notification.content == b""

    assert tools.status_code == 200
    names = {tool["name"] for tool in tools.json()["result"]["tools"]}
    assert names == {"search_capabilities", "get_agent_manifest", "check_compatibility"}

    assert search.status_code == 200, search.text
    search_result = search.json()["result"]
    assert search_result["isError"] is False
    assert search_result["structuredContent"]["data"]
    assert search_result["structuredContent"]["policy_decision"]["decision"] == "allow"
    assert json.loads(search_result["content"][0]["text"]) == search_result["structuredContent"]

    assert cross_tenant_manifest.status_code == 200
    manifest_result = cross_tenant_manifest.json()["result"]
    assert manifest_result["isError"] is True
    assert manifest_result["content"] == [{"type": "text", "text": "agent not found"}]
    assert "structuredContent" not in manifest_result


def test_mcp_transport_and_input_fail_closed() -> None:
    with TestClient(app) as client:
        registration = _oauth_registration(client)
        token = _oauth_token(client, registration, resource=MCP_RESOURCE).json()["access_token"]
        headers = _mcp_headers(token)

        invalid_origin = client.post(
            "/mcp",
            json=_initialize(),
            headers={**headers, "Origin": "https://attacker.example"},
        )
        invalid_origin_without_auth = client.post(
            "/mcp",
            json=_initialize(),
            headers={"Accept": MCP_ACCEPT, "Origin": "https://attacker.example"},
        )
        invalid_version = client.post(
            "/mcp",
            json=_rpc("tools/list"),
            headers={**headers, "MCP-Protocol-Version": "1900-01-01"},
        )
        wildcard_accept = client.post(
            "/mcp",
            json=_initialize(),
            headers={**headers, "Accept": "*/*"},
        )
        jsonp_content_type = client.post(
            "/mcp",
            content=json.dumps(_initialize()),
            headers={**headers, "Content-Type": "application/jsonp"},
        )
        malformed = client.post("/mcp", json={"jsonrpc": "1.0", "id": 2}, headers=headers)
        malformed_initialize = client.post(
            "/mcp",
            json=_rpc(
                "initialize",
                request_id=3,
                params={"protocolVersion": MCP_VERSION, "capabilities": {}, "clientInfo": {}},
            ),
            headers=headers,
        )
        boolean_id = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": True, "method": "ping"},
            headers=headers,
        )
        unknown_tool = client.post(
            "/mcp",
            json=_rpc("tools/call", params={"name": "delete_everything", "arguments": {}}),
            headers=headers,
        )
        invalid_arguments = client.post(
            "/mcp",
            json=_rpc(
                "tools/call",
                params={"name": "search_capabilities", "arguments": {"query": "x", "secret": "do-not-echo"}},
            ),
            headers=headers,
        )
        get_response = client.get("/mcp", headers=headers)
        delete_response = client.delete("/mcp", headers=headers)
        invalid_origin_get = client.get("/mcp", headers={**headers, "Origin": "https://attacker.example"})

    assert invalid_origin.status_code == 403
    assert invalid_origin_without_auth.status_code == 403
    assert invalid_version.status_code == 400
    assert wildcard_accept.status_code == 406
    assert jsonp_content_type.status_code == 415
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == -32600
    assert malformed_initialize.status_code == 200
    assert malformed_initialize.json()["error"]["code"] == -32602
    assert boolean_id.status_code == 400
    assert boolean_id.json()["error"]["code"] == -32600
    assert unknown_tool.status_code == 200
    assert unknown_tool.json()["error"] == {"code": -32602, "message": "Unknown tool: delete_everything"}

    assert invalid_arguments.status_code == 200
    tool_error = invalid_arguments.json()["result"]
    assert tool_error["isError"] is True
    assert tool_error["content"] == [{"type": "text", "text": "invalid tool arguments"}]
    assert "do-not-echo" not in invalid_arguments.text

    assert get_response.status_code == 405
    assert delete_response.status_code == 405
    assert invalid_origin_get.status_code == 403


def test_mcp_rejects_non_finite_tool_constraints_without_http_500() -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        registration = _oauth_registration(client)
        token = _oauth_token(client, registration, resource=MCP_RESOURCE).json()["access_token"]
        response = client.post(
            "/mcp",
            content=(
                '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
                '{"name":"search_capabilities","arguments":{"query":"invoice",'
                '"constraints":{"max_cost_usd":1e309}}}}'
            ),
            headers=_mcp_headers(token),
        )

    assert response.status_code == 200
    assert response.json()["result"] == {
        "content": [{"type": "text", "text": "invalid tool arguments"}],
        "isError": True,
    }


def test_mcp_tools_are_filtered_and_enforced_by_oauth_scope() -> None:
    with TestClient(app) as client:
        registration = _oauth_registration(client, scope="discovery.read")
        token = _oauth_token(
            client,
            registration,
            resource=MCP_RESOURCE,
            scope="discovery.read",
        ).json()["access_token"]
        headers = _mcp_headers(token)
        tools = client.post("/mcp", json=_rpc("tools/list"), headers=headers)
        denied_search = client.post(
            "/mcp",
            json=_rpc(
                "tools/call",
                params={"name": "search_capabilities", "arguments": {"query": "invoice"}},
            ),
            headers=headers,
        )

    assert {row["name"] for row in tools.json()["result"]["tools"]} == {"get_agent_manifest"}
    assert denied_search.json()["result"] == {
        "content": [{"type": "text", "text": "insufficient scope"}],
        "isError": True,
    }


def test_mcp_targeted_oauth_token_cannot_replay_to_generic_api() -> None:
    with TestClient(app) as client:
        registration = _oauth_registration(client)
        targeted_token = _oauth_token(client, registration, resource=MCP_RESOURCE).json()["access_token"]
        replay = client.get(
            "/v1/discovery/mcp-tools",
            headers={"Authorization": f"Bearer {targeted_token}", "X-Tenant-ID": "tenant-a"},
        )

    assert replay.status_code == 401


def test_mcp_resource_boundary_rejects_agent_jwt_and_generic_bearer_replay() -> None:
    with TestClient(app) as client:
        registered = client.post(
            "/v1/identity/agents",
            json={"agent_id": "resource-bound-agent"},
            headers={"X-API-Key": "platform-key", "X-Tenant-ID": "tenant-a"},
        )
        assert registered.status_code == 200, registered.text
        agent_token_response = client.post(
            "/v1/identity/tokens/jwt",
            json={
                "agent_id": "resource-bound-agent",
                "audience": MCP_RESOURCE,
                "scopes": ["discovery.read", "discovery.search"],
            },
            headers={"X-API-Key": "platform-key", "X-Tenant-ID": "tenant-a"},
        )
        assert agent_token_response.status_code == 200, agent_token_response.text
        agent_token = agent_token_response.json()["token"]

        generic_token_response = client.post(
            "/v1/auth/tokens",
            json={"scopes": ["discovery.search"], "ttl_seconds": 300},
            headers={"X-API-Key": "platform-key", "X-Tenant-ID": "tenant-a"},
        )
        assert generic_token_response.status_code == 200, generic_token_response.text
        generic_token = generic_token_response.json()["access_token"]

        agent_replay = client.get(
            "/v1/discovery/mcp-tools",
            headers={"Authorization": f"Bearer {agent_token}", "X-Tenant-ID": "tenant-a"},
        )
        generic_replay = client.post(
            "/mcp",
            json=_initialize(),
            headers=_mcp_headers(generic_token),
        )

    assert agent_replay.status_code == 401
    assert generic_replay.status_code == 401


def test_mcp_advertised_schema_matches_nested_runtime_validation() -> None:
    with TestClient(app) as client:
        registration = _oauth_registration(client)
        token = _oauth_token(client, registration, resource=MCP_RESOURCE).json()["access_token"]
        headers = _mcp_headers(token)
        tools = client.post("/mcp", json=_rpc("tools/list"), headers=headers)
        search_tool = next(
            tool for tool in tools.json()["result"]["tools"] if tool["name"] == "search_capabilities"
        )
        arguments = {"query": "invoice", "constraints": {"unknown": "accepted-by-loose-schema"}}

        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(arguments, search_tool["inputSchema"])

        rejected = client.post(
            "/mcp",
            json=_rpc(
                "tools/call",
                params={"name": "search_capabilities", "arguments": arguments},
            ),
            headers=headers,
        )

    assert rejected.status_code == 200
    assert rejected.json()["result"]["isError"] is True
    assert rejected.json()["result"]["content"] == [
        {"type": "text", "text": "invalid tool arguments"}
    ]
