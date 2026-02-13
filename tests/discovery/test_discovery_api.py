from __future__ import annotations

import statistics
import time

from fastapi.testclient import TestClient

from src.api.app import app


client = TestClient(app)
HEADERS = {"X-API-Key": "dev-owner-key"}


def test_discovery_search_cost_constraint_optimization() -> None:
    response = client.post(
        "/v1/discovery/search",
        json={
            "query": "extract invoice totals",
            "constraints": {"max_cost_usd": 0.02, "min_trust_score": 0.8},
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    data = response.json()["data"]
    policy = response.json()["policy_decision"]
    assert data
    assert all(item["estimated_cost_usd"] <= 0.02 for item in data)
    assert "cost_optimized_score" in data[0]
    assert policy["decision"] == "allow"


def test_contract_match_and_compatibility_cached_sla() -> None:
    contract_lat = []
    compat_lat = []

    for _ in range(120):
        t = time.perf_counter()
        r1 = client.post(
            "/v1/discovery/contract-match",
            json={
                "input_schema": {"type": "object", "required": ["invoice_text"]},
                "output_schema": {"type": "object", "required": ["vendor", "total"]},
                "constraints": {"max_cost_usd": 0.03},
            },
            headers=HEADERS,
        )
        contract_lat.append((time.perf_counter() - t) * 1000)
        assert r1.status_code == 200
        assert r1.json()["data"]
        assert r1.json()["policy_decision"]["decision"] == "allow"

        t = time.perf_counter()
        r2 = client.post(
            "/v1/discovery/compatibility",
            json={
                "my_schema": {"type": "object", "required": ["ticket_text", "account_id", "action"]},
                "agent_id": "support-orchestrator",
            },
            headers=HEADERS,
        )
        compat_lat.append((time.perf_counter() - t) * 1000)
        assert r2.status_code == 200
        assert r2.json()["capability_reports"]
        assert r2.json()["policy_decision"]["decision"] == "allow"

    p95_contract = statistics.quantiles(contract_lat, n=100)[94]
    p95_compat = statistics.quantiles(compat_lat, n=100)[94]

    assert p95_contract < 100, f"contract path p95 too high: {p95_contract:.3f}ms"
    assert p95_compat < 100, f"compat path p95 too high: {p95_compat:.3f}ms"


def test_semantic_discovery_sla() -> None:
    latencies = []
    for _ in range(180):
        t = time.perf_counter()
        response = client.post(
            "/v1/discovery/search",
            json={"query": "classify support incidents", "constraints": {"min_trust_score": 0.8}},
            headers=HEADERS,
        )
        latencies.append((time.perf_counter() - t) * 1000)
        assert response.status_code == 200
        assert response.json()["policy_decision"]["decision"] == "allow"

    p95 = statistics.quantiles(latencies, n=100)[94]
    assert p95 < 300, f"semantic discovery p95 too high: {p95:.3f}ms"


def test_mcp_tools_and_a2a_agent_card() -> None:
    tools = client.get("/v1/discovery/mcp-tools", headers=HEADERS)
    assert tools.status_code == 200
    names = {tool["name"] for tool in tools.json()["tools"]}
    assert names == {"search_capabilities", "get_agent_manifest", "check_compatibility"}

    card = client.get("/.well-known/agent-card.json")
    assert card.status_code == 200
    payload = card.json()
    assert payload["id"] == "agenthub-discovery-service"
    assert payload["meta"]["service_tier"] == "agent-native"


def test_discovery_policy_denies_malformed_constraints() -> None:
    response = client.post(
        "/v1/discovery/search",
        json={
            "query": "invoice",
            "constraints": {"allowed_protocols": ["SOAP"], "required_permissions": ["payments.*"]},
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["data"] == []
    assert payload["policy_decision"]["decision"] == "deny"
