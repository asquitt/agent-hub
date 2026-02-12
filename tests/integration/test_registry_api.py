from __future__ import annotations

import statistics
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.eval import storage
from src.eval.runner import run_tier1_eval

ROOT = Path(__file__).resolve().parents[2]
VALID_MANIFEST_PATH = ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml"
INVALID_MANIFEST_PATH = ROOT / "tests" / "manifest" / "fixtures" / "invalid" / "invalid-semver.yaml"


@pytest.fixture(autouse=True)
def reset_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    STORE.namespaces.clear()
    STORE.agents.clear()
    STORE.idempotency_cache.clear()
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "results.json"))


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def register_default_agent(client: TestClient, version: str = "1.0.0") -> str:
    manifest = load_yaml(VALID_MANIFEST_PATH)
    manifest["identity"]["version"] = version
    response = client.post(
        "/v1/agents",
        json={"namespace": "@demo", "manifest": manifest},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": f"create-{version}"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_healthz() -> None:
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_registration_and_listing_flow(client: TestClient) -> None:
    agent_id = register_default_agent(client)

    list_response = client.get("/v1/agents")
    assert list_response.status_code == 200
    data = list_response.json()["data"]
    assert len(data) == 1
    assert data[0]["id"] == agent_id

    get_response = client.get(f"/v1/agents/{agent_id}")
    assert get_response.status_code == 200
    assert get_response.json()["latest_version"] == "1.0.0"


def test_manifest_validation_rejects_invalid_manifest(client: TestClient) -> None:
    invalid_manifest = load_yaml(INVALID_MANIFEST_PATH)
    response = client.post(
        "/v1/agents",
        json={"namespace": "@demo", "manifest": invalid_manifest},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "create-invalid"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "manifest validation failed"
    assert any("identity.version" in err for err in detail["errors"])


def test_permissions_enforced_for_update_and_delete(client: TestClient) -> None:
    agent_id = register_default_agent(client)

    updated_manifest = load_yaml(VALID_MANIFEST_PATH)
    updated_manifest["identity"]["version"] = "1.0.1"

    unauthorized_update = client.put(
        f"/v1/agents/{agent_id}",
        json={"manifest": updated_manifest},
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "update-1"},
    )
    assert unauthorized_update.status_code == 403

    unauthorized_delete = client.delete(
        f"/v1/agents/{agent_id}",
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "delete-1"},
    )
    assert unauthorized_delete.status_code == 403


def test_versioning_endpoints(client: TestClient) -> None:
    agent_id = register_default_agent(client, version="1.0.0")

    updated_manifest = load_yaml(VALID_MANIFEST_PATH)
    updated_manifest["identity"]["version"] = "1.1.0"

    put_response = client.put(
        f"/v1/agents/{agent_id}",
        json={"manifest": updated_manifest},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "update-1.1.0"},
    )
    assert put_response.status_code == 200

    versions_response = client.get(f"/v1/agents/{agent_id}/versions")
    assert versions_response.status_code == 200
    versions = [v["version"] for v in versions_response.json()["versions"]]
    assert versions == ["1.0.0", "1.1.0"]

    get_version_response = client.get(f"/v1/agents/{agent_id}/versions/1.1.0")
    assert get_version_response.status_code == 200
    assert get_version_response.json()["manifest"]["identity"]["version"] == "1.1.0"


def test_namespace_listing(client: TestClient) -> None:
    agent_id = register_default_agent(client)
    ns_response = client.get("/v1/namespaces/@demo")
    assert ns_response.status_code == 200
    assert ns_response.json()["data"][0]["id"] == agent_id


def test_d02_query_scenarios_relevance(client: TestClient) -> None:
    # Q01
    q01 = client.post(
        "/v1/capabilities/search",
        json={
            "query": "extract invoice totals",
            "filters": {"min_trust_score": 0.8, "max_cost_usd": 0.02, "allowed_protocols": ["MCP"]},
            "pagination": {"mode": "offset", "offset": 0, "limit": 10},
        },
    )
    assert q01.status_code == 200
    assert q01.json()["data"][0]["capability_id"] == "summarize-invoice"

    # Q02
    q02 = client.post(
        "/v1/capabilities/search",
        json={
            "query": "classify support ticket severity",
            "filters": {"max_latency_ms": 100, "min_trust_score": 0.8},
            "pagination": {"mode": "offset", "offset": 0, "limit": 10},
        },
    )
    assert q02.status_code == 200
    assert any(item["capability_id"] == "classify-ticket" for item in q02.json()["data"])

    # Q03
    q03 = client.post(
        "/v1/capabilities/search",
        json={
            "query": "execute payment",
            "filters": {"required_permissions": ["payments.execute"], "min_trust_score": 0.9},
            "pagination": {"mode": "offset", "offset": 0, "limit": 10},
        },
    )
    assert q03.status_code == 200
    assert q03.json()["data"][0]["capability_id"] == "execute-payment"

    # Q04
    q04 = client.post(
        "/v1/capabilities/match",
        json={
            "input_schema": {"type": "object", "required": ["invoice_text"]},
            "output_schema": {"type": "object", "required": ["vendor", "total", "due_date"]},
            "filters": {"compatibility_mode": "exact"},
        },
    )
    assert q04.status_code == 200
    assert q04.json()["data"][0]["compatibility"] == "exact"

    # Q05
    q05 = client.post(
        "/v1/capabilities/match",
        json={
            "input_schema": {"type": "object", "required": ["invoice_text"]},
            "output_schema": {"type": "object", "required": ["vendor", "total"]},
            "filters": {"compatibility_mode": "backward_compatible"},
        },
    )
    assert q05.status_code == 200
    assert any(item["capability_id"] == "summarize-invoice" for item in q05.json()["data"])

    # Q06
    q06 = client.get("/v1/agents/support-orchestrator/capabilities")
    assert q06.status_code == 200
    assert {c["capability_id"] for c in q06.json()["capabilities"]} == {"classify-ticket", "apply-remediation"}

    # Q07
    q07 = client.post(
        "/v1/capabilities/recommend",
        json={
            "task_description": "complete customer onboarding with billing setup",
            "current_capability_ids": ["validate-identity", "run-policy-screening"],
            "pagination": {"mode": "offset", "offset": 0, "limit": 10},
        },
    )
    assert q07.status_code == 200
    assert q07.json()["data"][0]["capability_id"] == "provision-billing"

    # Q08
    q08 = client.post(
        "/v1/capabilities/recommend",
        json={
            "task_description": "resolve customer incidents automatically",
            "current_capability_ids": ["classify-ticket"],
            "filters": {"min_trust_score": 0.8},
            "pagination": {"mode": "offset", "offset": 0, "limit": 10},
        },
    )
    assert q08.status_code == 200
    assert any(item["capability_id"] == "apply-remediation" for item in q08.json()["data"])

    # Q09
    q09 = client.post(
        "/v1/capabilities/search",
        json={"query": "anything", "filters": {"max_latency_ms": -5}},
    )
    assert q09.status_code in (400, 422)

    # Q10
    q10 = client.post(
        "/v1/capabilities/search",
        json={"query": "provision billing", "filters": {"min_trust_score": 0.95, "max_cost_usd": 0.01}},
    )
    assert q10.status_code == 200
    assert q10.json()["data"] == []


def test_latency_p95_thresholds(client: TestClient) -> None:
    manifest = load_yaml(VALID_MANIFEST_PATH)

    write_latencies = []
    for idx in range(20):
        local_manifest = dict(manifest)
        local_manifest = yaml.safe_load(yaml.safe_dump(local_manifest))
        local_manifest["identity"]["id"] = f"invoice-summarizer-{idx}"
        local_manifest["identity"]["version"] = "1.0.0"

        start = time.perf_counter()
        response = client.post(
            "/v1/agents",
            json={"namespace": "@perf", "manifest": local_manifest},
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": f"perf-create-{idx}"},
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        write_latencies.append(elapsed_ms)
        assert response.status_code == 200

    read_latencies = []
    for _ in range(60):
        start = time.perf_counter()
        response = client.get("/v1/agents", params={"namespace": "@perf", "offset": 0, "limit": 20})
        elapsed_ms = (time.perf_counter() - start) * 1000
        read_latencies.append(elapsed_ms)
        assert response.status_code == 200

    p95_write = statistics.quantiles(write_latencies, n=100)[94]
    p95_read = statistics.quantiles(read_latencies, n=100)[94]

    assert p95_write < 500, f"p95 write too high: {p95_write:.2f}ms"
    assert p95_read < 200, f"p95 read too high: {p95_read:.2f}ms"


def test_eval_results_visible_on_agent_detail(client: TestClient) -> None:
    agent_id = register_default_agent(client, version="1.0.0")
    manifest = load_yaml(VALID_MANIFEST_PATH)
    run_tier1_eval(manifest=manifest, agent_id=agent_id, version="1.0.0")

    response = client.get(f"/v1/agents/{agent_id}")
    assert response.status_code == 200
    eval_summary = response.json()["eval_summary"]
    assert "accuracy" in eval_summary
    assert "latency_ms" in eval_summary
