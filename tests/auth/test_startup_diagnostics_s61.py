from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import app
from src.api.startup_diagnostics import build_startup_diagnostics


def test_startup_diagnostics_reports_missing_and_invalid_fields() -> None:
    payload = build_startup_diagnostics(
        {
            "AGENTHUB_API_KEYS_JSON": "{bad-json",
            "AGENTHUB_AUTH_TOKEN_SECRET": "",
            "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": "{}",
        }
    )
    assert payload["startup_ready"] is False
    checks = {row["env_var"]: row for row in payload["checks"]}
    assert checks["AGENTHUB_API_KEYS_JSON"]["valid"] is False
    assert checks["AGENTHUB_API_KEYS_JSON"]["message"] == "environment variable must be valid JSON"
    assert checks["AGENTHUB_AUTH_TOKEN_SECRET"]["valid"] is False
    assert checks["AGENTHUB_PROVENANCE_SIGNING_SECRET"]["present"] is False
    assert "AGENTHUB_PROVENANCE_SIGNING_SECRET" in payload["missing_or_invalid"]
    assert checks["AGENTHUB_API_KEYS_JSON"]["severity"] == "critical"
    assert payload["summary"]["check_failures"] >= 1
    assert payload["overall_ready"] is False


def test_startup_diagnostics_endpoint_admin_access() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/system/startup-diagnostics", headers={"X-API-Key": "platform-owner-key"})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["startup_ready"] is True
    assert payload["overall_ready"] is True
    assert payload["summary"]["check_failures"] == 0
    assert payload["access_enforcement_mode"] == "enforce"
    assert sorted(payload["required_env_vars"]) == sorted(
        [
            "AGENTHUB_API_KEYS_JSON",
            "AGENTHUB_AUTH_TOKEN_SECRET",
            "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
            "AGENTHUB_POLICY_SIGNING_SECRET",
            "AGENTHUB_PROVENANCE_SIGNING_SECRET",
        ]
    )
    assert all(row["valid"] is True for row in payload["checks"])


def test_startup_diagnostics_reports_probe_failures() -> None:
    payload = build_startup_diagnostics(
        {
            "AGENTHUB_API_KEYS_JSON": '{"dev-owner-key":"owner-dev"}',
            "AGENTHUB_AUTH_TOKEN_SECRET": "ok-secret",
            "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": '{"partner-east":"token"}',
            "AGENTHUB_POLICY_SIGNING_SECRET": "ok-policy-secret",
            "AGENTHUB_PROVENANCE_SIGNING_SECRET": "ok-provenance-secret",
            "AGENTHUB_REGISTRY_DB_PATH": "/dev/null/registry.db",
        }
    )
    assert payload["startup_ready"] is True
    assert payload["overall_ready"] is False
    assert "AGENTHUB_REGISTRY_DB_PATH" in payload["probe_failures"]
    assert payload["summary"]["probe_failures"] >= 1
    failed_probe = next(row for row in payload["probes"] if row["probe"] == "AGENTHUB_REGISTRY_DB_PATH")
    assert failed_probe["severity"] == "high"


def test_startup_diagnostics_endpoint_blocks_non_admin() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/system/startup-diagnostics", headers={"X-API-Key": "partner-owner-key"})
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["code"] == "auth.admin_required"


def test_startup_diagnostics_endpoint_requires_auth() -> None:
    with TestClient(app) as client:
        response = client.get("/v1/system/startup-diagnostics")
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["code"] == "auth.required"
