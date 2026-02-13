from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.lease import service


@pytest.fixture(autouse=True)
def reset_leases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_LEASE_DB_PATH", str(tmp_path / "lease.db"))
    service.reset_state_for_tests()


def test_lease_create_and_promote_success() -> None:
    client = TestClient(app)

    lease_response = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-create-1"},
    )
    assert lease_response.status_code == 200, lease_response.text
    lease = lease_response.json()

    promote_response = client.post(
        f"/v1/capabilities/leases/{lease['lease_id']}/promote",
        json={
            "attestation_hash": lease["attestation_hash"],
            "signature": f"sig:{lease['attestation_hash']}:owner-dev",
            "policy_approved": True,
            "approval_ticket": "APR-1001",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-promote-1"},
    )
    assert promote_response.status_code == 200, promote_response.text
    promoted = promote_response.json()
    assert promoted["status"] == "promoted"
    assert promoted["promotion"]["installed_ref"].startswith("@demo:invoice-summarizer::")
    assert promoted["policy_decision"]["decision"] == "allow"


def test_lease_permission_boundary_blocks_other_owner_promote() -> None:
    client = TestClient(app)

    lease_response = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-create-2"},
    )
    lease = lease_response.json()

    blocked = client.post(
        f"/v1/capabilities/leases/{lease['lease_id']}/promote",
        json={
            "attestation_hash": lease["attestation_hash"],
            "signature": f"sig:{lease['attestation_hash']}:owner-partner",
            "policy_approved": True,
            "approval_ticket": "APR-1002",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s17-lease-promote-blocked"},
    )
    assert blocked.status_code == 403


def test_lease_ttl_expiry_blocks_promotion() -> None:
    client = TestClient(app)
    ticks = itertools.count(start=1_000_000, step=2)

    def fake_now() -> int:
        return next(ticks)

    original_now = service._now_epoch
    service._now_epoch = fake_now
    try:
        lease_response = client.post(
            "/v1/capabilities/lease",
            json={
                "requester_agent_id": "@demo:invoice-summarizer",
                "capability_ref": "@seed:data-normalizer/normalize-records",
                "ttl_seconds": 1,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-create-3"},
        )
        assert lease_response.status_code == 200
        lease = lease_response.json()

        expired = client.post(
            f"/v1/capabilities/leases/{lease['lease_id']}/promote",
            json={
                "attestation_hash": lease["attestation_hash"],
                "signature": f"sig:{lease['attestation_hash']}:owner-dev",
                "policy_approved": True,
                "approval_ticket": "APR-1003",
                "compatibility_verified": True,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-promote-expired"},
        )
        assert expired.status_code == 400
        assert "expired" in expired.json()["detail"]
    finally:
        service._now_epoch = original_now


def test_lease_promotion_requires_policy_approval() -> None:
    client = TestClient(app)
    lease_response = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-create-4"},
    )
    lease = lease_response.json()

    denied = client.post(
        f"/v1/capabilities/leases/{lease['lease_id']}/promote",
        json={
            "attestation_hash": lease["attestation_hash"],
            "signature": f"sig:{lease['attestation_hash']}:owner-dev",
            "policy_approved": False,
            "approval_ticket": "APR-1004",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-promote-denied"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["policy_decision"]["decision"] == "deny"
    assert "approval.policy_required" in detail["policy_decision"]["violated_constraints"]


def test_lease_promotion_requires_compatibility_and_supports_rollback() -> None:
    client = TestClient(app)
    lease_response = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@demo:invoice-summarizer",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-create-5"},
    )
    lease = lease_response.json()

    blocked = client.post(
        f"/v1/capabilities/leases/{lease['lease_id']}/promote",
        json={
            "attestation_hash": lease["attestation_hash"],
            "signature": f"sig:{lease['attestation_hash']}:owner-dev",
            "policy_approved": True,
            "approval_ticket": "APR-1005",
            "compatibility_verified": False,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-promote-compat-block"},
    )
    assert blocked.status_code == 403

    promoted = client.post(
        f"/v1/capabilities/leases/{lease['lease_id']}/promote",
        json={
            "attestation_hash": lease["attestation_hash"],
            "signature": f"sig:{lease['attestation_hash']}:owner-dev",
            "policy_approved": True,
            "approval_ticket": "APR-1006",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-promote-2"},
    )
    assert promoted.status_code == 200
    install_id = promoted.json()["promotion"]["install_id"]

    rollback = client.post(
        f"/v1/capabilities/installs/{install_id}/rollback",
        json={"reason": "compatibility regression"},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s17-lease-rollback-1"},
    )
    assert rollback.status_code == 200
    assert rollback.json()["status"] == "rolled_back"
