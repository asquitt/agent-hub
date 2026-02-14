from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.access_policy import access_mode
from src.api.app import app
from src.cost_governance import storage as cost_storage
from src.federation.gateway import validate_federation_configuration
from src.provenance.service import validate_provenance_configuration


@pytest.fixture(autouse=True)
def isolate_marketplace_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    billing_db = tmp_path / "billing.db"
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(tmp_path / "listings.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(tmp_path / "contracts.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_DISPUTES_PATH", str(tmp_path / "disputes.json"))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_PAYOUTS_PATH", str(tmp_path / "payouts.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(tmp_path / "proc-policy-packs.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_APPROVALS_PATH", str(tmp_path / "proc-approvals.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_EXCEPTIONS_PATH", str(tmp_path / "proc-exceptions.json"))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_AUDIT_PATH", str(tmp_path / "proc-audit.json"))
    monkeypatch.setenv("AGENTHUB_COST_EVENTS_PATH", str(tmp_path / "cost-events.json"))
    monkeypatch.setenv("AGENTHUB_COST_DB_PATH", str(billing_db))
    monkeypatch.setenv("AGENTHUB_BILLING_DB_PATH", str(billing_db))
    cost_storage.reset_for_tests(db_path=billing_db)


def test_access_mode_defaults_to_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", raising=False)
    assert access_mode() == "enforce"


def test_procurement_purchase_denies_when_policy_pack_missing() -> None:
    with TestClient(app) as client:
        listing = client.post(
            "/v1/marketplace/listings",
            json={
                "capability_ref": "@seed:data-normalizer/normalize-records",
                "unit_price_usd": 0.5,
                "max_units_per_purchase": 10,
                "policy_purchase_limit_usd": 3.0,
            },
            headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": "s60-listing-create"},
        )
        assert listing.status_code == 200

        purchase = client.post(
            "/v1/marketplace/purchase",
            json={
                "listing_id": listing.json()["listing_id"],
                "units": 2,
                "max_total_usd": 2.0,
                "policy_approved": True,
            },
            headers={"X-API-Key": "partner-owner-key", "Idempotency-Key": "s60-purchase-deny"},
        )
        assert purchase.status_code == 403
        assert "policy pack required" in str(purchase.json()["detail"])


def test_federation_configuration_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON", raising=False)
    with pytest.raises(PermissionError, match="AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON is required"):
        validate_federation_configuration()


def test_provenance_configuration_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTHUB_PROVENANCE_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="AGENTHUB_PROVENANCE_SIGNING_SECRET is required"):
        validate_provenance_configuration()


def test_policy_signing_configuration_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENTHUB_POLICY_SIGNING_SECRET", raising=False)
    from src.policy.helpers import policy_signing_secret

    with pytest.raises(RuntimeError, match="AGENTHUB_POLICY_SIGNING_SECRET env var is required"):
        policy_signing_secret()
