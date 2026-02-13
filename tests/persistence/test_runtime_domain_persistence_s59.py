from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from src.compliance import storage as compliance_storage
from src.eval import storage as eval_storage
from src.federation import storage as federation_storage
from src.knowledge import service as knowledge_service
from src.lease import service as lease_service
from src.marketplace import storage as marketplace_storage
from src.procurement import storage as procurement_storage
from src.trust import storage as trust_storage


@pytest.fixture()
def isolated_runtime_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    paths = {
        "marketplace_listings": tmp_path / "listings.json",
        "marketplace_contracts": tmp_path / "contracts.json",
        "proc_policy_packs": tmp_path / "proc-policy-packs.json",
        "trust_usage_events": tmp_path / "trust-usage-events.json",
        "eval_results": tmp_path / "eval-results.json",
        "compliance_reports": tmp_path / "compliance-reports.json",
        "federation_audit": tmp_path / "federation-audit.json",
        "lease_db": tmp_path / "lease.db",
        "knowledge_db": tmp_path / "knowledge.db",
    }
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_LISTINGS_PATH", str(paths["marketplace_listings"]))
    monkeypatch.setenv("AGENTHUB_MARKETPLACE_CONTRACTS_PATH", str(paths["marketplace_contracts"]))
    monkeypatch.setenv("AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH", str(paths["proc_policy_packs"]))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(paths["trust_usage_events"]))
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(paths["eval_results"]))
    monkeypatch.setenv("AGENTHUB_COMPLIANCE_EVIDENCE_PATH", str(paths["compliance_reports"]))
    monkeypatch.setenv("AGENTHUB_FEDERATION_AUDIT_PATH", str(paths["federation_audit"]))
    monkeypatch.setenv("AGENTHUB_LEASE_DB_PATH", str(paths["lease_db"]))
    monkeypatch.setenv("AGENTHUB_KNOWLEDGE_DB_PATH", str(paths["knowledge_db"]))
    return paths


def _write_json(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows) + "\n", encoding="utf-8")


def test_legacy_json_bootstrap_to_sqlite_collections(isolated_runtime_paths: dict[str, Path]) -> None:
    _write_json(isolated_runtime_paths["marketplace_listings"], [{"listing_id": "lst-1", "capability_ref": "@seed:a"}])
    _write_json(isolated_runtime_paths["proc_policy_packs"], [{"pack_id": "pp-1", "buyer": "owner-partner"}])
    _write_json(isolated_runtime_paths["trust_usage_events"], [{"agent_id": "@demo:a", "success": True}])
    _write_json(isolated_runtime_paths["eval_results"], [{"agent_id": "@demo:a", "version": "1.0.0", "completed_at": "2026-01-01T00:00:00Z"}])
    _write_json(isolated_runtime_paths["compliance_reports"], [{"report_id": "rep-1", "framework": "SOC2"}])
    _write_json(isolated_runtime_paths["federation_audit"], [{"attestation_hash": "att-1", "domain_id": "partner-east"}])

    assert marketplace_storage.load("listings")[0]["listing_id"] == "lst-1"
    assert procurement_storage.load("policy_packs")[0]["pack_id"] == "pp-1"
    assert trust_storage.load("usage_events")[0]["agent_id"] == "@demo:a"
    assert eval_storage.load_results()[0]["version"] == "1.0.0"
    assert compliance_storage.load_reports()[0]["report_id"] == "rep-1"
    assert federation_storage.load_audit()[0]["attestation_hash"] == "att-1"

    # Remove legacy files and confirm data remains available from SQLite.
    for key in (
        "marketplace_listings",
        "proc_policy_packs",
        "trust_usage_events",
        "eval_results",
        "compliance_reports",
        "federation_audit",
    ):
        isolated_runtime_paths[key].unlink()

    assert marketplace_storage.load("listings")[0]["listing_id"] == "lst-1"
    assert procurement_storage.load("policy_packs")[0]["pack_id"] == "pp-1"
    assert trust_storage.load("usage_events")[0]["agent_id"] == "@demo:a"
    assert eval_storage.load_results()[0]["version"] == "1.0.0"
    assert compliance_storage.load_reports()[0]["report_id"] == "rep-1"
    assert federation_storage.load_audit()[0]["attestation_hash"] == "att-1"


def test_lease_and_knowledge_state_is_durable(isolated_runtime_paths: dict[str, Path]) -> None:
    lease_service.reset_state_for_tests()
    knowledge_service.reset_state_for_tests()

    lease = lease_service.create_lease(
        requester_agent_id="@demo:invoice-summarizer",
        capability_ref="@seed:data-normalizer/normalize-records",
        owner="owner-dev",
        ttl_seconds=600,
    )
    entry = knowledge_service.contribute_entry(
        owner="owner-dev",
        title="Triage checklist",
        content="Use deterministic incident checklists and attach provenance for every escalation.",
        tags=["triage", "incident"],
        source_uri="https://kb.agenthub.local/triage",
        contributor="ops-team",
        base_confidence=0.8,
    )

    lease_service_reloaded = importlib.reload(lease_service)
    knowledge_service_reloaded = importlib.reload(knowledge_service)

    loaded_lease = lease_service_reloaded.get_lease(lease["lease_id"], owner="owner-dev")
    assert loaded_lease["lease_id"] == lease["lease_id"]
    assert loaded_lease["status"] == "active"

    results = knowledge_service_reloaded.query_entries("triage provenance", limit=5)
    assert any(row["entry_id"] == entry["entry_id"] for row in results)
