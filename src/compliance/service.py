from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from src.billing.service import verify_double_entry, verify_ledger_chain
from src.compliance import storage
from src.cost_governance import storage as cost_storage
from src.federation import storage as federation_storage
from src.procurement import storage as procurement_storage
from src.provenance.service import (
    sign_artifact,
    sign_manifest,
    verify_artifact_signature,
    verify_manifest_signature,
)


CONTROL_CATALOG = [
    {
        "framework": "SOC2",
        "control_id": "SOC2-CC7.2",
        "title": "Ledger Integrity",
        "description": "Billing ledger chain and double-entry integrity remain valid.",
        "check_key": "billing_ledger_integrity",
    },
    {
        "framework": "SOC2",
        "control_id": "SOC2-CC7.3",
        "title": "Metering Event Integrity",
        "description": "Metering events are well-formed with actor/operation/timestamp metadata.",
        "check_key": "metering_schema_integrity",
    },
    {
        "framework": "SOC2",
        "control_id": "SOC2-CC6.8",
        "title": "Federation Audit Completeness",
        "description": "Federated execution events preserve attestable audit fields.",
        "check_key": "federation_audit_completeness",
    },
    {
        "framework": "SOC2",
        "control_id": "SOC2-CC6.1",
        "title": "Procurement Governance Audit",
        "description": "Procurement decisions are auditable with actor/action/outcome evidence.",
        "check_key": "procurement_audit_completeness",
    },
    {
        "framework": "SOC2",
        "control_id": "SOC2-CC6.6",
        "title": "Provenance Signature Verification",
        "description": "Manifest and artifact signatures validate and tamper checks fail closed.",
        "check_key": "provenance_signature_verification",
    },
    {
        "framework": "ISO27001",
        "control_id": "ISO27001-A.8.9",
        "title": "Configuration Integrity",
        "description": "Ledger evidence chain maintains deterministic integrity guarantees.",
        "check_key": "billing_ledger_integrity",
    },
    {
        "framework": "ISO27001",
        "control_id": "ISO27001-A.8.15",
        "title": "Logging",
        "description": "Operational metering logs contain required audit metadata.",
        "check_key": "metering_schema_integrity",
    },
    {
        "framework": "ISO27001",
        "control_id": "ISO27001-A.8.16",
        "title": "Monitoring Activities",
        "description": "Federated operations emit complete monitoring/audit records.",
        "check_key": "federation_audit_completeness",
    },
    {
        "framework": "ISO27001",
        "control_id": "ISO27001-A.5.24",
        "title": "Incident and Exception Governance",
        "description": "Procurement exception and approval actions remain auditable.",
        "check_key": "procurement_audit_completeness",
    },
    {
        "framework": "ISO27001",
        "control_id": "ISO27001-A.8.24",
        "title": "Use of Cryptography",
        "description": "Provenance signing/verification paths remain tamper-resistant.",
        "check_key": "provenance_signature_verification",
    },
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_billing_ledger_integrity() -> dict[str, Any]:
    chain = verify_ledger_chain()
    double_entry = verify_double_entry()
    passed = bool(chain.get("valid")) and bool(double_entry.get("valid"))
    return {
        "passed": passed,
        "evidence": {
            "chain_valid": bool(chain.get("valid")),
            "chain_entry_count": int(chain.get("entry_count", 0)),
            "double_entry_valid": bool(double_entry.get("valid")),
            "transaction_count": int(double_entry.get("transaction_count", 0)),
        },
    }


def _check_metering_schema_integrity() -> dict[str, Any]:
    rows = cost_storage.load_events()
    invalid = []
    for row in rows:
        if not isinstance(row, dict):
            invalid.append("row_not_object")
            continue
        if not str(row.get("timestamp", "")).strip():
            invalid.append("missing_timestamp")
        if not str(row.get("actor", "")).strip():
            invalid.append("missing_actor")
        if not str(row.get("operation", "")).strip():
            invalid.append("missing_operation")
        metadata = row.get("metadata", {})
        if not isinstance(metadata, dict):
            invalid.append("invalid_metadata")
    return {
        "passed": len(invalid) == 0,
        "evidence": {
            "event_count": len(rows),
            "invalid_count": len(invalid),
            "invalid_reasons": sorted(set(invalid)),
        },
    }


def _check_federation_audit_completeness() -> dict[str, Any]:
    rows = federation_storage.load_audit()
    required = {
        "timestamp",
        "actor",
        "domain_id",
        "attestation_hash",
        "input_hash",
        "output_hash",
        "policy_context_hash",
        "residency_region",
        "connection_mode",
    }
    invalid_count = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid_count += 1
            continue
        missing = [field for field in required if not str(row.get(field, "")).strip()]
        if missing:
            invalid_count += 1
    return {
        "passed": invalid_count == 0,
        "evidence": {
            "row_count": len(rows),
            "invalid_count": invalid_count,
            "required_fields": sorted(required),
        },
    }


def _check_procurement_audit_completeness() -> dict[str, Any]:
    rows = procurement_storage.load("audit")
    required = {"created_at", "actor", "action", "outcome"}
    invalid_count = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid_count += 1
            continue
        missing = [field for field in required if not str(row.get(field, "")).strip()]
        if missing:
            invalid_count += 1
    return {
        "passed": invalid_count == 0,
        "evidence": {
            "row_count": len(rows),
            "invalid_count": invalid_count,
            "required_fields": sorted(required),
        },
    }


def _check_provenance_signature_verification() -> dict[str, Any]:
    manifest = {"identity": {"name": "compliance-check", "version": "1.0.0"}, "capabilities": []}
    artifact = {"artifact": "control-evidence", "version": 1}
    signer = "owner-platform"

    manifest_env = sign_manifest(manifest=manifest, signer=signer, artifact_hashes=[])
    manifest_ok = verify_manifest_signature(manifest=manifest, envelope=manifest_env)["valid"]
    manifest_tamper = verify_manifest_signature(
        manifest={"identity": {"name": "compliance-check", "version": "2.0.0"}, "capabilities": []},
        envelope=manifest_env,
    )["valid"]

    artifact_env = sign_artifact(artifact_id="artifact-control", artifact_payload=artifact, signer=signer)
    artifact_ok = verify_artifact_signature(
        artifact_id="artifact-control",
        artifact_payload=artifact,
        envelope=artifact_env,
    )["valid"]
    artifact_tamper = verify_artifact_signature(
        artifact_id="artifact-control",
        artifact_payload={"artifact": "control-evidence", "version": 2},
        envelope=artifact_env,
    )["valid"]

    passed = bool(manifest_ok) and bool(artifact_ok) and not bool(manifest_tamper) and not bool(artifact_tamper)
    return {
        "passed": passed,
        "evidence": {
            "manifest_valid": bool(manifest_ok),
            "manifest_tamper_detected": not bool(manifest_tamper),
            "artifact_valid": bool(artifact_ok),
            "artifact_tamper_detected": not bool(artifact_tamper),
        },
    }


CHECKS = {
    "billing_ledger_integrity": _check_billing_ledger_integrity,
    "metering_schema_integrity": _check_metering_schema_integrity,
    "federation_audit_completeness": _check_federation_audit_completeness,
    "procurement_audit_completeness": _check_procurement_audit_completeness,
    "provenance_signature_verification": _check_provenance_signature_verification,
}


def list_controls(framework: str | None = None) -> list[dict[str, Any]]:
    rows = CONTROL_CATALOG
    if framework is not None:
        normalized = framework.strip().upper()
        rows = [row for row in rows if str(row.get("framework", "")).upper() == normalized]
    return [
        {
            "framework": row["framework"],
            "control_id": row["control_id"],
            "title": row["title"],
            "description": row["description"],
            "check_key": row["check_key"],
        }
        for row in rows
    ]


def export_evidence_pack(*, actor: str, framework: str, control_ids: list[str] | None = None) -> dict[str, Any]:
    normalized_framework = framework.strip().upper()
    if normalized_framework not in {"SOC2", "ISO27001"}:
        raise ValueError("framework must be SOC2 or ISO27001")

    controls = list_controls(framework=normalized_framework)
    if control_ids:
        requested = {control_id.strip() for control_id in control_ids if control_id.strip()}
        unknown = sorted(requested.difference({row["control_id"] for row in controls}))
        if unknown:
            raise ValueError(f"unknown control_ids: {', '.join(unknown)}")
        controls = [row for row in controls if row["control_id"] in requested]
    if not controls:
        raise ValueError("no controls selected")

    evaluated_controls: list[dict[str, Any]] = []
    for control in controls:
        check_key = str(control["check_key"])
        result = CHECKS[check_key]()
        evaluated_controls.append(
            {
                "control_id": control["control_id"],
                "framework": control["framework"],
                "title": control["title"],
                "description": control["description"],
                "check_key": check_key,
                "status": "pass" if bool(result["passed"]) else "fail",
                "checked_at": _utc_now(),
                "evidence": result["evidence"],
            }
        )

    passed = len([row for row in evaluated_controls if row["status"] == "pass"])
    failed = len(evaluated_controls) - passed
    report = {
        "report_id": str(uuid.uuid4()),
        "framework": normalized_framework,
        "generated_at": _utc_now(),
        "generated_by": actor,
        "summary": {
            "control_count": len(evaluated_controls),
            "passed_count": passed,
            "failed_count": failed,
        },
        "controls": evaluated_controls,
    }
    storage.append_report(report)
    return report


def list_evidence_reports(*, framework: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    rows = storage.load_reports()
    if framework is not None:
        normalized = framework.strip().upper()
        rows = [row for row in rows if str(row.get("framework", "")).upper() == normalized]
    rows.sort(key=lambda row: str(row.get("generated_at", "")), reverse=True)
    return rows[: max(1, int(limit))]
