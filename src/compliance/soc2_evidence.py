"""SOC2 Evidence Automation — continuous evidence collection and export.

Automates SOC2 Type II evidence collection across trust service criteria:
- CC6 (Logical & Physical Access): credential lifecycle, access logs
- CC7 (System Operations): monitoring, anomaly detection
- CC8 (Change Management): configuration changes, audit trails
- CC9 (Risk Mitigation): policy enforcement, delegation controls

Produces structured evidence packages for auditor review.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.soc2_evidence")

# SOC2 Trust Service Criteria
CRITERIA_CC6 = "CC6"  # Logical and Physical Access Controls
CRITERIA_CC7 = "CC7"  # System Operations
CRITERIA_CC8 = "CC8"  # Change Management
CRITERIA_CC9 = "CC9"  # Risk Mitigation

VALID_CRITERIA = {CRITERIA_CC6, CRITERIA_CC7, CRITERIA_CC8, CRITERIA_CC9}

# Evidence types
EVIDENCE_CREDENTIAL_LIFECYCLE = "credential_lifecycle"
EVIDENCE_ACCESS_LOG = "access_log"
EVIDENCE_POLICY_DECISION = "policy_decision"
EVIDENCE_CONFIG_CHANGE = "config_change"
EVIDENCE_DELEGATION_CHAIN = "delegation_chain"
EVIDENCE_REVOCATION = "revocation"
EVIDENCE_ANOMALY = "anomaly_detection"
EVIDENCE_ROTATION = "credential_rotation"

# In-memory evidence store
_evidence_records: list[dict[str, Any]] = []


def record_evidence(
    *,
    criteria: str,
    evidence_type: str,
    description: str,
    actor: str,
    details: dict[str, Any] | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """Record a single evidence item for SOC2 compliance."""
    if criteria not in VALID_CRITERIA:
        raise ValueError(f"invalid SOC2 criteria: {criteria}")

    evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
    now = time.time()

    record: dict[str, Any] = {
        "evidence_id": evidence_id,
        "criteria": criteria,
        "evidence_type": evidence_type,
        "description": description,
        "actor": actor,
        "agent_id": agent_id,
        "details": details or {},
        "recorded_at": now,
    }

    # Compute integrity hash
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["integrity_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    _evidence_records.append(record)
    _log.info("evidence recorded: id=%s criteria=%s type=%s", evidence_id, criteria, evidence_type)
    return record


def collect_evidence_for_criteria(
    criteria: str,
    *,
    start_time: float | None = None,
    end_time: float | None = None,
) -> list[dict[str, Any]]:
    """Collect all evidence for a specific SOC2 criteria within a time range."""
    if criteria not in VALID_CRITERIA:
        raise ValueError(f"invalid SOC2 criteria: {criteria}")

    results = []
    for rec in _evidence_records:
        if rec["criteria"] != criteria:
            continue
        t = rec["recorded_at"]
        if start_time and t < start_time:
            continue
        if end_time and t > end_time:
            continue
        results.append(rec)
    return results


def generate_evidence_package(
    *,
    criteria: list[str] | None = None,
    start_time: float | None = None,
    end_time: float | None = None,
    auditor_name: str = "",
) -> dict[str, Any]:
    """Generate a structured evidence package for auditor review.

    Returns a complete package with evidence grouped by criteria,
    integrity verification, and coverage statistics.
    """
    target_criteria = criteria or list(VALID_CRITERIA)
    for c in target_criteria:
        if c not in VALID_CRITERIA:
            raise ValueError(f"invalid SOC2 criteria: {c}")

    package_id = f"pkg-{uuid.uuid4().hex[:12]}"
    now = time.time()

    evidence_by_criteria: dict[str, list[dict[str, Any]]] = {}
    total_evidence = 0

    for c in sorted(target_criteria):
        items = collect_evidence_for_criteria(c, start_time=start_time, end_time=end_time)
        evidence_by_criteria[c] = items
        total_evidence += len(items)

    # Coverage analysis
    coverage: dict[str, dict[str, Any]] = {}
    for c in sorted(target_criteria):
        items = evidence_by_criteria.get(c, [])
        evidence_types = {item["evidence_type"] for item in items}
        coverage[c] = {
            "evidence_count": len(items),
            "evidence_types": sorted(evidence_types),
            "has_evidence": len(items) > 0,
        }

    # Package integrity
    package_data: dict[str, Any] = {
        "package_id": package_id,
        "generated_at": now,
        "auditor_name": auditor_name,
        "criteria_requested": sorted(target_criteria),
        "time_range": {
            "start": start_time,
            "end": end_time,
        },
        "total_evidence_count": total_evidence,
        "coverage": coverage,
        "evidence": evidence_by_criteria,
    }

    canonical = json.dumps(
        {"package_id": package_id, "total": total_evidence, "generated_at": now},
        sort_keys=True,
        separators=(",", ":"),
    )
    package_data["package_integrity_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    _log.info(
        "evidence package generated: id=%s criteria=%s count=%d",
        package_id, target_criteria, total_evidence,
    )
    return package_data


def get_compliance_summary() -> dict[str, Any]:
    """Get a summary of SOC2 compliance evidence status."""
    now = time.time()
    last_24h = now - 86400
    last_7d = now - 604800

    summary: dict[str, Any] = {
        "total_evidence": len(_evidence_records),
        "criteria_coverage": {},
    }

    for criteria in sorted(VALID_CRITERIA):
        all_items = [r for r in _evidence_records if r["criteria"] == criteria]
        recent_items = [r for r in all_items if r["recorded_at"] >= last_24h]
        week_items = [r for r in all_items if r["recorded_at"] >= last_7d]

        summary["criteria_coverage"][criteria] = {
            "total": len(all_items),
            "last_24h": len(recent_items),
            "last_7d": len(week_items),
            "has_recent_evidence": len(recent_items) > 0,
        }

    return summary


def verify_evidence_integrity(evidence_id: str) -> dict[str, Any]:
    """Verify the integrity hash of a specific evidence record."""
    for rec in _evidence_records:
        if rec["evidence_id"] == evidence_id:
            stored_hash = rec.get("integrity_hash", "")
            # Recompute hash without the hash field
            check = {k: v for k, v in rec.items() if k != "integrity_hash"}
            canonical = json.dumps(check, sort_keys=True, separators=(",", ":"))
            computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            return {
                "evidence_id": evidence_id,
                "valid": stored_hash == computed_hash,
                "stored_hash": stored_hash,
                "computed_hash": computed_hash,
            }
    raise KeyError(f"evidence not found: {evidence_id}")


def reset_for_tests() -> None:
    """Clear all evidence records for testing."""
    _evidence_records.clear()
