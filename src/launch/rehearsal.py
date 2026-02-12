from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .readiness import evaluate_onboarding_funnel, run_demo_smoke


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def _extract_violations(response_payload: Any) -> list[str]:
    if not isinstance(response_payload, dict):
        return []
    detail = response_payload.get("detail")
    if isinstance(detail, dict):
        decision = detail.get("policy_decision")
        if isinstance(decision, dict):
            violated = decision.get("violated_constraints", [])
            if isinstance(violated, list):
                return [str(item) for item in violated]
    return []


def _incident_result(
    *,
    incident_id: str,
    severity: str,
    category: str,
    affected_flow: str,
    expected_status: int,
    observed_status: int,
    resolved: bool,
    mitigation: str,
    notes: str,
) -> dict[str, Any]:
    return {
        "incident_id": incident_id,
        "occurred_at": _now_iso(),
        "severity": severity,
        "category": category,
        "affected_flow": affected_flow,
        "resolved": resolved,
        "mitigation": mitigation,
        "owner": "platform",
        "expected_status": expected_status,
        "observed_status": observed_status,
        "notes": notes,
    }


def run_incident_drills(client: Any) -> dict[str, Any]:
    drills: list[dict[str, Any]] = []

    lease_a = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@launch:incident-drill-a",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    lease_a_payload = _safe_json(lease_a)
    approval_promote = None
    if isinstance(lease_a_payload, dict):
        approval_promote = client.post(
            f"/v1/capabilities/leases/{lease_a_payload['lease_id']}/promote",
            json={
                "attestation_hash": lease_a_payload["attestation_hash"],
                "signature": f"sig:{lease_a_payload['attestation_hash']}:owner-dev",
                "policy_approved": False,
                "approval_ticket": "APR-5201",
                "compatibility_verified": True,
            },
            headers={"X-API-Key": "dev-owner-key"},
        )

    approval_status = approval_promote.status_code if approval_promote is not None else 500
    approval_payload = _safe_json(approval_promote) if approval_promote is not None else None
    approval_violations = _extract_violations(approval_payload)
    approval_passed = approval_status == 403 and "approval.policy_required" in approval_violations
    drills.append(
        _incident_result(
            incident_id="S52-INC-APPROVAL-POLICY",
            severity="sev1",
            category="policy_bypass",
            affected_flow="lease_promote",
            expected_status=403,
            observed_status=approval_status,
            resolved=approval_passed,
            mitigation="Explicit policy approval enforced before install promotion.",
            notes="Missing policy approval is blocked by policy engine.",
        )
    )

    lease_b = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@launch:incident-drill-b",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    lease_b_payload = _safe_json(lease_b)
    boundary_promote = None
    if isinstance(lease_b_payload, dict):
        boundary_promote = client.post(
            f"/v1/capabilities/leases/{lease_b_payload['lease_id']}/promote",
            json={
                "attestation_hash": lease_b_payload["attestation_hash"],
                "signature": f"sig:{lease_b_payload['attestation_hash']}:owner-partner",
                "policy_approved": True,
                "approval_ticket": "APR-5202",
                "compatibility_verified": True,
            },
            headers={"X-API-Key": "partner-owner-key"},
        )

    boundary_status = boundary_promote.status_code if boundary_promote is not None else 500
    boundary_payload = _safe_json(boundary_promote) if boundary_promote is not None else None
    boundary_detail = (
        str(boundary_payload.get("detail")) if isinstance(boundary_payload, dict) and "detail" in boundary_payload else ""
    )
    boundary_passed = boundary_status == 403 and "owner mismatch" in boundary_detail
    drills.append(
        _incident_result(
            incident_id="S52-INC-OWNER-BOUNDARY",
            severity="sev2",
            category="delegation_failure",
            affected_flow="lease_promote",
            expected_status=403,
            observed_status=boundary_status,
            resolved=boundary_passed,
            mitigation="Owner boundary enforcement prevents cross-owner promotion.",
            notes="Promotion attempts from non-owner identities are denied.",
        )
    )

    lease_c = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@launch:incident-drill-c",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    lease_c_payload = _safe_json(lease_c)
    attestation_promote = None
    if isinstance(lease_c_payload, dict):
        original_hash = str(lease_c_payload["attestation_hash"])
        invalid_hash = ("0" if original_hash[0] != "0" else "1") + original_hash[1:]
        attestation_promote = client.post(
            f"/v1/capabilities/leases/{lease_c_payload['lease_id']}/promote",
            json={
                "attestation_hash": invalid_hash,
                "signature": f"sig:{invalid_hash}:owner-dev",
                "policy_approved": True,
                "approval_ticket": "APR-5203",
                "compatibility_verified": True,
            },
            headers={"X-API-Key": "dev-owner-key"},
        )

    attestation_status = attestation_promote.status_code if attestation_promote is not None else 500
    attestation_payload = _safe_json(attestation_promote) if attestation_promote is not None else None
    attestation_detail = (
        str(attestation_payload.get("detail"))
        if isinstance(attestation_payload, dict) and "detail" in attestation_payload
        else ""
    )
    attestation_passed = attestation_status == 403 and "attestation hash mismatch" in attestation_detail
    drills.append(
        _incident_result(
            incident_id="S52-INC-ATTESTATION-INTEGRITY",
            severity="sev2",
            category="delegation_failure",
            affected_flow="lease_promote",
            expected_status=403,
            observed_status=attestation_status,
            resolved=attestation_passed,
            mitigation="Attestation hash verification blocks tampered promotion payloads.",
            notes="Hash mismatch is rejected before install state is mutated.",
        )
    )

    return {
        "passed": all(drill["resolved"] for drill in drills),
        "drills": drills,
    }


def run_rollback_simulation(client: Any, *, reason: str = "launch rehearsal rollback simulation") -> dict[str, Any]:
    steps: list[dict[str, Any]] = []

    lease_response = client.post(
        "/v1/capabilities/lease",
        json={
            "requester_agent_id": "@launch:rollback-drill",
            "capability_ref": "@seed:data-normalizer/normalize-records",
            "ttl_seconds": 600,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    lease_payload = _safe_json(lease_response)
    lease_passed = bool(
        lease_response.status_code == 200
        and isinstance(lease_payload, dict)
        and lease_payload.get("status") == "active"
    )
    steps.append(
        {
            "step": "create_lease",
            "status_code": lease_response.status_code,
            "passed": lease_passed,
        }
    )
    if not lease_passed:
        return {"passed": False, "steps": steps, "install_id": None}

    promote_response = client.post(
        f"/v1/capabilities/leases/{lease_payload['lease_id']}/promote",
        json={
            "attestation_hash": lease_payload["attestation_hash"],
            "signature": f"sig:{lease_payload['attestation_hash']}:owner-dev",
            "policy_approved": True,
            "approval_ticket": "APR-5204",
            "compatibility_verified": True,
        },
        headers={"X-API-Key": "dev-owner-key"},
    )
    promote_payload = _safe_json(promote_response)
    install_id = (
        str(promote_payload.get("promotion", {}).get("install_id"))
        if isinstance(promote_payload, dict)
        else None
    )
    promote_passed = bool(
        promote_response.status_code == 200
        and isinstance(promote_payload, dict)
        and promote_payload.get("status") == "promoted"
        and install_id
    )
    steps.append(
        {
            "step": "promote_lease",
            "status_code": promote_response.status_code,
            "passed": promote_passed,
        }
    )
    if not promote_passed or install_id is None:
        return {"passed": False, "steps": steps, "install_id": install_id}

    rollback_response = client.post(
        f"/v1/capabilities/installs/{install_id}/rollback",
        json={"reason": reason},
        headers={"X-API-Key": "dev-owner-key"},
    )
    rollback_payload = _safe_json(rollback_response)
    rollback_passed = bool(
        rollback_response.status_code == 200
        and isinstance(rollback_payload, dict)
        and rollback_payload.get("status") == "rolled_back"
        and rollback_payload.get("rollback_reason") == reason
    )
    steps.append(
        {
            "step": "rollback_install",
            "status_code": rollback_response.status_code,
            "passed": rollback_passed,
        }
    )

    rollback_repeat = client.post(
        f"/v1/capabilities/installs/{install_id}/rollback",
        json={"reason": reason},
        headers={"X-API-Key": "dev-owner-key"},
    )
    rollback_repeat_payload = _safe_json(rollback_repeat)
    rollback_repeat_passed = bool(
        rollback_repeat.status_code == 200
        and isinstance(rollback_repeat_payload, dict)
        and rollback_repeat_payload.get("status") == "rolled_back"
        and rollback_repeat_payload.get("rollback_reason") == reason
    )
    steps.append(
        {
            "step": "rollback_idempotency",
            "status_code": rollback_repeat.status_code,
            "passed": rollback_repeat_passed,
        }
    )

    return {
        "passed": all(step["passed"] for step in steps),
        "steps": steps,
        "install_id": install_id,
    }


def _summarize_gate_review(gate_review: dict[str, Any]) -> dict[str, Any]:
    decision = str(gate_review.get("decision", "UNKNOWN")).upper()
    raw_reasons = gate_review.get("blocking_reasons", [])
    if isinstance(raw_reasons, list):
        blocking_reasons = [str(reason) for reason in raw_reasons]
    elif raw_reasons:
        blocking_reasons = [str(raw_reasons)]
    else:
        blocking_reasons = []

    return {
        "passed": decision == "GO",
        "decision": decision,
        "blocking_reasons": blocking_reasons,
        "gate_version": gate_review.get("gate_version", "unknown"),
        "generated_at": gate_review.get("generated_at"),
    }


def build_ga_launch_rehearsal_report(
    *,
    client: Any,
    manifest: dict[str, Any],
    onboarding_metrics: dict[str, Any],
    gate_review: dict[str, Any],
) -> dict[str, Any]:
    demo = run_demo_smoke(client=client, manifest=manifest)
    funnel = evaluate_onboarding_funnel(onboarding_metrics)
    incidents = run_incident_drills(client=client)
    rollback = run_rollback_simulation(client=client)
    gate = _summarize_gate_review(gate_review)

    checks = [
        {"id": "demo_reproducibility", "passed": bool(demo.get("passed"))},
        {"id": "onboarding_funnel", "passed": bool(funnel.get("passed"))},
        {"id": "incident_drills", "passed": bool(incidents.get("passed"))},
        {"id": "rollback_simulation", "passed": bool(rollback.get("passed"))},
        {"id": "gate_review", "passed": bool(gate.get("passed"))},
    ]

    blocking_reasons: list[str] = []
    if not demo.get("passed"):
        blocking_reasons.append("Demo reproducibility checks failed")
    if not funnel.get("passed"):
        blocking_reasons.append("Onboarding funnel thresholds failed")
    if not incidents.get("passed"):
        blocking_reasons.append("Incident drill controls failed")
    if not rollback.get("passed"):
        blocking_reasons.append("Rollback simulation failed")
    if not gate.get("passed"):
        gate_reasons = gate.get("blocking_reasons", [])
        if gate_reasons:
            blocking_reasons.append(f"Gate review blocking reasons: {', '.join(gate_reasons)}")
        else:
            blocking_reasons.append(f"Gate review decision is {gate.get('decision')}")

    return {
        "launch_rehearsal_version": "s52",
        "generated_at": _now_iso(),
        "checks": checks,
        "demo_reproducibility": demo,
        "onboarding_funnel": funnel,
        "incident_drills": incidents,
        "rollback_simulation": rollback,
        "gate_review": gate,
        "ga_candidate_ready": all(check["passed"] for check in checks),
        "blocking_reasons": blocking_reasons,
    }


def render_ga_rehearsal_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# S52 GA Launch Rehearsal",
        "",
        f"- GA Candidate Ready: **{report.get('ga_candidate_ready')}**",
        f"- Rehearsal version: `{report.get('launch_rehearsal_version', 's52')}`",
        f"- Generated at: `{report.get('generated_at', '')}`",
        "",
        "## Checks",
    ]
    for check in report.get("checks", []):
        status = "PASS" if check.get("passed") else "FAIL"
        lines.append(f"- [{status}] {check.get('id')}")

    lines.extend(["", "## Blocking Reasons"])
    reasons = report.get("blocking_reasons", [])
    if reasons:
        for reason in reasons:
            lines.append(f"- {reason}")
    else:
        lines.append("- None")

    lines.extend(["", "## Incident Drills"])
    incident_drills = report.get("incident_drills", {}).get("drills", [])
    for drill in incident_drills:
        status = "resolved" if drill.get("resolved") else "unresolved"
        lines.append(f"- {drill.get('incident_id')}: {status} ({drill.get('category')})")

    lines.extend(["", "## Rollback Simulation Steps"])
    rollback_steps = report.get("rollback_simulation", {}).get("steps", [])
    for step in rollback_steps:
        status = "PASS" if step.get("passed") else "FAIL"
        lines.append(f"- [{status}] {step.get('step')} (status={step.get('status_code')})")

    return "\n".join(lines) + "\n"
