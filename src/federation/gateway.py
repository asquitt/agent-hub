from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from src.federation import storage

DOMAIN_TOKENS = {
    "partner-east": "fed-partner-east-token",
    "partner-west": "fed-partner-west-token",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _has_inline_secret(payload: dict[str, Any]) -> bool:
    risky = {"secret", "token", "password", "api_key", "private_key"}
    for key, value in payload.items():
        key_norm = key.lower()
        if any(word in key_norm for word in risky) and value not in (None, "", "***"):
            return True
    return False


def execute_federated(
    *,
    actor: str,
    domain_id: str,
    domain_token: str,
    task_spec: str,
    payload: dict[str, Any],
    policy_context: dict[str, Any],
    estimated_cost_usd: float,
    max_budget_usd: float,
) -> dict[str, Any]:
    expected_token = DOMAIN_TOKENS.get(domain_id)
    if expected_token is None or domain_token != expected_token:
        raise PermissionError("federation domain authentication failed")
    if _has_inline_secret(payload):
        raise ValueError("inline secrets are not allowed in federated payload")
    if policy_context.get("decision") != "allow":
        raise PermissionError("policy propagation denied remote execution")
    if estimated_cost_usd > max_budget_usd:
        raise ValueError("estimated cost exceeds federated budget limit")

    input_hash = _stable_hash(
        {
            "domain_id": domain_id,
            "task_spec": task_spec,
            "payload": payload,
            "policy_context": policy_context,
            "estimated_cost_usd": estimated_cost_usd,
            "max_budget_usd": max_budget_usd,
        }
    )
    output = {
        "status": "completed",
        "domain_id": domain_id,
        "result": {"summary": f"Executed task '{task_spec}' in federated domain"},
    }
    output_hash = _stable_hash(output)
    attestation_hash = _stable_hash(
        {
            "actor": actor,
            "domain_id": domain_id,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "timestamp": _utc_now(),
        }
    )

    audit_row = {
        "timestamp": _utc_now(),
        "actor": actor,
        "domain_id": domain_id,
        "task_spec": task_spec,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "attestation_hash": attestation_hash,
        "estimated_cost_usd": round(estimated_cost_usd, 6),
        "max_budget_usd": round(max_budget_usd, 6),
        "policy_context_hash": _stable_hash(policy_context),
    }
    storage.append_audit(audit_row)

    return {
        "execution": output,
        "attestation": {
            "attestation_hash": attestation_hash,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "timestamp": audit_row["timestamp"],
            "domain_id": domain_id,
            "actor": actor,
        },
    }


def list_federation_audit(limit: int = 100) -> list[dict[str, Any]]:
    rows = storage.load_audit()
    rows.sort(key=lambda row: row.get("timestamp", ""), reverse=True)
    return rows[:limit]
