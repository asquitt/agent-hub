from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from src.federation import storage

LEGACY_DOMAIN_TOKENS = {
    "partner-east": "fed-partner-east-token",
    "partner-west": "fed-partner-west-token",
}

DOMAIN_PROFILES = {
    "partner-east": {
        "residency_region": "us-east",
        "private_connect_required": False,
        "network_pattern": "hybrid",
    },
    "partner-west": {
        "residency_region": "us-west",
        "private_connect_required": True,
        "network_pattern": "private-connect",
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _enforce_mode_enabled() -> bool:
    return str(os.getenv("AGENTHUB_ACCESS_ENFORCEMENT_MODE", "warn")).strip().lower() == "enforce"


def _domain_tokens() -> dict[str, str]:
    raw = os.getenv("AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON")
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            if _enforce_mode_enabled():
                raise PermissionError("invalid AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON configuration") from exc
            parsed = None
        if isinstance(parsed, dict):
            normalized: dict[str, str] = {}
            for domain_id, token in parsed.items():
                domain = str(domain_id).strip()
                value = str(token).strip()
                if domain and value:
                    normalized[domain] = value
            if normalized:
                return normalized
            if _enforce_mode_enabled():
                raise PermissionError("federation tokens must be configured in enforce mode")
    if _enforce_mode_enabled():
        raise PermissionError("federation tokens must be configured in enforce mode")
    return dict(LEGACY_DOMAIN_TOKENS)


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
    requested_residency_region: str | None = None,
    connection_mode: str = "public_internet",
) -> dict[str, Any]:
    expected_token = _domain_tokens().get(domain_id)
    if expected_token is None or domain_token != expected_token:
        raise PermissionError("federation domain authentication failed")
    profile = DOMAIN_PROFILES.get(
        domain_id,
        {
            "residency_region": "global",
            "private_connect_required": False,
            "network_pattern": "public",
        },
    )
    if requested_residency_region is not None:
        requested = requested_residency_region.strip().lower()
        if requested and requested != str(profile["residency_region"]).lower():
            raise PermissionError("requested residency region is not allowed for domain")
    if bool(profile.get("private_connect_required")) and connection_mode != "private_connect":
        raise PermissionError("private connectivity required for federated domain")
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
            "requested_residency_region": requested_residency_region,
            "connection_mode": connection_mode,
            "profile": profile,
        }
    )
    output = {
        "status": "completed",
        "domain_id": domain_id,
        "federation_profile": profile,
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
        "requested_residency_region": requested_residency_region,
        "residency_region": profile["residency_region"],
        "private_connect_required": bool(profile.get("private_connect_required")),
        "connection_mode": connection_mode,
        "network_pattern": profile.get("network_pattern", "public"),
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
            "residency_region": profile["residency_region"],
            "connection_mode": connection_mode,
        },
    }


def list_federation_audit(limit: int = 100) -> list[dict[str, Any]]:
    rows = storage.load_audit()
    rows.sort(key=lambda row: row.get("timestamp", ""), reverse=True)
    return rows[:limit]


def list_domain_profiles() -> list[dict[str, Any]]:
    rows = [{"domain_id": domain_id, **profile} for domain_id, profile in DOMAIN_PROFILES.items()]
    rows.sort(key=lambda row: str(row.get("domain_id")))
    return rows


def export_attestation_bundle(*, actor: str, domain_id: str | None = None, limit: int = 250) -> dict[str, Any]:
    rows = list_federation_audit(limit=max(1, limit))
    if domain_id is not None:
        rows = [row for row in rows if row.get("domain_id") == domain_id]
    records = [
        {
            "timestamp": row.get("timestamp"),
            "actor": row.get("actor"),
            "domain_id": row.get("domain_id"),
            "task_spec": row.get("task_spec"),
            "attestation_hash": row.get("attestation_hash"),
            "input_hash": row.get("input_hash"),
            "output_hash": row.get("output_hash"),
            "policy_context_hash": row.get("policy_context_hash"),
            "residency_region": row.get("residency_region"),
            "requested_residency_region": row.get("requested_residency_region"),
            "private_connect_required": row.get("private_connect_required"),
            "connection_mode": row.get("connection_mode"),
            "network_pattern": row.get("network_pattern"),
            "estimated_cost_usd": row.get("estimated_cost_usd"),
            "max_budget_usd": row.get("max_budget_usd"),
        }
        for row in rows
    ]
    manifest = {
        "export_id": str(uuid.uuid4()),
        "generated_at": _utc_now(),
        "generated_by": actor,
        "domain_id": domain_id,
        "record_count": len(records),
        "residency_regions": sorted({str(row["residency_region"]) for row in records if row.get("residency_region")}),
        "private_connect_records": len([row for row in records if bool(row.get("private_connect_required"))]),
    }
    bundle_hash = _stable_hash({"manifest": manifest, "records": records})
    return {
        "manifest": {**manifest, "bundle_hash": bundle_hash},
        "records": records,
    }
