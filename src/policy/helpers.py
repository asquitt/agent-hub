"""Shared policy helpers: hashing, signing, reason/decision builders."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

POLICY_VERSION = "runtime-policy-v3"
SUPPORTED_PROTOCOLS = {"MCP", "A2A", "HTTP", "INTERNAL"}


def stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def policy_signing_secret() -> bytes:
    secret = os.getenv("AGENTHUB_POLICY_SIGNING_SECRET", "agenthub-policy-signing-secret")
    return secret.encode("utf-8")


def sign_policy_payload(payload: dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(policy_signing_secret() + normalized).hexdigest()


def reason(
    code: str,
    message: str,
    reason_type: str,
    *,
    field: str | None = None,
    expected: Any | None = None,
    observed: Any | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "code": code,
        "message": message,
        "type": reason_type,
    }
    if field is not None:
        row["field"] = field
    if expected is not None:
        row["expected"] = expected
    if observed is not None:
        row["observed"] = observed
    return row


def build_decision(
    context: str,
    action: str,
    actor: str,
    subject: dict[str, Any],
    evaluated_constraints: dict[str, Any],
    reasons: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered_reasons = sorted(
        reasons,
        key=lambda row: (
            row.get("type", ""),
            row.get("code", ""),
            row.get("field", ""),
            str(row.get("observed", "")),
            str(row.get("expected", "")),
        ),
    )
    violated_constraints = sorted({row["code"] for row in ordered_reasons if row.get("type") == "violation"})
    allowed = not violated_constraints
    payload = {
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "evaluated_constraints": evaluated_constraints,
        "reasons": ordered_reasons,
        "violated_constraints": violated_constraints,
        "policy_version": POLICY_VERSION,
    }
    input_hash = stable_hash(payload)
    decision_id = stable_hash({"policy_version": POLICY_VERSION, "input_hash": input_hash})[:24]
    explainability = {
        "violation_codes": [row["code"] for row in ordered_reasons if row.get("type") == "violation"],
        "warning_codes": [row["code"] for row in ordered_reasons if row.get("type") == "warning"],
        "allow_codes": [row["code"] for row in ordered_reasons if row.get("type") == "allow"],
        "evaluated_fields": sorted(evaluated_constraints.keys()),
    }
    signature_payload = {
        "policy_version": POLICY_VERSION,
        "decision_id": decision_id,
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "decision": "allow" if allowed else "deny",
        "violated_constraints": violated_constraints,
        "input_hash": input_hash,
    }
    decision_signature = sign_policy_payload(signature_payload)
    return {
        "policy_version": POLICY_VERSION,
        "decision_id": decision_id,
        "context": context,
        "action": action,
        "actor": actor,
        "subject": subject,
        "decision": "allow" if allowed else "deny",
        "allowed": allowed,
        "reasons": ordered_reasons,
        "violated_constraints": violated_constraints,
        "evaluated_constraints": evaluated_constraints,
        "input_hash": input_hash,
        "explainability": explainability,
        "signature_algorithm": "sha256(secret+payload)",
        "decision_signature": decision_signature,
    }


def verify_decision_signature(decision: dict[str, Any]) -> bool:
    if not isinstance(decision, dict):
        return False
    required = {
        "policy_version",
        "decision_id",
        "context",
        "action",
        "actor",
        "subject",
        "decision",
        "violated_constraints",
        "input_hash",
        "decision_signature",
    }
    if not required.issubset(decision.keys()):
        return False
    payload = {
        "policy_version": decision["policy_version"],
        "decision_id": decision["decision_id"],
        "context": decision["context"],
        "action": decision["action"],
        "actor": decision["actor"],
        "subject": decision["subject"],
        "decision": decision["decision"],
        "violated_constraints": decision["violated_constraints"],
        "input_hash": decision["input_hash"],
    }
    expected = sign_policy_payload(payload)
    return str(decision.get("decision_signature", "")) == expected
