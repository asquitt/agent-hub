"""Install promotion policy evaluator."""
from __future__ import annotations

import string
from typing import Any

from src.policy.abac import abac_violations
from src.policy.helpers import build_decision, reason


def evaluate_install_promotion_policy(
    *,
    actor: str,
    owner: str,
    lease_id: str,
    policy_approved: bool,
    attestation_hash: str,
    signature: str,
    abac_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []

    if not policy_approved:
        reasons.append(
            reason(
                "approval.policy_required",
                "explicit policy approval is required for install promotion",
                "violation",
                field="policy_approved",
                expected=True,
                observed=False,
            )
        )

    if not isinstance(attestation_hash, str) or len(attestation_hash) < 12:
        reasons.append(
            reason(
                "attestation.hash_invalid",
                "attestation hash must be a non-empty hash string",
                "violation",
                field="attestation_hash",
                expected="len>=12",
                observed=len(attestation_hash) if isinstance(attestation_hash, str) else None,
            )
        )
    elif any(ch not in string.hexdigits for ch in attestation_hash):
        reasons.append(
            reason(
                "attestation.hash_not_hex",
                "attestation hash must be hexadecimal",
                "violation",
                field="attestation_hash",
            )
        )

    if not isinstance(signature, str) or signature.strip() == "":
        reasons.append(
            reason(
                "attestation.signature_missing",
                "attestation signature is required",
                "violation",
                field="signature",
            )
        )

    reasons.extend(abac_violations(action="promote_lease", abac_context=abac_context))

    if not reasons:
        reasons.append(reason("policy.allow", "install promotion policy checks passed", "allow"))

    return build_decision(
        context="install",
        action="promote_lease",
        actor=actor,
        subject={"owner": owner, "lease_id": lease_id},
        evaluated_constraints={
            "policy_approved": policy_approved,
            "attestation_hash_prefix": attestation_hash[:12] if isinstance(attestation_hash, str) else "",
        },
        reasons=reasons,
    )
