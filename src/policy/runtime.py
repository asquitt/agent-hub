"""Backward-compatibility re-exports. All logic now lives in focused modules."""
from src.policy.abac import abac_violations as _abac_violations  # noqa: F401
from src.policy.delegation import evaluate_delegation_policy  # noqa: F401
from src.policy.discovery import (  # noqa: F401
    evaluate_compatibility_policy,
    evaluate_contract_match_policy,
    evaluate_discovery_policy,
)
from src.policy.helpers import (  # noqa: F401
    POLICY_VERSION,
    SUPPORTED_PROTOCOLS,
    build_decision as _build_decision,
    reason as _reason,
    sign_policy_payload as _sign_policy_payload,
    stable_hash as _stable_hash,
    verify_decision_signature,
)
from src.policy.identity_policy import (  # noqa: F401
    evaluate_agent_credential_policy,
    evaluate_delegation_token_policy,
)
from src.policy.install import evaluate_install_promotion_policy  # noqa: F401
