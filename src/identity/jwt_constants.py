"""JWT constants for AAP-compliant agent tokens."""
from __future__ import annotations

# Algorithms
ALG_HS256 = "HS256"
ALG_RS256 = "RS256"
ALG_ES256 = "ES256"
DEFAULT_ALGORITHM = ALG_HS256

# AAP-specific registered claims (IETF draft-ietf-oauth-agent-auth-protocol)
CLAIM_AGENT_ID = "agent_id"
CLAIM_AGENT_CAPABILITIES = "agent_capabilities"
CLAIM_TASK_BINDING = "task_binding"
CLAIM_OVERSIGHT_LEVEL = "oversight_level"
CLAIM_DELEGATION_CHAIN_ID = "delegation_chain_id"
CLAIM_SCOPE = "scope"

# Standard JWT claims
CLAIM_ISS = "iss"
CLAIM_SUB = "sub"
CLAIM_AUD = "aud"
CLAIM_EXP = "exp"
CLAIM_IAT = "iat"
CLAIM_JTI = "jti"

# Extended AAP claims (S135)
CLAIM_DELEGATION_CHAIN = "delegation_chain"
CLAIM_BEHAVIORAL_ATTESTATION = "behavioral_attestation"
CLAIM_RUNTIME_CONSTRAINTS = "runtime_constraints"
CLAIM_PEER_ATTESTATIONS = "peer_attestations"

# Credential type identifier
CREDENTIAL_TYPE_JWT = "jwt"

# Oversight levels (AAP spec)
OVERSIGHT_NONE = "none"
OVERSIGHT_NOTIFY = "notify"
OVERSIGHT_APPROVE = "approve"
OVERSIGHT_FULL = "full"
VALID_OVERSIGHT_LEVELS = {OVERSIGHT_NONE, OVERSIGHT_NOTIFY, OVERSIGHT_APPROVE, OVERSIGHT_FULL}

# Token defaults
DEFAULT_JWT_TTL_SECONDS = 3600  # 1 hour
MAX_JWT_TTL_SECONDS = 86400  # 24 hours
MIN_JWT_TTL_SECONDS = 60  # 1 minute

# Issuer
DEFAULT_ISSUER = "urn:agenthub:registry"
