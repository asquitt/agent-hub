from __future__ import annotations

# Credential types
CREDENTIAL_TYPE_API_KEY = "api_key"
CREDENTIAL_TYPE_X509 = "x509"
CREDENTIAL_TYPE_SPIFFE = "spiffe"
VALID_CREDENTIAL_TYPES = {CREDENTIAL_TYPE_API_KEY, CREDENTIAL_TYPE_X509, CREDENTIAL_TYPE_SPIFFE}

# Identity statuses
STATUS_ACTIVE = "active"
STATUS_SUSPENDED = "suspended"
STATUS_REVOKED = "revoked"
VALID_IDENTITY_STATUSES = {STATUS_ACTIVE, STATUS_SUSPENDED, STATUS_REVOKED}

# Credential statuses
CRED_STATUS_ACTIVE = "active"
CRED_STATUS_ROTATED = "rotated"
CRED_STATUS_REVOKED = "revoked"

# TTL defaults and limits (seconds)
DEFAULT_CREDENTIAL_TTL_SECONDS = 86400  # 1 day
MAX_CREDENTIAL_TTL_SECONDS = 2592000  # 30 days
MIN_CREDENTIAL_TTL_SECONDS = 300  # 5 minutes

# Secret generation
SECRET_BYTE_LENGTH = 32

# Delegation chain limits
MAX_DELEGATION_CHAIN_DEPTH = 5

# Scope format: resource.action (e.g., "delegation.create", "discovery.search")
WILDCARD_SCOPE = "*"
