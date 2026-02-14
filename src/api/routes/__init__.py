from src.api.routes.a2a import router as a2a_router
from src.api.routes.activity_monitor import router as activity_monitor_router
from src.api.routes.access_review import router as access_review_router
from src.api.routes.agent_groups import router as agent_groups_router
from src.api.routes.agents import router as agents_router
from src.api.routes.approval import router as approval_router
from src.api.routes.audit import router as audit_router
from src.api.routes.auth_routes import router as auth_routes_router
from src.api.routes.billing import router as billing_router
from src.api.routes.capabilities import router as capabilities_router
from src.api.routes.compliance import router as compliance_router
from src.api.routes.consent import router as consent_router
from src.api.routes.credential_binding import router as credential_binding_router
from src.api.routes.customer import router as customer_router
from src.api.routes.delegation import router as delegation_router
from src.api.routes.discovery import router as discovery_router
from src.api.routes.entitlements import router as entitlements_router
from src.api.routes.env_access import router as env_access_router
from src.api.routes.federation import router as federation_router
from src.api.routes.grants import router as grants_router
from src.api.routes.identity import router as identity_router
from src.api.routes.ip_allowlist import router as ip_allowlist_router
from src.api.routes.intent import router as intent_router
from src.api.routes.identity_advanced import router as identity_advanced_router
from src.api.routes.key_management import router as key_management_router
from src.api.routes.knowledge import router as knowledge_router
from src.api.routes.marketplace import router as marketplace_router
from src.api.routes.misc import router as misc_router
from src.api.routes.operator import router as operator_router
from src.api.routes.policy_code import router as policy_code_router
from src.api.routes.procurement import router as procurement_router
from src.api.routes.provenance import router as provenance_router
from src.api.routes.rate_policies import router as rate_policies_router
from src.api.routes.rbac import router as rbac_router
from src.api.routes.runtime import router as runtime_router
from src.api.routes.oauth import router as oauth_router
from src.api.routes.scim import router as scim_router
from src.api.routes.scope_narrowing import router as scope_narrowing_router
from src.api.routes.sessions import router as sessions_router
from src.api.routes.system import router as system_router
from src.api.routes.tokens import router as tokens_router
from src.api.routes.vault import router as vault_router

__all__ = [
    "a2a_router",
    "activity_monitor_router",
    "access_review_router",
    "agent_groups_router",
    "agents_router",
    "approval_router",
    "audit_router",
    "auth_routes_router",
    "billing_router",
    "capabilities_router",
    "compliance_router",
    "consent_router",
    "credential_binding_router",
    "customer_router",
    "delegation_router",
    "discovery_router",
    "entitlements_router",
    "env_access_router",
    "federation_router",
    "grants_router",
    "identity_router",
    "ip_allowlist_router",
    "identity_advanced_router",
    "intent_router",
    "key_management_router",
    "knowledge_router",
    "marketplace_router",
    "misc_router",
    "operator_router",
    "policy_code_router",
    "procurement_router",
    "provenance_router",
    "rate_policies_router",
    "rbac_router",
    "runtime_router",
    "oauth_router",
    "scim_router",
    "scope_narrowing_router",
    "sessions_router",
    "system_router",
    "tokens_router",
    "vault_router",
]
