from src.api.routes.agents import router as agents_router
from src.api.routes.auth_routes import router as auth_routes_router
from src.api.routes.billing import router as billing_router
from src.api.routes.capabilities import router as capabilities_router
from src.api.routes.compliance import router as compliance_router
from src.api.routes.customer import router as customer_router
from src.api.routes.delegation import router as delegation_router
from src.api.routes.discovery import router as discovery_router
from src.api.routes.federation import router as federation_router
from src.api.routes.identity import router as identity_router
from src.api.routes.knowledge import router as knowledge_router
from src.api.routes.marketplace import router as marketplace_router
from src.api.routes.misc import router as misc_router
from src.api.routes.operator import router as operator_router
from src.api.routes.procurement import router as procurement_router
from src.api.routes.provenance import router as provenance_router
from src.api.routes.runtime import router as runtime_router
from src.api.routes.system import router as system_router

__all__ = [
    "agents_router",
    "auth_routes_router",
    "billing_router",
    "capabilities_router",
    "compliance_router",
    "customer_router",
    "delegation_router",
    "discovery_router",
    "federation_router",
    "identity_router",
    "knowledge_router",
    "marketplace_router",
    "misc_router",
    "operator_router",
    "procurement_router",
    "provenance_router",
    "runtime_router",
    "system_router",
]
