from src.api.routes.customer import router as customer_router
from src.api.routes.identity import router as identity_router
from src.api.routes.operator import router as operator_router
from src.api.routes.runtime import router as runtime_router
from src.api.routes.system import router as system_router

__all__ = ["customer_router", "identity_router", "operator_router", "runtime_router", "system_router"]
