from __future__ import annotations

import os
import re

from fastapi.responses import JSONResponse

from src.api.route_helpers import stable_error

UNSAFE_FINANCIAL_MUTATIONS_ENV = "AGENTHUB_ENABLE_UNSAFE_FINANCIAL_MUTATIONS"
_DISABLED_MESSAGE = "unproven financial mutations are disabled"

_MARKETPLACE_FINANCIAL_PATHS = (
    re.compile(r"^/v1/marketplace/purchase$"),
    re.compile(r"^/v1/marketplace/contracts/[^/]+/(?:settle|disputes|payout)$"),
    re.compile(r"^/v1/marketplace/disputes/[^/]+/resolve$"),
)


def unsafe_financial_mutations_enabled() -> bool:
    """Require an explicit local-development opt-in for unproven money paths."""
    return os.getenv(UNSAFE_FINANCIAL_MUTATIONS_ENV, "").strip().lower() == "true"


def is_unproven_financial_mutation(method: str, path: str) -> bool:
    if method.upper() != "POST":
        return False
    if path == "/v1/delegations":
        return True
    if path.startswith("/v1/billing/"):
        return True
    if path.startswith("/v1/procurement/"):
        return True
    return any(pattern.fullmatch(path) for pattern in _MARKETPLACE_FINANCIAL_PATHS)


def financial_mutation_gate(method: str, path: str) -> JSONResponse | None:
    """Fail closed before idempotency or domain services can mutate state."""
    if not is_unproven_financial_mutation(method, path):
        return None
    if unsafe_financial_mutations_enabled():
        return None
    return stable_error(503, "financial.disabled", _DISABLED_MESSAGE)
