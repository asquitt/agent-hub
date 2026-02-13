from __future__ import annotations

import json
import os

_DEFAULT_ALLOWED_OWNERS = {"owner-dev", "owner-platform"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def customer_ui_enabled() -> bool:
    return _env_bool("AGENTHUB_CUSTOMER_UI_ENABLED", default=False)


def customer_ui_require_auth() -> bool:
    return _env_bool("AGENTHUB_CUSTOMER_UI_REQUIRE_AUTH", default=True)


def customer_ui_allowed_owners() -> set[str]:
    raw = os.getenv("AGENTHUB_CUSTOMER_UI_ALLOWED_OWNERS_JSON")
    if not raw:
        return set(_DEFAULT_ALLOWED_OWNERS)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return set(_DEFAULT_ALLOWED_OWNERS)
    if not isinstance(parsed, list):
        return set(_DEFAULT_ALLOWED_OWNERS)
    owners = {str(item).strip() for item in parsed if str(item).strip()}
    if not owners:
        return set(_DEFAULT_ALLOWED_OWNERS)
    return owners
