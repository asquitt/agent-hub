from __future__ import annotations

import json
import os
from typing import Any, Mapping

from src.api.access_policy import access_mode
from src.common.time import utc_now_iso


REQUIRED_ENV_VARS = (
    "AGENTHUB_API_KEYS_JSON",
    "AGENTHUB_AUTH_TOKEN_SECRET",
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
    "AGENTHUB_PROVENANCE_SIGNING_SECRET",
)


def _read_env(environ: Mapping[str, str] | None = None) -> Mapping[str, str]:
    if environ is not None:
        return environ
    return os.environ


def _check_non_empty(env: Mapping[str, str], key: str) -> dict[str, Any]:
    raw = env.get(key)
    present = raw is not None and bool(str(raw).strip())
    return {
        "env_var": key,
        "present": raw is not None,
        "valid": present,
        "message": "ok" if present else "missing required environment variable",
    }


def _check_non_empty_json_object(env: Mapping[str, str], key: str) -> dict[str, Any]:
    raw = env.get(key)
    if raw is None:
        return {
            "env_var": key,
            "present": False,
            "valid": False,
            "message": "missing required environment variable",
        }
    text = str(raw).strip()
    if not text:
        return {
            "env_var": key,
            "present": True,
            "valid": False,
            "message": "environment variable must not be empty",
        }
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {
            "env_var": key,
            "present": True,
            "valid": False,
            "message": "environment variable must be valid JSON",
        }
    if not isinstance(parsed, dict):
        return {
            "env_var": key,
            "present": True,
            "valid": False,
            "message": "environment variable must be a JSON object",
        }
    normalized = {
        str(name).strip(): str(value).strip()
        for name, value in parsed.items()
        if str(name).strip() and str(value).strip()
    }
    if not normalized:
        return {
            "env_var": key,
            "present": True,
            "valid": False,
            "message": "environment variable must define at least one non-empty key/value",
        }
    return {
        "env_var": key,
        "present": True,
        "valid": True,
        "message": "ok",
    }


def build_startup_diagnostics(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = _read_env(environ)
    checks = [
        {"component": "auth", **_check_non_empty_json_object(env, "AGENTHUB_API_KEYS_JSON")},
        {"component": "auth", **_check_non_empty(env, "AGENTHUB_AUTH_TOKEN_SECRET")},
        {"component": "federation", **_check_non_empty_json_object(env, "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON")},
        {"component": "provenance", **_check_non_empty(env, "AGENTHUB_PROVENANCE_SIGNING_SECRET")},
    ]
    missing_or_invalid = [row["env_var"] for row in checks if not row["valid"]]
    return {
        "generated_at": utc_now_iso(),
        "access_enforcement_mode": access_mode(),
        "required_env_vars": list(REQUIRED_ENV_VARS),
        "checks": checks,
        "startup_ready": len(missing_or_invalid) == 0,
        "missing_or_invalid": missing_or_invalid,
    }
