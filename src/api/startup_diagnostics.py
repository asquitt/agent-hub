from __future__ import annotations

import json
import os
from typing import Any, Mapping
from pathlib import Path

from src.api.access_policy import access_mode
from src.common.time import utc_now_iso


REQUIRED_ENV_VARS = (
    "AGENTHUB_API_KEYS_JSON",
    "AGENTHUB_AUTH_TOKEN_SECRET",
    "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON",
    "AGENTHUB_PROVENANCE_SIGNING_SECRET",
)

PATH_PROBES = (
    "AGENTHUB_REGISTRY_DB_PATH",
    "AGENTHUB_DELEGATION_DB_PATH",
    "AGENTHUB_BILLING_DB_PATH",
    "AGENTHUB_PROCUREMENT_POLICY_PACKS_PATH",
    "AGENTHUB_FEDERATION_AUDIT_PATH",
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


def _nearest_existing_parent(path: Path) -> Path:
    current = path
    while not current.exists() and current.parent != current:
        current = current.parent
    return current


def _path_probe(env: Mapping[str, str], key: str) -> dict[str, Any]:
    raw = env.get(key)
    if raw is None or not str(raw).strip():
        return {
            "probe": key,
            "configured": False,
            "status": "skipped",
            "message": "environment variable not configured",
        }

    path = Path(str(raw).strip()).expanduser()
    parent = path.parent
    check_target = parent
    if not parent.exists():
        check_target = _nearest_existing_parent(parent)

    if not check_target.exists():
        return {
            "probe": key,
            "configured": True,
            "path": str(path),
            "status": "fail",
            "message": "no existing parent path found for probe",
        }

    if not check_target.is_dir():
        return {
            "probe": key,
            "configured": True,
            "path": str(path),
            "status": "fail",
            "message": f"probe parent is not a directory: {check_target}",
        }

    writable = os.access(check_target, os.W_OK)
    return {
        "probe": key,
        "configured": True,
        "path": str(path),
        "status": "pass" if writable else "fail",
        "message": "ok" if writable else f"probe parent is not writable: {check_target}",
    }


def build_startup_diagnostics(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = _read_env(environ)
    checks = [
        {"component": "auth", **_check_non_empty_json_object(env, "AGENTHUB_API_KEYS_JSON")},
        {"component": "auth", **_check_non_empty(env, "AGENTHUB_AUTH_TOKEN_SECRET")},
        {"component": "federation", **_check_non_empty_json_object(env, "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON")},
        {"component": "provenance", **_check_non_empty(env, "AGENTHUB_PROVENANCE_SIGNING_SECRET")},
    ]
    probes = [_path_probe(env, key) for key in PATH_PROBES]
    for row in checks:
        row["severity"] = "critical" if not bool(row.get("valid")) else "info"
    for row in probes:
        status = str(row.get("status", "skipped"))
        if status == "fail":
            row["severity"] = "high"
        elif status == "pass":
            row["severity"] = "info"
        else:
            row["severity"] = "low"
    missing_or_invalid = [row["env_var"] for row in checks if not row["valid"]]
    probe_failures = [row["probe"] for row in probes if row["status"] == "fail"]
    startup_ready = len(missing_or_invalid) == 0
    overall_ready = startup_ready and len(probe_failures) == 0
    severity_counts = {"critical": 0, "high": 0, "low": 0, "info": 0}
    for row in checks + probes:
        severity = str(row.get("severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "generated_at": utc_now_iso(),
        "access_enforcement_mode": access_mode(),
        "required_env_vars": list(REQUIRED_ENV_VARS),
        "checks": checks,
        "startup_ready": startup_ready,
        "probes": probes,
        "probe_failures": probe_failures,
        "overall_ready": overall_ready,
        "summary": {
            "check_failures": len(missing_or_invalid),
            "probe_failures": len(probe_failures),
            "overall_ready": overall_ready,
            "severity_counts": severity_counts,
        },
        "missing_or_invalid": missing_or_invalid,
    }
