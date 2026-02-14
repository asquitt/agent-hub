"""Runtime Integrity Attestation — continuous sandbox fingerprint verification.

Provides runtime environment attestation for agent sandboxes:
- Environment fingerprinting (config hash, dependency hash, runtime version)
- Periodic integrity checks against baseline
- Tamper detection with drift scoring
- Attestation reports for compliance evidence
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.integrity")

# In-memory stores
_MAX_RECORDS = 10_000
_baselines: dict[str, dict[str, Any]] = {}  # sandbox_id -> baseline
_attestations: list[dict[str, Any]] = []  # attestation history
_integrity_alerts: list[dict[str, Any]] = []  # tamper alerts


def _compute_fingerprint(env_data: dict[str, Any]) -> str:
    """Compute a SHA-256 fingerprint of environment data."""
    canonical = json.dumps(env_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def register_baseline(
    *,
    sandbox_id: str,
    agent_id: str,
    environment: dict[str, Any],
    runtime_version: str = "1.0.0",
    dependencies: list[str] | None = None,
) -> dict[str, Any]:
    """Register the integrity baseline for a sandbox environment."""
    now = time.time()

    env_fingerprint = _compute_fingerprint(environment)
    dep_fingerprint = _compute_fingerprint({"deps": sorted(dependencies or [])})

    baseline: dict[str, Any] = {
        "baseline_id": f"bl-{uuid.uuid4().hex[:12]}",
        "sandbox_id": sandbox_id,
        "agent_id": agent_id,
        "environment_fingerprint": env_fingerprint,
        "dependency_fingerprint": dep_fingerprint,
        "runtime_version": runtime_version,
        "environment": environment,
        "dependencies": sorted(dependencies or []),
        "registered_at": now,
        "check_count": 0,
        "last_check_at": None,
        "status": "active",
    }

    _baselines[sandbox_id] = baseline
    _log.info("baseline registered: sandbox=%s env_fp=%s", sandbox_id, env_fingerprint[:16])
    return baseline


def check_integrity(
    *,
    sandbox_id: str,
    current_environment: dict[str, Any],
    current_dependencies: list[str] | None = None,
    current_runtime_version: str = "1.0.0",
) -> dict[str, Any]:
    """Check current environment against the registered baseline."""
    baseline = _baselines.get(sandbox_id)
    if baseline is None:
        raise KeyError(f"no baseline registered for sandbox: {sandbox_id}")

    now = time.time()
    baseline["check_count"] += 1
    baseline["last_check_at"] = now

    current_env_fp = _compute_fingerprint(current_environment)
    current_dep_fp = _compute_fingerprint({"deps": sorted(current_dependencies or [])})

    env_match = current_env_fp == baseline["environment_fingerprint"]
    dep_match = current_dep_fp == baseline["dependency_fingerprint"]
    version_match = current_runtime_version == baseline["runtime_version"]

    # Compute drift details
    drifts: list[dict[str, str]] = []
    if not env_match:
        drifts.append({"component": "environment", "expected": baseline["environment_fingerprint"][:16], "actual": current_env_fp[:16]})
    if not dep_match:
        drifts.append({"component": "dependencies", "expected": baseline["dependency_fingerprint"][:16], "actual": current_dep_fp[:16]})
    if not version_match:
        drifts.append({"component": "runtime_version", "expected": baseline["runtime_version"], "actual": current_runtime_version})

    # Drift score: 0 = perfect, 100 = fully tampered
    drift_score = 0.0
    if not env_match:
        drift_score += 50.0
    if not dep_match:
        drift_score += 30.0
    if not version_match:
        drift_score += 20.0

    intact = len(drifts) == 0

    attestation: dict[str, Any] = {
        "attestation_id": f"att-{uuid.uuid4().hex[:12]}",
        "sandbox_id": sandbox_id,
        "agent_id": baseline["agent_id"],
        "intact": intact,
        "drift_score": drift_score,
        "drifts": drifts,
        "check_number": baseline["check_count"],
        "checked_at": now,
    }
    _attestations.append(attestation)
    if len(_attestations) > _MAX_RECORDS:
        _attestations[:] = _attestations[-_MAX_RECORDS:]

    if not intact:
        alert: dict[str, Any] = {
            "alert_id": f"ia-{uuid.uuid4().hex[:12]}",
            "sandbox_id": sandbox_id,
            "agent_id": baseline["agent_id"],
            "severity": "critical" if drift_score >= 50 else "warning",
            "drift_score": drift_score,
            "drifts": drifts,
            "detected_at": now,
        }
        _integrity_alerts.append(alert)
        if len(_integrity_alerts) > _MAX_RECORDS:
            _integrity_alerts[:] = _integrity_alerts[-_MAX_RECORDS:]
        _log.warning("integrity drift: sandbox=%s score=%.1f drifts=%d", sandbox_id, drift_score, len(drifts))

    return attestation


def get_baseline(sandbox_id: str) -> dict[str, Any]:
    """Get the registered baseline for a sandbox."""
    baseline = _baselines.get(sandbox_id)
    if baseline is None:
        raise KeyError(f"no baseline registered for sandbox: {sandbox_id}")
    return baseline


def get_attestation_history(
    *,
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get attestation check history."""
    results = _attestations
    if sandbox_id:
        results = [a for a in results if a["sandbox_id"] == sandbox_id]
    if agent_id:
        results = [a for a in results if a["agent_id"] == agent_id]
    return list(reversed(results[-limit:]))


def get_integrity_alerts(
    *,
    sandbox_id: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get integrity tamper alerts."""
    results = _integrity_alerts
    if sandbox_id:
        results = [a for a in results if a["sandbox_id"] == sandbox_id]
    if severity:
        results = [a for a in results if a["severity"] == severity]
    return list(reversed(results[-limit:]))


def generate_attestation_report(sandbox_id: str) -> dict[str, Any]:
    """Generate a compliance attestation report for a sandbox."""
    baseline = _baselines.get(sandbox_id)
    if baseline is None:
        raise KeyError(f"no baseline registered for sandbox: {sandbox_id}")

    history = get_attestation_history(sandbox_id=sandbox_id)
    alerts = get_integrity_alerts(sandbox_id=sandbox_id)

    intact_checks = sum(1 for a in history if a["intact"])
    total_checks = len(history)
    integrity_rate = round(intact_checks / total_checks, 3) if total_checks > 0 else 1.0

    return {
        "sandbox_id": sandbox_id,
        "agent_id": baseline["agent_id"],
        "baseline_registered_at": baseline["registered_at"],
        "total_checks": total_checks,
        "intact_checks": intact_checks,
        "integrity_rate": integrity_rate,
        "alert_count": len(alerts),
        "critical_alerts": sum(1 for a in alerts if a["severity"] == "critical"),
        "current_status": "intact" if (history and history[0]["intact"]) else ("compromised" if history else "unchecked"),
        "generated_at": time.time(),
    }


def reset_for_tests() -> None:
    """Clear all integrity data for testing."""
    _baselines.clear()
    _attestations.clear()
    _integrity_alerts.clear()
