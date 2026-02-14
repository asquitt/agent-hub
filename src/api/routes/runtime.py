from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth import require_api_key
from src.runtime.constants import (
    MAX_CPU_CORES,
    MAX_DISK_IO_MB,
    MAX_MEMORY_MB,
    MAX_TIMEOUT_SECONDS,
    VALID_NETWORK_MODES,
)
from src.runtime.audit import export_sandbox_evidence
from src.runtime.integrity import (
    check_integrity,
    generate_attestation_report,
    get_attestation_history,
    get_baseline,
    get_integrity_alerts,
    register_baseline,
)
from src.runtime.integration import create_delegated_sandbox, create_leased_sandbox
from src.runtime.sandbox import (
    complete_execution,
    create_sandbox,
    get_execution,
    get_logs,
    get_metrics,
    get_sandbox,
    list_executions,
    list_sandboxes,
    start_execution,
    terminate_sandbox,
)
from src.runtime.storage import RUNTIME_STORAGE

router = APIRouter(tags=["runtime"])


# --- Request models ---


class CreateProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=64)
    description: str = Field(default="", max_length=500)
    cpu_cores: float = Field(gt=0, le=MAX_CPU_CORES)
    memory_mb: int = Field(gt=0, le=MAX_MEMORY_MB)
    timeout_seconds: int = Field(gt=0, le=MAX_TIMEOUT_SECONDS)
    network_mode: str = Field(default="disabled")
    disk_io_mb: int = Field(gt=0, le=MAX_DISK_IO_MB)


class CreateSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=2)
    profile_id: str | None = None
    profile_name: str | None = None
    resource_limits: dict[str, Any] | None = None
    delegation_id: str | None = None
    lease_id: str | None = None


class ExecuteInSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_data: dict[str, Any]


class CompleteSandboxExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_data: dict[str, Any] | None = None
    exit_code: int = 0
    error_message: str | None = None


class TerminateSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="manual_termination", min_length=3)


class DelegatedSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delegation_id: str = Field(min_length=2)
    agent_id: str = Field(min_length=2)
    profile_name: str | None = None
    resource_limits: dict[str, Any] | None = None


class LeasedSandboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(min_length=2)
    agent_id: str = Field(min_length=2)
    profile_name: str | None = None
    resource_limits: dict[str, Any] | None = None


# --- Profile endpoints ---


@router.post("/v1/runtime/profiles")
def create_profile(
    request: CreateProfileRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    if request.network_mode not in VALID_NETWORK_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"invalid network_mode: {request.network_mode}, must be one of {sorted(VALID_NETWORK_MODES)}",
        )
    try:
        profile = RUNTIME_STORAGE.insert_profile(
            name=request.name,
            description=request.description,
            cpu_cores=request.cpu_cores,
            memory_mb=request.memory_mb,
            timeout_seconds=request.timeout_seconds,
            network_mode=request.network_mode,
            disk_io_mb=request.disk_io_mb,
            created_by=owner,
        )
        return dict(profile)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/v1/runtime/profiles")
def list_profiles(
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    profiles = RUNTIME_STORAGE.list_profiles()
    return {"profiles": [dict(p) for p in profiles], "total": len(profiles)}


@router.get("/v1/runtime/profiles/{profile_id}")
def get_profile(
    profile_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        profile = RUNTIME_STORAGE.get_profile(profile_id)
        return dict(profile)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/v1/runtime/profiles/{profile_id}")
def delete_profile(
    profile_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        RUNTIME_STORAGE.delete_profile(profile_id)
        return {"deleted": True, "profile_id": profile_id}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --- Sandbox endpoints ---


@router.post("/v1/runtime/sandboxes")
def post_create_sandbox(
    request: CreateSandboxRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        instance = create_sandbox(
            agent_id=request.agent_id,
            owner=owner,
            profile_id=request.profile_id,
            profile_name=request.profile_name,
            resource_limits=request.resource_limits,
            delegation_id=request.delegation_id,
            lease_id=request.lease_id,
        )
        return dict(instance)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/runtime/sandboxes")
def get_list_sandboxes(
    owner: str = Depends(require_api_key),
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    sandboxes = list_sandboxes(owner=owner, agent_id=agent_id, status=status, limit=limit)
    return {"sandboxes": [dict(s) for s in sandboxes], "total": len(sandboxes)}


@router.get("/v1/runtime/sandboxes/{sandbox_id}")
def get_sandbox_status(
    sandbox_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        instance = get_sandbox(sandbox_id, owner)
        return dict(instance)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/v1/runtime/sandboxes/{sandbox_id}/execute")
def post_execute_in_sandbox(
    sandbox_id: str,
    request: ExecuteInSandboxRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        execution = start_execution(sandbox_id, owner=owner, input_data=request.input_data)
        return dict(execution)
    except (KeyError, ValueError) as exc:
        status = 404 if "not found" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/v1/runtime/sandboxes/{sandbox_id}/complete")
def post_complete_execution(
    sandbox_id: str,
    request: CompleteSandboxExecutionRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    # Find the active execution for this sandbox
    executions = list_executions(sandbox_id=sandbox_id, status="running")
    if not executions:
        raise HTTPException(status_code=404, detail="no running execution found")
    try:
        execution = complete_execution(
            executions[0]["execution_id"],
            owner=owner,
            output_data=request.output_data,
            exit_code=request.exit_code,
            error_message=request.error_message,
        )
        return dict(execution)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.post("/v1/runtime/sandboxes/{sandbox_id}/terminate")
def post_terminate_sandbox(
    sandbox_id: str,
    request: TerminateSandboxRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        instance = terminate_sandbox(sandbox_id, owner=owner, reason=request.reason)
        return dict(instance)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/v1/runtime/sandboxes/{sandbox_id}/logs")
def get_sandbox_logs(
    sandbox_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        logs = get_logs(sandbox_id, owner)
        return {"logs": [dict(log) for log in logs], "total": len(logs)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/v1/runtime/sandboxes/{sandbox_id}/metrics")
def get_sandbox_metrics(
    sandbox_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        metrics = get_metrics(sandbox_id, owner)
        return {"metrics": [dict(m) for m in metrics], "total": len(metrics)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/v1/runtime/executions")
def get_list_executions(
    owner: str = Depends(require_api_key),
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    executions = list_executions(
        sandbox_id=sandbox_id, agent_id=agent_id, status=status,
    )
    # Filter to only show executions owned by the authenticated user
    owned = [e for e in executions if e["owner"] == owner]
    return {"executions": [dict(e) for e in owned], "total": len(owned)}


@router.get("/v1/runtime/executions/{execution_id}")
def get_execution_detail(
    execution_id: str,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        execution = get_execution(execution_id, owner)
        return dict(execution)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# --- Integration endpoints ---


@router.post("/v1/runtime/sandboxes/delegated")
def post_delegated_sandbox(
    request: DelegatedSandboxRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        instance = create_delegated_sandbox(
            delegation_id=request.delegation_id,
            agent_id=request.agent_id,
            owner=owner,
            profile_name=request.profile_name,
            resource_limits=request.resource_limits,
        )
        return dict(instance)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/v1/runtime/sandboxes/leased")
def post_leased_sandbox(
    request: LeasedSandboxRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        instance = create_leased_sandbox(
            lease_id=request.lease_id,
            agent_id=request.agent_id,
            owner=owner,
            profile_name=request.profile_name,
            resource_limits=request.resource_limits,
        )
        return dict(instance)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/runtime/audit/evidence")
def get_audit_evidence(
    owner: str = Depends(require_api_key),
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    return export_sandbox_evidence(
        actor=owner,
        sandbox_id=sandbox_id,
        agent_id=agent_id,
        limit=limit,
    )


# ── Runtime Integrity Attestation ─────────────────────────────────


class RegisterBaselineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sandbox_id: str = Field(min_length=1, max_length=256)
    agent_id: str = Field(min_length=1, max_length=256)
    environment: dict[str, Any]
    runtime_version: str = Field(default="1.0.0", max_length=32)
    dependencies: list[str] | None = None


class CheckIntegrityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sandbox_id: str = Field(min_length=1, max_length=256)
    current_environment: dict[str, Any]
    current_dependencies: list[str] | None = None
    current_runtime_version: str = Field(default="1.0.0", max_length=32)


@router.post("/v1/runtime/integrity/baselines")
def post_register_baseline(
    request: RegisterBaselineRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Register an integrity baseline for a sandbox."""
    return register_baseline(
        sandbox_id=request.sandbox_id,
        agent_id=request.agent_id,
        environment=request.environment,
        runtime_version=request.runtime_version,
        dependencies=request.dependencies,
    )


@router.get("/v1/runtime/integrity/baselines/{sandbox_id}")
def get_integrity_baseline(
    sandbox_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get the registered baseline for a sandbox."""
    try:
        return get_baseline(sandbox_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/v1/runtime/integrity/check")
def post_check_integrity(
    request: CheckIntegrityRequest,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Check current environment against the baseline."""
    try:
        return check_integrity(
            sandbox_id=request.sandbox_id,
            current_environment=request.current_environment,
            current_dependencies=request.current_dependencies,
            current_runtime_version=request.current_runtime_version,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/v1/runtime/integrity/history")
def get_integrity_history(
    sandbox_id: str | None = None,
    agent_id: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get attestation check history."""
    history = get_attestation_history(sandbox_id=sandbox_id, agent_id=agent_id)
    return {"count": len(history), "attestations": history}


@router.get("/v1/runtime/integrity/alerts")
def get_integrity_alerts_endpoint(
    sandbox_id: str | None = None,
    severity: str | None = None,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get integrity tamper alerts."""
    alerts = get_integrity_alerts(sandbox_id=sandbox_id, severity=severity)
    return {"count": len(alerts), "alerts": alerts}


@router.get("/v1/runtime/integrity/report/{sandbox_id}")
def get_integrity_report(
    sandbox_id: str,
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Generate an attestation report for a sandbox."""
    try:
        return generate_attestation_report(sandbox_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
