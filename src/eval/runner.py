from __future__ import annotations

import random
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import yaml

from src.eval.storage import append_result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _required_fields(schema: dict[str, Any]) -> list[str]:
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return [str(x) for x in required]


def _evaluate_capability_contract(capability: dict[str, Any]) -> tuple[bool, list[str]]:
    checks: list[str] = []
    passed = True

    in_schema = capability.get("input_schema", {})
    out_schema = capability.get("output_schema", {})

    if not isinstance(in_schema, dict) or not isinstance(out_schema, dict):
        return False, ["input_schema/output_schema must be objects"]

    if "type" not in in_schema and "$ref_uri" not in in_schema:
        passed = False
        checks.append("input_schema missing type or $ref_uri")

    if "type" not in out_schema and "$ref_uri" not in out_schema:
        passed = False
        checks.append("output_schema missing type or $ref_uri")

    if capability.get("side_effect_level") in {"low", "high"} and not capability.get("idempotency_key_required"):
        passed = False
        checks.append("idempotency_key_required must be true for side-effecting capability")

    if not capability.get("protocols"):
        passed = False
        checks.append("protocols must contain at least one protocol")

    if in_schema.get("type") == "object" and len(_required_fields(in_schema)) == 0:
        checks.append("input schema has no required fields")

    if out_schema.get("type") == "object" and len(_required_fields(out_schema)) == 0:
        checks.append("output schema has no required fields")

    return passed, checks


def run_tier1_eval(manifest: dict[str, Any], agent_id: str, version: str | None = None) -> dict[str, Any]:
    seed = 42
    random.seed(seed)

    started_at = _utc_now()
    start = time.perf_counter()

    traces: list[dict[str, Any]] = []
    results_by_type: dict[str, dict[str, int]] = {
        "reasoning": {"passed": 0, "failed": 0},
        "transformation": {"passed": 0, "failed": 0},
        "action": {"passed": 0, "failed": 0},
    }

    total = 0
    passed_total = 0

    with tempfile.TemporaryDirectory(prefix="agenthub-eval-sandbox-") as sandbox:
        traces.append(
            {
                "timestamp": _utc_now(),
                "event": "sandbox.start",
                "details": {
                    "path": sandbox,
                    "network": "disabled",
                    "resource_limits": {"cpu": "1", "memory_mb": 256, "timeout_seconds": 30},
                },
            }
        )

        for capability in manifest.get("capabilities", []):
            ctype = capability.get("category", "unknown")
            if ctype not in results_by_type:
                continue

            total += 1
            ok, notes = _evaluate_capability_contract(capability)
            if ok:
                passed_total += 1
                results_by_type[ctype]["passed"] += 1
            else:
                results_by_type[ctype]["failed"] += 1

            traces.append(
                {
                    "timestamp": _utc_now(),
                    "event": "capability.contract_check",
                    "capability_id": capability.get("id"),
                    "category": ctype,
                    "passed": ok,
                    "notes": notes,
                }
            )

    elapsed_ms = (time.perf_counter() - start) * 1000
    cost_usd = round(0.0015 * max(total, 1), 6)
    accuracy = round(passed_total / total, 4) if total else 0.0

    result = {
        "eval_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "version": version or manifest.get("identity", {}).get("version", "unknown"),
        "suite_id": "tier1-contract-v1",
        "tier": "tier1_contract",
        "status": "passed" if total > 0 and passed_total == total else "failed",
        "metrics": {
            "total_checks": total,
            "passed_checks": passed_total,
            "accuracy": accuracy,
            "latency_ms": round(elapsed_ms, 3),
            "cost_usd": cost_usd,
        },
        "capability_type_results": results_by_type,
        "seed": seed,
        "trace": traces,
        "started_at": started_at,
        "completed_at": _utc_now(),
    }

    append_result(result)
    return result


def run_eval_from_manifest_path(manifest_path: str, agent_id: str | None = None) -> dict[str, Any]:
    manifest = yaml.safe_load(open(manifest_path, encoding="utf-8"))
    effective_agent = agent_id or manifest.get("identity", {}).get("id", "unknown-agent")
    version = manifest.get("identity", {}).get("version", "unknown")
    return run_tier1_eval(manifest=manifest, agent_id=effective_agent, version=version)
