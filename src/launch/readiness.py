from __future__ import annotations

import copy
import uuid
from typing import Any


def evaluate_onboarding_funnel(
    metrics: dict[str, int | float],
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    rules = thresholds or {
        "signup_rate_min": 0.15,
        "activation_rate_min": 0.4,
        "paid_rate_min": 0.2,
    }

    visitors = float(metrics.get("visitors", 0))
    signups = float(metrics.get("signups", 0))
    activated = float(metrics.get("activated", 0))
    paid = float(metrics.get("paid", 0))

    signup_rate = (signups / visitors) if visitors else 0.0
    activation_rate = (activated / signups) if signups else 0.0
    paid_rate = (paid / activated) if activated else 0.0

    checks = [
        {
            "name": "signup_rate",
            "value": round(signup_rate, 4),
            "threshold": rules["signup_rate_min"],
            "passed": signup_rate >= rules["signup_rate_min"],
        },
        {
            "name": "activation_rate",
            "value": round(activation_rate, 4),
            "threshold": rules["activation_rate_min"],
            "passed": activation_rate >= rules["activation_rate_min"],
        },
        {
            "name": "paid_rate",
            "value": round(paid_rate, 4),
            "threshold": rules["paid_rate_min"],
            "passed": paid_rate >= rules["paid_rate_min"],
        },
    ]
    return {
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "metrics": {
            "visitors": int(visitors),
            "signups": int(signups),
            "activated": int(activated),
            "paid": int(paid),
        },
    }


def run_demo_smoke(client: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    local = copy.deepcopy(manifest)
    suffix = uuid.uuid4().hex[:6]
    local["identity"]["id"] = f"launch-agent-{suffix}"
    local["identity"]["name"] = f"Launch Agent {suffix}"
    local["identity"]["version"] = "1.0.0"

    namespace = f"@launch{suffix}"
    create = client.post(
        "/v1/agents",
        json={"namespace": namespace, "manifest": local},
        headers={"X-API-Key": "dev-owner-key", "Idempotency-Key": f"launch-create-{suffix}"},
    )

    steps = [
        {"step": "healthz", "status_code": client.get("/healthz").status_code},
        {"step": "register_agent", "status_code": create.status_code},
        {"step": "get_agent", "status_code": client.get(f"/v1/agents/{namespace}:{local['identity']['id']}").status_code},
        {
            "step": "search_capabilities",
            "status_code": client.post("/v1/capabilities/search", json={"query": "invoice"}).status_code,
        },
        {
            "step": "operator_dashboard",
            "status_code": client.get(
                "/v1/operator/dashboard",
                params={"agent_id": f"{namespace}:{local['identity']['id']}", "query": "invoice"},
                headers={"X-API-Key": "partner-owner-key", "X-Operator-Role": "viewer"},
            ).status_code,
        },
    ]
    return {"passed": all(item["status_code"] < 400 for item in steps), "steps": steps}
