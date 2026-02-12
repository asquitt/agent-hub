from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from src.cost_governance.service import record_metering_event
from src.policy import (
    evaluate_compatibility_policy,
    evaluate_contract_match_policy,
    evaluate_discovery_policy,
)
from tools.capability_search.mock_engine import (
    list_agent_capabilities,
    match_capabilities,
    search_capabilities,
)


@dataclass
class CacheEntry:
    value: dict[str, Any]
    expires_at: float


class DiscoveryService:
    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, CacheEntry] = {}

    def _cache_key(self, payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _get_cached(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        key = self._cache_key(payload)
        entry = self._cache.get(key)
        now = time.time()
        if entry and entry.expires_at > now:
            cached = dict(entry.value)
            cached["cache"] = "hit"
            return cached
        if key in self._cache:
            del self._cache[key]
        return None

    def _put_cache(self, payload: dict[str, Any], value: dict[str, Any]) -> None:
        self._cache[self._cache_key(payload)] = CacheEntry(value=value, expires_at=time.time() + self.ttl_seconds)

    def semantic_discovery(self, query: str, constraints: dict[str, Any] | None = None) -> dict[str, Any]:
        constraints = constraints or {}
        policy_decision = evaluate_discovery_policy(
            action="semantic_search",
            actor="runtime.discovery",
            query=query,
            constraints=constraints,
        )
        if not policy_decision["allowed"]:
            return {
                "data": [],
                "ttl_hint_seconds": self.ttl_seconds,
                "constraints": constraints,
                "cache": "miss",
                "policy_decision": policy_decision,
            }

        max_cost = constraints.get("max_cost_usd")
        filters = dict(constraints)

        result = search_capabilities(
            query=query,
            filters=filters,
            pagination={"mode": "offset", "offset": 0, "limit": 50},
        )

        rows = result["data"]
        if max_cost is not None:
            rows = [r for r in rows if r["estimated_cost_usd"] <= float(max_cost)]

        # Cost-constraint optimization for agent-native callers.
        for row in rows:
            cost_bonus = row["score_breakdown"]["cost_efficiency"]
            row["cost_optimized_score"] = round((0.7 * row["composite_score"]) + (0.3 * cost_bonus), 6)

        rows.sort(key=lambda r: (-r["cost_optimized_score"], r["estimated_cost_usd"], r["p95_latency_ms"]))
        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.semantic_search",
            cost_usd=max(0.0002, 0.00005 * len(rows)),
            metadata={"query": query, "result_count": len(rows)},
        )

        return {
            "data": rows,
            "ttl_hint_seconds": self.ttl_seconds,
            "constraints": constraints,
            "cache": "miss",
            "policy_decision": policy_decision,
        }

    def contract_match(self, input_required: list[str], output_required: list[str], max_cost_usd: float | None = None) -> dict[str, Any]:
        policy_decision = evaluate_contract_match_policy(
            actor="runtime.discovery",
            input_required=input_required,
            output_required=output_required,
            constraints={"max_cost_usd": max_cost_usd},
        )
        if not policy_decision["allowed"]:
            return {
                "data": [],
                "ttl_hint_seconds": self.ttl_seconds,
                "cache": "miss",
                "policy_decision": policy_decision,
            }

        payload = {
            "mode": "contract",
            "input_required": sorted(input_required),
            "output_required": sorted(output_required),
            "max_cost_usd": max_cost_usd,
        }
        cached = self._get_cached(payload)
        if cached:
            return cached

        result = match_capabilities(
            input_required=input_required,
            output_required=output_required,
            compatibility_mode="backward_compatible",
            filters={"max_cost_usd": max_cost_usd} if max_cost_usd is not None else None,
            pagination={"mode": "offset", "offset": 0, "limit": 50},
        )

        out = {
            "data": result["data"],
            "ttl_hint_seconds": self.ttl_seconds,
            "cache": "miss",
            "policy_decision": policy_decision,
        }
        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.contract_match",
            cost_usd=max(0.00015, 0.00005 * len(result["data"])),
            metadata={"result_count": len(result["data"])},
        )
        self._put_cache(payload, out)
        return out

    def compatibility_report(self, my_schema: dict[str, Any], agent_id: str) -> dict[str, Any]:
        policy_decision = evaluate_compatibility_policy(
            actor="runtime.discovery",
            my_schema=my_schema,
            agent_id=agent_id,
        )
        if not policy_decision["allowed"]:
            return {
                "agent_id": agent_id,
                "request_required": [],
                "capability_reports": [],
                "ttl_hint_seconds": self.ttl_seconds,
                "cache": "miss",
                "policy_decision": policy_decision,
            }

        payload = {"mode": "compat", "schema": my_schema, "agent_id": agent_id}
        cached = self._get_cached(payload)
        if cached:
            return cached

        required = set(my_schema.get("required", []))
        capabilities = list_agent_capabilities(agent_id).get("capabilities", [])
        reports = []
        for cap in capabilities:
            in_required = set(cap.get("input_schema", {}).get("required", []))
            compatibility = "compatible" if in_required.issubset(required) else "incompatible"
            reports.append(
                {
                    "capability_id": cap["capability_id"],
                    "compatibility": compatibility,
                    "missing_required_inputs": sorted(in_required - required),
                }
            )

        out = {
            "agent_id": agent_id,
            "request_required": sorted(required),
            "capability_reports": reports,
            "ttl_hint_seconds": self.ttl_seconds,
            "cache": "miss",
            "policy_decision": policy_decision,
        }
        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.compatibility_report",
            cost_usd=max(0.0001, 0.00003 * len(reports)),
            metadata={"agent_id": agent_id, "result_count": len(reports)},
        )
        self._put_cache(payload, out)
        return out


DISCOVERY_SERVICE = DiscoveryService(ttl_seconds=120)


def mcp_tool_declarations() -> list[dict[str, Any]]:
    return [
        {
            "name": "search_capabilities",
            "description": "Search capability catalog with structured constraints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "constraints": {"type": "object"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "get_agent_manifest",
            "description": "Get agent manifest by id and version.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string"},
                    "version": {"type": "string"},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "check_compatibility",
            "description": "Check schema compatibility with target agent capabilities.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "my_schema": {"type": "object"},
                    "agent_id": {"type": "string"},
                },
                "required": ["my_schema", "agent_id"],
            },
        },
    ]
