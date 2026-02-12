from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Any

from src.cost_governance.service import record_metering_event
from src.discovery.index import CapabilityRow, LIVE_CAPABILITY_INDEX
from src.policy import (
    evaluate_compatibility_policy,
    evaluate_contract_match_policy,
    evaluate_discovery_policy,
)


@dataclass
class CacheEntry:
    value: dict[str, Any]
    expires_at: float


def _tokenize(value: str) -> set[str]:
    return {token for token in value.lower().replace("-", " ").replace("_", " ").split() if token}


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

    def refresh_index(self, force: bool = False) -> None:
        LIVE_CAPABILITY_INDEX.refresh(force=force)

    def _constraints_filter(self, rows: list[CapabilityRow], constraints: dict[str, Any]) -> list[CapabilityRow]:
        max_cost = constraints.get("max_cost_usd")
        max_latency = constraints.get("max_latency_ms")
        min_trust = constraints.get("min_trust_score")
        required_permissions = {str(item) for item in constraints.get("required_permissions", [])}
        allowed_protocols = {str(item) for item in constraints.get("allowed_protocols", [])}

        filtered: list[CapabilityRow] = []
        for row in rows:
            if max_cost is not None and row.estimated_cost_usd > float(max_cost):
                continue
            if max_latency is not None and row.p95_latency_ms > int(max_latency):
                continue
            if min_trust is not None and row.trust_score < float(min_trust):
                continue
            row_permissions = set(row.permissions)
            if required_permissions and not required_permissions.issubset(row_permissions):
                continue
            row_protocols = set(row.protocols)
            if allowed_protocols and not row_protocols.intersection(allowed_protocols):
                continue
            filtered.append(row)
        return filtered

    def _semantic_score(self, query: str, row: CapabilityRow) -> tuple[float, dict[str, float]]:
        query_tokens = _tokenize(query)
        corpus_tokens = (
            _tokenize(row.capability_name)
            | _tokenize(row.description)
            | set(token.lower() for token in row.tags)
            | set(token.lower() for token in row.input_required)
            | set(token.lower() for token in row.output_fields)
        )
        overlap = len(query_tokens.intersection(corpus_tokens))
        lexical_relevance = overlap / max(1, len(query_tokens))
        trust = row.trust_score
        latency_efficiency = 1 / (1 + (row.p95_latency_ms / 250))
        cost_efficiency = 1 / (1 + (row.estimated_cost_usd / 0.05))
        freshness = 1 / (1 + (row.freshness_days / 14))
        usage_signal = min(1.0, math.log1p(max(row.usage_30d, 0)) / 10)
        score_breakdown = {
            "lexical_relevance": round(lexical_relevance, 6),
            "trust": round(trust, 6),
            "latency_efficiency": round(latency_efficiency, 6),
            "cost_efficiency": round(cost_efficiency, 6),
            "freshness": round(freshness, 6),
            "usage_signal": round(usage_signal, 6),
        }
        composite = (
            0.34 * score_breakdown["lexical_relevance"]
            + 0.24 * score_breakdown["trust"]
            + 0.14 * score_breakdown["latency_efficiency"]
            + 0.12 * score_breakdown["cost_efficiency"]
            + 0.08 * score_breakdown["freshness"]
            + 0.08 * score_breakdown["usage_signal"]
        )
        return round(composite, 6), score_breakdown

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

        snapshot = LIVE_CAPABILITY_INDEX.snapshot()
        rows = self._constraints_filter(snapshot["rows"], constraints)
        scored: list[dict[str, Any]] = []
        for row in rows:
            composite, score_breakdown = self._semantic_score(query=query, row=row)
            scored.append(
                {
                    "agent_id": row.agent_id,
                    "capability_id": row.capability_id,
                    "capability_name": row.capability_name,
                    "description": row.description,
                    "category": row.category,
                    "protocols": row.protocols,
                    "permissions": row.permissions,
                    "trust_score": row.trust_score,
                    "usage_30d": row.usage_30d,
                    "p95_latency_ms": row.p95_latency_ms,
                    "estimated_cost_usd": row.estimated_cost_usd,
                    "freshness_days": row.freshness_days,
                    "input_required": row.input_required,
                    "output_fields": row.output_fields,
                    "source": row.source,
                    "score_breakdown": score_breakdown,
                    "composite_score": composite,
                }
            )

        for row in scored:
            cost_bonus = row["score_breakdown"]["cost_efficiency"]
            row["cost_optimized_score"] = round((0.7 * row["composite_score"]) + (0.3 * cost_bonus), 6)

        scored.sort(key=lambda r: (-r["cost_optimized_score"], r["estimated_cost_usd"], r["p95_latency_ms"]))

        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.semantic_search",
            cost_usd=max(0.0002, 0.00005 * len(scored)),
            metadata={
                "query": query,
                "result_count": len(scored),
                "index_sources": snapshot["source_counts"],
            },
        )
        return {
            "data": scored,
            "ttl_hint_seconds": self.ttl_seconds,
            "constraints": constraints,
            "cache": "miss",
            "index_metadata": {
                "source_counts": snapshot["source_counts"],
                "refreshed_at_epoch": snapshot["refreshed_at_epoch"],
            },
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

        snapshot = LIVE_CAPABILITY_INDEX.snapshot()
        payload = {
            "mode": "contract",
            "input_required": sorted(input_required),
            "output_required": sorted(output_required),
            "max_cost_usd": max_cost_usd,
            "index_refreshed_at_epoch": snapshot["refreshed_at_epoch"],
        }
        cached = self._get_cached(payload)
        if cached:
            return cached

        request_input = set(input_required)
        request_output = set(output_required)
        data: list[dict[str, Any]] = []
        for row in snapshot["rows"]:
            if max_cost_usd is not None and row.estimated_cost_usd > float(max_cost_usd):
                continue
            cap_input = set(row.input_required)
            cap_output = set(row.output_fields)
            exact = cap_input == request_input and cap_output == request_output
            backward_compatible = cap_input.issubset(request_input) and request_output.issubset(cap_output)
            if not backward_compatible and not exact:
                continue
            compatibility = "exact" if exact else "backward_compatible"
            score = 1.0 if exact else 0.82
            score += 0.12 * row.trust_score
            score += 0.06 * (1 / (1 + (row.estimated_cost_usd / 0.05)))
            data.append(
                {
                    "agent_id": row.agent_id,
                    "capability_id": row.capability_id,
                    "capability_name": row.capability_name,
                    "compatibility": compatibility,
                    "compatibility_score": round(score, 6),
                    "estimated_cost_usd": row.estimated_cost_usd,
                    "p95_latency_ms": row.p95_latency_ms,
                    "input_required": row.input_required,
                    "output_fields": row.output_fields,
                    "source": row.source,
                }
            )

        data.sort(key=lambda row: (-row["compatibility_score"], row["estimated_cost_usd"], row["p95_latency_ms"]))
        out = {
            "data": data,
            "ttl_hint_seconds": self.ttl_seconds,
            "cache": "miss",
            "index_metadata": {
                "source_counts": snapshot["source_counts"],
                "refreshed_at_epoch": snapshot["refreshed_at_epoch"],
            },
            "policy_decision": policy_decision,
        }
        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.contract_match",
            cost_usd=max(0.00015, 0.00005 * len(data)),
            metadata={"result_count": len(data), "index_sources": snapshot["source_counts"]},
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

        snapshot = LIVE_CAPABILITY_INDEX.snapshot()
        payload = {
            "mode": "compat",
            "schema": my_schema,
            "agent_id": agent_id,
            "index_refreshed_at_epoch": snapshot["refreshed_at_epoch"],
        }
        cached = self._get_cached(payload)
        if cached:
            return cached

        required = set(my_schema.get("required", []))
        rows = [row for row in snapshot["rows"] if row.agent_id == agent_id]
        reports: list[dict[str, Any]] = []
        for row in rows:
            cap_required = set(row.input_required)
            missing = sorted(cap_required - required)
            reports.append(
                {
                    "capability_id": row.capability_id,
                    "compatibility": "compatible" if not missing else "incompatible",
                    "missing_required_inputs": missing,
                }
            )

        out = {
            "agent_id": agent_id,
            "request_required": sorted(required),
            "capability_reports": reports,
            "ttl_hint_seconds": self.ttl_seconds,
            "cache": "miss",
            "index_metadata": {
                "source_counts": snapshot["source_counts"],
                "refreshed_at_epoch": snapshot["refreshed_at_epoch"],
            },
            "policy_decision": policy_decision,
        }
        record_metering_event(
            actor="runtime.discovery",
            operation="discovery.compatibility_report",
            cost_usd=max(0.0001, 0.00003 * len(reports)),
            metadata={"agent_id": agent_id, "result_count": len(reports), "index_sources": snapshot["source_counts"]},
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
