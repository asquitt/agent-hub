"""Deterministic mock engine for capability search API contract verification (S02)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_WEIGHTS = {
    "capability_relevance": 0.30,
    "trust_score": 0.25,
    "usage_volume": 0.15,
    "cost_efficiency": 0.10,
    "latency": 0.10,
    "freshness": 0.10,
}
KEYWORD_SYNONYMS = {
    "invoice": {"bill", "billing"},
    "billing": {"invoice", "bill"},
    "ticket": {"incident", "case"},
    "incident": {"ticket", "case"},
    "classify": {"triage", "categorize"},
    "payment": {"payout", "pay"},
}


def load_mock_capabilities() -> list[dict[str, Any]]:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "capability_search"
        / "fixtures"
        / "mock_capabilities.json"
    )
    return json.loads(fixture.read_text(encoding="utf-8"))


def _tokenize(text: str) -> set[str]:
    return {t.strip(".,:;!?()[]{}\"'").lower() for t in text.split() if t.strip()}


def _safe_minmax_normalize(values: list[float], invert: bool = False) -> list[float]:
    if not values:
        return []
    v_min = min(values)
    v_max = max(values)
    if v_min == v_max:
        return [1.0 for _ in values]

    out: list[float] = []
    for value in values:
        score = (value - v_min) / (v_max - v_min)
        out.append(1.0 - score if invert else score)
    return out


def _normalize_weights(weights: dict[str, float] | None) -> dict[str, float]:
    selected = dict(DEFAULT_WEIGHTS)
    if weights:
        for key, value in weights.items():
            if key not in selected:
                continue
            if value < 0:
                raise ValueError(f"weight must be non-negative: {key}")
            selected[key] = value

    total = sum(selected.values())
    if total <= 0:
        raise ValueError("weight sum must be > 0")

    return {key: value / total for key, value in selected.items()}


def _validate_filters(filters: dict[str, Any] | None) -> None:
    if not filters:
        return
    if "max_latency_ms" in filters and filters["max_latency_ms"] <= 0:
        raise ValueError("max_latency_ms must be > 0")
    if "max_cost_usd" in filters and filters["max_cost_usd"] < 0:
        raise ValueError("max_cost_usd must be >= 0")
    if "min_trust_score" in filters:
        trust = filters["min_trust_score"]
        if trust < 0 or trust > 1:
            raise ValueError("min_trust_score must be in [0,1]")


def _policy_rejection_reasons(candidate: dict[str, Any], filters: dict[str, Any] | None) -> list[dict[str, Any]]:
    reasons: list[dict[str, Any]] = []
    if not filters:
        return reasons

    if "min_trust_score" in filters and candidate["trust_score"] < filters["min_trust_score"]:
        reasons.append(
            {
                "code": "policy.min_trust_score",
                "detail": "candidate trust score below minimum threshold",
                "expected": filters["min_trust_score"],
                "observed": candidate["trust_score"],
            }
        )

    if "max_latency_ms" in filters and candidate["p95_latency_ms"] > filters["max_latency_ms"]:
        reasons.append(
            {
                "code": "policy.max_latency_ms",
                "detail": "candidate latency exceeds allowed maximum",
                "expected": filters["max_latency_ms"],
                "observed": candidate["p95_latency_ms"],
            }
        )

    if "max_cost_usd" in filters and candidate["estimated_cost_usd"] > filters["max_cost_usd"]:
        reasons.append(
            {
                "code": "policy.max_cost_usd",
                "detail": "candidate estimated cost exceeds allowed maximum",
                "expected": filters["max_cost_usd"],
                "observed": candidate["estimated_cost_usd"],
            }
        )

    required_permissions = set(filters.get("required_permissions", []))
    if required_permissions and not required_permissions.issubset(set(candidate.get("permissions", []))):
        reasons.append(
            {
                "code": "policy.required_permissions",
                "detail": "candidate missing one or more required permissions",
                "expected": sorted(required_permissions),
                "observed": sorted(set(candidate.get("permissions", []))),
            }
        )

    allowed_protocols = set(filters.get("allowed_protocols", []))
    if allowed_protocols and not allowed_protocols.intersection(set(candidate.get("protocols", []))):
        reasons.append(
            {
                "code": "policy.allowed_protocols",
                "detail": "candidate does not support any allowed protocol",
                "expected": sorted(allowed_protocols),
                "observed": sorted(set(candidate.get("protocols", []))),
            }
        )

    return reasons


def _passes_policy_filters(candidate: dict[str, Any], filters: dict[str, Any] | None) -> bool:
    return len(_policy_rejection_reasons(candidate, filters)) == 0


def _semantic_relevance(query_tokens: set[str], candidate: dict[str, Any], ranking_mode: str) -> tuple[float, list[dict[str, Any]]]:
    name_tokens = _tokenize(candidate["capability_name"])
    description_tokens = _tokenize(candidate["description"])
    tag_tokens = {token.lower() for token in candidate.get("tags", [])}
    corpus_tokens = name_tokens | description_tokens | tag_tokens
    overlap_tokens = query_tokens.intersection(corpus_tokens)

    if not query_tokens:
        return 0.0, [{"type": "semantic", "detail": "query is empty after tokenization"}]

    # Baseline: simple overlap ratio used for D02.
    if ranking_mode == "baseline":
        baseline = len(overlap_tokens) / max(1, len(query_tokens))
        if baseline <= 0:
            return 0.0, [{"type": "semantic", "detail": "no token overlap between query and candidate"}]
        return min(1.0, baseline), [
            {"type": "semantic", "detail": f"{len(overlap_tokens)} token(s) overlapped with query"},
        ]

    # S18 v2: weighted semantic scoring with phrase/name emphasis and synonym support.
    synonym_hits = 0
    for token in query_tokens:
        synonyms = KEYWORD_SYNONYMS.get(token, set())
        if synonyms.intersection(corpus_tokens):
            synonym_hits += 1

    name_overlap = len(query_tokens.intersection(name_tokens))
    desc_overlap = len(query_tokens.intersection(description_tokens))
    tag_overlap = len(query_tokens.intersection(tag_tokens))

    base = (
        (2.0 * name_overlap)
        + (1.2 * tag_overlap)
        + (1.0 * desc_overlap)
        + (0.6 * synonym_hits)
    ) / max(1.0, 2.0 * len(query_tokens))

    phrase_bonus = 0.0
    query_phrase = " ".join(sorted(query_tokens))
    candidate_phrase = " ".join(sorted(name_tokens))
    if query_phrase and query_phrase == candidate_phrase:
        phrase_bonus = 0.1

    relevance = min(1.0, base + phrase_bonus)
    if relevance <= 0:
        return 0.0, [{"type": "semantic", "detail": "candidate failed weighted semantic scoring"}]

    return relevance, [
        {"type": "semantic", "detail": f"weighted relevance score {relevance:.3f}"},
        {"type": "semantic", "detail": f"name_overlap={name_overlap}, tag_overlap={tag_overlap}, desc_overlap={desc_overlap}"},
        {"type": "semantic", "detail": f"synonym_hits={synonym_hits}"},
    ]


def _default_pagination(pagination: dict[str, Any] | None) -> dict[str, Any]:
    if not pagination:
        return {"mode": "offset", "offset": 0, "limit": 20}

    mode = pagination.get("mode", "offset")
    limit = int(pagination.get("limit", 20))
    if limit < 1 or limit > 100:
        raise ValueError("limit must be in [1,100]")

    if mode == "offset":
        offset = int(pagination.get("offset", 0))
        if offset < 0:
            raise ValueError("offset must be >= 0")
        return {"mode": "offset", "offset": offset, "limit": limit}

    if mode == "cursor":
        cursor = pagination.get("cursor")
        if not isinstance(cursor, str) or not cursor.startswith("idx:"):
            raise ValueError("cursor mode requires cursor with format idx:<n>")
        start = int(cursor.split(":", 1)[1])
        if start < 0:
            raise ValueError("cursor index must be >= 0")
        return {"mode": "cursor", "start": start, "limit": limit}

    raise ValueError("mode must be cursor or offset")


def _apply_pagination(rows: list[dict[str, Any]], pagination: dict[str, Any] | None) -> dict[str, Any]:
    page = _default_pagination(pagination)
    total = len(rows)

    if page["mode"] == "offset":
        start = page["offset"]
        end = start + page["limit"]
        data = rows[start:end]
        meta = {
            "mode": "offset",
            "offset": start,
            "limit": page["limit"],
            "total": total,
        }
        return {"data": data, "pagination": meta}

    start = page["start"]
    end = start + page["limit"]
    data = rows[start:end]
    next_cursor = f"idx:{end}" if end < total else None
    meta = {
        "mode": "cursor",
        "limit": page["limit"],
        "next_cursor": next_cursor,
    }
    return {"data": data, "pagination": meta}


def _compatibility(req_in: set[str], req_out: set[str], candidate: dict[str, Any]) -> tuple[str, float]:
    cand_in = set(candidate.get("input_required", []))
    cand_out = set(candidate.get("output_fields", []))
    if cand_in == req_in and cand_out == req_out:
        return "exact", 1.0

    # Backward compatible: candidate requires no extra input and provides at least requested outputs.
    if cand_in.issubset(req_in) and req_out.issubset(cand_out):
        return "backward_compatible", 0.8

    return "partial", 0.0


def _build_scored_results(
    candidates: list[dict[str, Any]],
    relevance_scores: dict[str, float],
    weights: dict[str, float],
    compatibility_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    if not candidates:
        return []

    usage_norm = _safe_minmax_normalize([float(c["usage_30d"]) for c in candidates])
    cost_norm = _safe_minmax_normalize([float(c["estimated_cost_usd"]) for c in candidates], invert=True)
    latency_norm = _safe_minmax_normalize([float(c["p95_latency_ms"]) for c in candidates], invert=True)
    freshness_norm = _safe_minmax_normalize([float(c["freshness_days"]) for c in candidates], invert=True)

    results: list[dict[str, Any]] = []
    for idx, candidate in enumerate(candidates):
        cid = candidate["capability_id"]
        breakdown = {
            "capability_relevance": max(0.0, min(1.0, relevance_scores.get(cid, 0.0))),
            "trust_score": max(0.0, min(1.0, float(candidate["trust_score"]))),
            "usage_volume": usage_norm[idx],
            "cost_efficiency": cost_norm[idx],
            "latency": latency_norm[idx],
            "freshness": freshness_norm[idx],
        }

        score = sum(weights[k] * breakdown[k] for k in DEFAULT_WEIGHTS)
        item = {
            "agent_id": candidate["agent_id"],
            "capability_id": cid,
            "capability_name": candidate["capability_name"],
            "description": candidate["description"],
            "protocols": candidate["protocols"],
            "permissions": candidate["permissions"],
            "trust_score": candidate["trust_score"],
            "usage_30d": candidate["usage_30d"],
            "p95_latency_ms": candidate["p95_latency_ms"],
            "estimated_cost_usd": candidate["estimated_cost_usd"],
            "freshness_days": candidate["freshness_days"],
            "compatibility": compatibility_map.get(cid, "partial") if compatibility_map else "partial",
            "composite_score": round(score, 6),
            "score_breakdown": breakdown,
        }
        results.append(item)

    results.sort(
        key=lambda r: (
            -r["composite_score"],
            -r["trust_score"],
            r["estimated_cost_usd"],
            r["p95_latency_ms"],
            r["freshness_days"],
            f"{r['agent_id']}/{r['capability_id']}",
        )
    )
    return results


def search_capabilities(
    query: str,
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    ranking_weights: dict[str, float] | None = None,
    ranking_mode: str = "v2",
) -> dict[str, Any]:
    if ranking_mode not in {"baseline", "v2"}:
        raise ValueError("ranking_mode must be baseline or v2")

    _validate_filters(filters)
    weights = _normalize_weights(ranking_weights)
    query_tokens = _tokenize(query)

    candidates = []
    relevance_scores: dict[str, float] = {}
    selected_reasons: dict[str, list[dict[str, Any]]] = {}
    rejected: list[dict[str, Any]] = []
    for candidate in load_mock_capabilities():
        rejections = _policy_rejection_reasons(candidate, filters)
        if rejections:
            rejected.append(
                {
                    "agent_id": candidate["agent_id"],
                    "capability_id": candidate["capability_id"],
                    "reasons": rejections,
                }
            )
            continue

        relevance, reasons = _semantic_relevance(query_tokens, candidate, ranking_mode)
        if relevance <= 0:
            rejected.append(
                {
                    "agent_id": candidate["agent_id"],
                    "capability_id": candidate["capability_id"],
                    "reasons": reasons,
                }
            )
            continue

        candidates.append(candidate)
        relevance_scores[candidate["capability_id"]] = min(1.0, relevance)
        selected_reasons[candidate["capability_id"]] = reasons

    scored = _build_scored_results(candidates, relevance_scores, weights)
    if ranking_mode == "v2":
        for row in scored:
            row["search_v2_score"] = round(
                (0.75 * row["composite_score"]) + (0.25 * row["score_breakdown"]["capability_relevance"]),
                6,
            )
        scored.sort(
            key=lambda r: (
                -r["search_v2_score"],
                -r["trust_score"],
                r["estimated_cost_usd"],
                r["p95_latency_ms"],
                r["freshness_days"],
                f"{r['agent_id']}/{r['capability_id']}",
            )
        )

    paged = _apply_pagination(scored, pagination)

    why_selected = []
    for row in paged["data"]:
        cid = row["capability_id"]
        reasons = list(selected_reasons.get(cid, []))
        reasons.append({"type": "policy", "detail": "candidate passed policy-first constraints"})
        reasons.append({"type": "ranking", "detail": f"composite_score={row['composite_score']}"})
        if ranking_mode == "v2":
            reasons.append({"type": "ranking", "detail": f"search_v2_score={row['search_v2_score']}"})
        row["why_selected"] = reasons
        why_selected.append(
            {
                "agent_id": row["agent_id"],
                "capability_id": cid,
                "reasons": reasons,
            }
        )

    rejected.sort(key=lambda r: (r["agent_id"], r["capability_id"]))
    paged["explainability"] = {
        "why_selected": why_selected,
        "why_rejected": rejected,
        "ranking_mode": ranking_mode,
    }
    return paged


def match_capabilities(
    input_required: list[str],
    output_required: list[str],
    compatibility_mode: str = "backward_compatible",
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    ranking_weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    if compatibility_mode not in {"exact", "backward_compatible"}:
        raise ValueError("compatibility_mode must be exact or backward_compatible")

    _validate_filters(filters)
    weights = _normalize_weights(ranking_weights)
    req_in = set(input_required)
    req_out = set(output_required)

    candidates = []
    relevance_scores: dict[str, float] = {}
    compatibility_map: dict[str, str] = {}

    for candidate in load_mock_capabilities():
        if not _passes_policy_filters(candidate, filters):
            continue

        compatibility, relevance = _compatibility(req_in, req_out, candidate)
        if compatibility_mode == "exact" and compatibility != "exact":
            continue
        if compatibility_mode == "backward_compatible" and compatibility == "partial":
            continue

        candidates.append(candidate)
        relevance_scores[candidate["capability_id"]] = relevance
        compatibility_map[candidate["capability_id"]] = compatibility

    scored = _build_scored_results(candidates, relevance_scores, weights, compatibility_map)
    return _apply_pagination(scored, pagination)


def list_agent_capabilities(agent_id: str) -> dict[str, Any]:
    capabilities = []
    for candidate in load_mock_capabilities():
        if candidate["agent_id"] != agent_id:
            continue
        capabilities.append(
            {
                "capability_id": candidate["capability_id"],
                "capability_name": candidate["capability_name"],
                "description": candidate["description"],
                "protocols": candidate["protocols"],
                "permissions": candidate["permissions"],
                "input_schema": {
                    "type": "object",
                    "required": candidate["input_required"],
                },
                "output_schema": {
                    "type": "object",
                    "required": candidate["output_fields"],
                },
            }
        )
    if not capabilities:
        raise ValueError(f"agent not found: {agent_id}")
    return {"agent_id": agent_id, "capabilities": capabilities}


def recommend_capabilities(
    task_description: str,
    current_capability_ids: list[str],
    filters: dict[str, Any] | None = None,
    pagination: dict[str, Any] | None = None,
    ranking_weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    _validate_filters(filters)
    weights = _normalize_weights(ranking_weights)
    task_tokens = _tokenize(task_description)
    current = set(current_capability_ids)

    all_candidates = load_mock_capabilities()
    current_categories = {c["category"] for c in all_candidates if c["capability_id"] in current}

    candidates = []
    relevance_scores: dict[str, float] = {}

    for candidate in all_candidates:
        if candidate["capability_id"] in current:
            continue
        if not _passes_policy_filters(candidate, filters):
            continue

        corpus = " ".join([candidate["capability_name"], candidate["description"], *candidate.get("tags", [])])
        corpus_tokens = _tokenize(corpus)
        overlap = len(task_tokens.intersection(corpus_tokens)) / max(1, len(task_tokens))

        # Recommendation must stay task-grounded; category complement is a boost, not a standalone signal.
        if overlap <= 0:
            continue

        complement_bonus = 0.2 if candidate["category"] not in current_categories else 0.0
        relevance = min(1.0, overlap + complement_bonus)

        candidates.append(candidate)
        relevance_scores[candidate["capability_id"]] = relevance

    scored = _build_scored_results(candidates, relevance_scores, weights)
    for row in scored:
        reasons = []
        if row["capability_id"] == "provision-billing":
            reasons.append({"type": "coverage_gap", "detail": "Adds billing setup capability missing from current set."})
        if row["score_breakdown"]["capability_relevance"] >= 0.5:
            reasons.append({"type": "schema_compatibility", "detail": "Task terms align with capability contract and outputs."})
        if row["trust_score"] >= 0.8:
            reasons.append({"type": "trust_alignment", "detail": "Meets trust policy threshold for runtime delegation."})
        if row["estimated_cost_usd"] <= 0.1:
            reasons.append({"type": "cost_efficiency", "detail": "Within lower-cost tier for comparable candidates."})
        row["recommendation_reasons"] = reasons[:3] if reasons else [
            {"type": "coverage_gap", "detail": "Provides additional capability coverage for the task."}
        ]

    return _apply_pagination(scored, pagination)
