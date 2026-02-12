from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.eval.storage import latest_result
from src.trust import storage

WEIGHTS = {
    "eval_pass_rate": 0.30,
    "usage_success_rate": 0.20,
    "publisher_reputation": 0.15,
    "community_validation": 0.10,
    "security_audit": 0.10,
    "freshness": 0.10,
}
INCIDENT_PENALTY_WEIGHT = 0.20
MANIPULATION_PENALTY_WEIGHT = 0.15
GRAPH_ABUSE_PENALTY_WEIGHT = 0.20
REPUTATION_DECAY_PENALTY_WEIGHT = 0.10


@dataclass
class Tier:
    name: str
    min_score: float
    max_score: float
    badge: str
    capabilities: str


TIERS = [
    Tier("Unverified", 0, 39, "Gray", "Listed in registry, no delegation eligibility"),
    Tier("Community", 40, 59, "Bronze", "Human delegation (manual approval)"),
    Tier("Verified", 60, 79, "Silver", "Automated delegation with cost limits"),
    Tier("Trusted", 80, 89, "Gold", "Full automated delegation"),
    Tier("Certified", 90, 100, "Platinum", "Enterprise-grade, audited, insured"),
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _recency_weight(raw_ts: str | None, half_life_days: float = 30.0) -> float:
    when = _parse_dt(raw_ts)
    if when is None:
        return 0.7
    age_days = max(0.0, (_utc_now() - when).total_seconds() / 86400.0)
    return _clamp(0.5 ** (age_days / max(half_life_days, 1.0)))


def _eval_signal(agent_id: str) -> float:
    latest = latest_result(agent_id)
    if not latest:
        return 0.5
    return _clamp(float(latest.get("metrics", {}).get("accuracy", 0.0)))


def _usage_signal(agent_id: str) -> tuple[float, int]:
    rows = storage.load("usage_events")
    cutoff = _utc_now() - timedelta(days=30)
    relevant = []
    for row in rows:
        if row.get("agent_id") != agent_id:
            continue
        when = _parse_dt(row.get("occurred_at"))
        if when and when >= cutoff:
            relevant.append(row)
    if not relevant:
        return 0.5, 0

    weighted_success = 0.0
    weight_total = 0.0
    for row in relevant:
        recency = _recency_weight(row.get("occurred_at"), half_life_days=20.0)
        latency_ms = float(row.get("latency_ms", 300.0))
        cost_usd = float(row.get("cost_usd", 0.1))
        evidence_quality = _clamp((0.6 * (1.0 - min(latency_ms, 5000.0) / 5000.0)) + (0.4 * (1.0 - min(cost_usd, 5.0) / 5.0)))
        weight = max(0.05, recency * evidence_quality)
        weight_total += weight
        if row.get("success") is True:
            weighted_success += weight

    return _clamp(weighted_success / max(weight_total, 1e-6)), len(relevant)


def _publisher_profile(owner: str) -> dict[str, Any]:
    for row in storage.load("publisher_profiles"):
        if row.get("owner") == owner:
            return row
    return {"owner": owner, "account_age_days": 60, "publisher_agent_count": 3, "independent_usage_agents": 3}


def _publisher_signal(owner: str) -> tuple[float, list[str]]:
    flags: list[str] = []
    profile = _publisher_profile(owner)
    signal = 0.7

    if int(profile.get("publisher_agent_count", 0)) < 3 or int(profile.get("independent_usage_agents", 0)) < 3:
        signal = 0.0
        flags.append("publisher_reputation_gated_for_insufficient_independent_usage")

    return _clamp(signal), flags


def _community_signal(agent_id: str) -> tuple[float, list[str]]:
    rows = storage.load("reviews")
    verified = [r for r in rows if r.get("agent_id") == agent_id and r.get("verified_usage") is True]
    unverified = [r for r in rows if r.get("agent_id") == agent_id and not r.get("verified_usage")]

    flags: list[str] = []
    if unverified:
        flags.append("unverified_reviews_ignored")

    if not verified:
        return 0.5, flags

    weighted_rating = 0.0
    weight_total = 0.0
    reviewers = []
    for row in verified:
        rating = _clamp(float(row.get("rating", 0.0)) / 5.0)
        evidence_quality = _clamp(float(row.get("evidence_quality", 1.0)))
        reviewer_reputation = _clamp(float(row.get("reviewer_reputation", 1.0)))
        recency = _recency_weight(row.get("occurred_at"), half_life_days=45.0)
        weight = max(0.05, evidence_quality * reviewer_reputation * recency)
        weighted_rating += rating * weight
        weight_total += weight
        reviewer = row.get("reviewer_id") or row.get("reviewer")
        if reviewer:
            reviewers.append(str(reviewer))

    if reviewers:
        diversity = len(set(reviewers)) / max(1, len(reviewers))
        if len(reviewers) >= 5 and diversity < 0.4:
            flags.append("low_reviewer_diversity_detected")

    recent_verified = [r for r in verified if _recency_weight(r.get("occurred_at"), half_life_days=1.0) > 0.7]
    if len(recent_verified) >= 5 and all(float(r.get("rating", 0.0)) >= 4.5 for r in recent_verified):
        flags.append("review_burst_detected")

    avg = weighted_rating / max(weight_total, 1e-6)
    return _clamp(avg), flags


def _security_signal(agent_id: str) -> tuple[float, list[str]]:
    rows = [r for r in storage.load("security_audits") if r.get("agent_id") == agent_id]
    flags: list[str] = []
    if not rows:
        return 0.7, flags

    rows.sort(key=lambda r: r.get("occurred_at", ""), reverse=True)
    row = rows[0]
    base_score = _clamp(float(row.get("score", 0.7)))
    evidence_quality = _clamp(float(row.get("evidence_quality", 1.0)))
    recency = _recency_weight(row.get("occurred_at"), half_life_days=60.0)
    signal = _clamp(base_score * ((0.75 * evidence_quality) + (0.25 * recency)))

    if row.get("canary_failed") is True:
        signal = min(signal, 0.3)
        flags.append("canary_failure_detected")

    return signal, flags


def _freshness_signal(agent_id: str) -> float:
    latest = latest_result(agent_id)
    if not latest:
        return 0.4
    completed = _parse_dt(latest.get("completed_at"))
    if not completed:
        return 0.4
    age_days = (_utc_now() - completed).days
    return _clamp(1.0 - (age_days / 90.0))


def _incident_penalty(agent_id: str) -> float:
    rows = [r for r in storage.load("incidents") if r.get("agent_id") == agent_id]
    if not rows:
        return 0.0

    severity = {"low": 0.2, "medium": 0.5, "high": 1.0}
    total = 0.0
    for row in rows:
        if row.get("resolved"):
            continue
        total += severity.get(str(row.get("severity", "medium")).lower(), 0.5)
    return _clamp(total / max(1, len(rows)))


def _manipulation_penalty(
    *,
    community_signal: float,
    usage_events_30d: int,
    flags: list[str],
) -> float:
    penalty = 0.0
    if community_signal >= 0.9 and usage_events_30d < 3:
        penalty += 0.35
        flags.append("community_usage_mismatch_penalty_applied")
    if "low_reviewer_diversity_detected" in flags:
        penalty += 0.2
    if "review_burst_detected" in flags:
        penalty += 0.2
    return _clamp(penalty)


def _apply_sybil_resistance(raw_score: float, owner: str, flags: list[str]) -> float:
    profile = _publisher_profile(owner)
    account_age_days = int(profile.get("account_age_days", 0))
    if account_age_days >= 30:
        return raw_score

    multiplier = max(0.05, account_age_days / 30.0)
    flags.append("sybil_trust_accumulation_delay_applied")
    return raw_score * multiplier


def _graph_abuse_penalty(agent_id: str, flags: list[str]) -> float:
    rows = storage.load("interaction_graph")
    if not rows:
        return 0.0

    cutoff = _utc_now() - timedelta(days=90)
    related = []
    outgoing_pairs: set[tuple[str, str]] = set()
    for row in rows:
        source_agent = str(row.get("source_agent_id", ""))
        target_agent = str(row.get("target_agent_id", ""))
        when = _parse_dt(row.get("occurred_at"))
        if when is not None and when < cutoff:
            continue
        if source_agent and target_agent:
            outgoing_pairs.add((source_agent, target_agent))
        if target_agent == agent_id:
            related.append(row)

    if not related:
        return 0.0

    penalty = 0.0
    sources = [str(row.get("source_agent_id", "")) for row in related if row.get("source_agent_id")]
    unique_sources = {source for source in sources if source}
    source_diversity = len(unique_sources) / max(1, len(sources))
    if len(related) >= 6 and source_diversity < 0.4:
        penalty += 0.35
        flags.append("collusion_ring_low_diversity_detected")

    reciprocal_sources = 0
    for source in unique_sources:
        if (agent_id, source) in outgoing_pairs:
            reciprocal_sources += 1
    reciprocal_ratio = reciprocal_sources / max(1, len(unique_sources))
    if len(unique_sources) >= 2 and reciprocal_ratio > 0.6:
        penalty += 0.25
        flags.append("collusion_reciprocal_loop_detected")

    source_owners = {str(row.get("source_owner", "")) for row in related if row.get("source_owner")}
    if source_owners:
        sybil_owners = 0
        for source_owner in source_owners:
            profile = _publisher_profile(source_owner)
            if int(profile.get("account_age_days", 0)) < 30:
                sybil_owners += 1
        sybil_ratio = sybil_owners / len(source_owners)
        if len(source_owners) >= 3 and sybil_ratio >= 0.5:
            penalty += 0.35
            flags.append("sybil_cluster_interaction_detected")

    return _clamp(penalty)


def _reputation_decay_penalty(agent_id: str, flags: list[str]) -> float:
    timestamps: list[datetime] = []
    latest_eval = latest_result(agent_id)
    if latest_eval:
        when = _parse_dt(latest_eval.get("completed_at"))
        if when is not None:
            timestamps.append(when)

    for row in storage.load("usage_events"):
        if row.get("agent_id") != agent_id:
            continue
        when = _parse_dt(row.get("occurred_at"))
        if when is not None:
            timestamps.append(when)

    for row in storage.load("reviews"):
        if row.get("agent_id") != agent_id:
            continue
        when = _parse_dt(row.get("occurred_at"))
        if when is not None:
            timestamps.append(when)

    for row in storage.load("security_audits"):
        if row.get("agent_id") != agent_id:
            continue
        when = _parse_dt(row.get("occurred_at"))
        if when is not None:
            timestamps.append(when)

    if not timestamps:
        return 0.0

    latest_activity = max(timestamps)
    inactivity_days = max(0.0, (_utc_now() - latest_activity).total_seconds() / 86400.0)
    if inactivity_days <= 45:
        return 0.0

    penalty = _clamp((inactivity_days - 45) / 240.0)
    if penalty > 0:
        flags.append("reputation_decay_applied")
    return penalty


def _tier_for(score: float) -> Tier:
    for tier in TIERS:
        if tier.min_score <= score <= tier.max_score:
            return tier
    return TIERS[0]


def compute_trust_score(agent_id: str, owner: str) -> dict[str, Any]:
    flags: list[str] = []

    eval_signal = _eval_signal(agent_id)
    usage_signal, usage_events = _usage_signal(agent_id)
    publisher_signal, publisher_flags = _publisher_signal(owner)
    community_signal, community_flags = _community_signal(agent_id)
    security_signal, security_flags = _security_signal(agent_id)
    freshness_signal = _freshness_signal(agent_id)
    incident_penalty = _incident_penalty(agent_id)

    flags.extend(publisher_flags)
    flags.extend(community_flags)
    flags.extend(security_flags)
    manipulation_penalty = _manipulation_penalty(
        community_signal=community_signal,
        usage_events_30d=usage_events,
        flags=flags,
    )
    graph_abuse_penalty = _graph_abuse_penalty(agent_id=agent_id, flags=flags)
    reputation_decay_penalty = _reputation_decay_penalty(agent_id=agent_id, flags=flags)

    weighted = (
        WEIGHTS["eval_pass_rate"] * eval_signal
        + WEIGHTS["usage_success_rate"] * usage_signal
        + WEIGHTS["publisher_reputation"] * publisher_signal
        + WEIGHTS["community_validation"] * community_signal
        + WEIGHTS["security_audit"] * security_signal
        + WEIGHTS["freshness"] * freshness_signal
        - INCIDENT_PENALTY_WEIGHT * incident_penalty
        - MANIPULATION_PENALTY_WEIGHT * manipulation_penalty
        - GRAPH_ABUSE_PENALTY_WEIGHT * graph_abuse_penalty
        - REPUTATION_DECAY_PENALTY_WEIGHT * reputation_decay_penalty
    )

    raw_score = _clamp(weighted) * 100
    adjusted_score = _apply_sybil_resistance(raw_score, owner, flags)
    final_score = max(0.0, min(100.0, round(adjusted_score, 2)))

    tier = _tier_for(final_score)

    breakdown = {
        "eval_pass_rate": round(eval_signal, 4),
        "usage_success_rate": round(usage_signal, 4),
        "publisher_reputation": round(publisher_signal, 4),
        "community_validation": round(community_signal, 4),
        "security_audit": round(security_signal, 4),
        "freshness": round(freshness_signal, 4),
        "incident_penalty": round(incident_penalty, 4),
        "manipulation_penalty": round(manipulation_penalty, 4),
        "graph_abuse_penalty": round(graph_abuse_penalty, 4),
        "reputation_decay_penalty": round(reputation_decay_penalty, 4),
        "usage_events_30d": usage_events,
    }

    score_row = {
        "agent_id": agent_id,
        "score": final_score,
        "tier": tier.name,
        "badge": tier.badge,
        "tier_capabilities": tier.capabilities,
        "breakdown": breakdown,
        "flags": sorted(set(flags)),
        "weights": WEIGHTS,
        "incident_penalty_weight": INCIDENT_PENALTY_WEIGHT,
        "manipulation_penalty_weight": MANIPULATION_PENALTY_WEIGHT,
        "graph_abuse_penalty_weight": GRAPH_ABUSE_PENALTY_WEIGHT,
        "reputation_decay_penalty_weight": REPUTATION_DECAY_PENALTY_WEIGHT,
        "computed_at": _utc_now().isoformat(),
    }
    storage.upsert_score(score_row)
    return score_row


def record_usage_event(agent_id: str, success: bool, cost_usd: float, latency_ms: float) -> None:
    storage.append(
        "usage_events",
        {
            "agent_id": agent_id,
            "success": success,
            "cost_usd": cost_usd,
            "latency_ms": latency_ms,
            "occurred_at": _utc_now().isoformat(),
        },
    )
