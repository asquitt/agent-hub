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
    successes = sum(1 for row in relevant if row.get("success") is True)
    return _clamp(successes / len(relevant)), len(relevant)


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

    avg = sum(float(r.get("rating", 0.0)) for r in verified) / (5.0 * len(verified))
    return _clamp(avg), flags


def _security_signal(agent_id: str) -> tuple[float, list[str]]:
    rows = [r for r in storage.load("security_audits") if r.get("agent_id") == agent_id]
    flags: list[str] = []
    if not rows:
        return 0.7, flags

    rows.sort(key=lambda r: r.get("occurred_at", ""), reverse=True)
    row = rows[0]
    signal = _clamp(float(row.get("score", 0.7)))

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


def _apply_sybil_resistance(raw_score: float, owner: str, flags: list[str]) -> float:
    profile = _publisher_profile(owner)
    account_age_days = int(profile.get("account_age_days", 0))
    if account_age_days >= 30:
        return raw_score

    multiplier = max(0.05, account_age_days / 30.0)
    flags.append("sybil_trust_accumulation_delay_applied")
    return raw_score * multiplier


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

    weighted = (
        WEIGHTS["eval_pass_rate"] * eval_signal
        + WEIGHTS["usage_success_rate"] * usage_signal
        + WEIGHTS["publisher_reputation"] * publisher_signal
        + WEIGHTS["community_validation"] * community_signal
        + WEIGHTS["security_audit"] * security_signal
        + WEIGHTS["freshness"] * freshness_signal
        - INCIDENT_PENALTY_WEIGHT * incident_penalty
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
