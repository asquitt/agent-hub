from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from src.eval import storage as eval_storage
from src.trust import storage as trust_storage
from src.trust.scoring import compute_trust_score


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture(autouse=True)
def isolated_trust_paths(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "eval_results.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_REVIEWS_PATH", str(tmp_path / "reviews.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SECURITY_AUDITS_PATH", str(tmp_path / "security_audits.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_INCIDENTS_PATH", str(tmp_path / "incidents.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_PUBLISHER_PROFILES_PATH", str(tmp_path / "publisher_profiles.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SCORES_PATH", str(tmp_path / "scores.json"))


def test_trust_score_computation_uses_eval_usage_and_community() -> None:
    agent_id = "@demo:agent"
    owner = "owner-dev"

    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 0.95},
            "completed_at": _iso_now(),
        }
    )
    trust_storage.append("usage_events", {"agent_id": agent_id, "success": True, "occurred_at": _iso_now()})
    trust_storage.append("usage_events", {"agent_id": agent_id, "success": False, "occurred_at": _iso_now()})

    trust_storage.append("reviews", {"agent_id": agent_id, "rating": 5, "verified_usage": True})
    trust_storage.append("reviews", {"agent_id": agent_id, "rating": 1, "verified_usage": False})

    trust_storage.append("security_audits", {"agent_id": agent_id, "score": 0.9, "canary_failed": False, "occurred_at": _iso_now()})
    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 120, "publisher_agent_count": 5, "independent_usage_agents": 4},
    )

    score = compute_trust_score(agent_id=agent_id, owner=owner)
    assert score["score"] > 60
    assert score["breakdown"]["eval_pass_rate"] == 0.95
    assert score["breakdown"]["usage_success_rate"] == 0.5
    assert score["breakdown"]["community_validation"] == 1.0
    assert "unverified_reviews_ignored" in score["flags"]


def test_anti_gaming_flags_sybil_and_canary() -> None:
    agent_id = "@demo:risky-agent"
    owner = "owner-new"

    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 1.0},
            "completed_at": _iso_now(),
        }
    )

    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 5, "publisher_agent_count": 1, "independent_usage_agents": 1},
    )
    trust_storage.append(
        "security_audits",
        {"agent_id": agent_id, "score": 0.95, "canary_failed": True, "occurred_at": _iso_now()},
    )

    score = compute_trust_score(agent_id=agent_id, owner=owner)

    assert "sybil_trust_accumulation_delay_applied" in score["flags"]
    assert "publisher_reputation_gated_for_insufficient_independent_usage" in score["flags"]
    assert "canary_failure_detected" in score["flags"]
    assert score["score"] < 40


def test_manipulation_penalty_detects_review_burst_without_usage() -> None:
    agent_id = "@demo:burst-agent"
    owner = "owner-burst"

    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 0.98},
            "completed_at": _iso_now(),
        }
    )
    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 120, "publisher_agent_count": 5, "independent_usage_agents": 5},
    )
    trust_storage.append(
        "security_audits",
        {"agent_id": agent_id, "score": 0.9, "canary_failed": False, "occurred_at": _iso_now()},
    )

    # Simulate suspicious high-rating review burst from a single reviewer identity.
    for idx in range(8):
        trust_storage.append(
            "reviews",
            {
                "agent_id": agent_id,
                "rating": 5,
                "verified_usage": True,
                "reviewer_id": "same-reviewer",
                "occurred_at": _iso_now(),
            },
        )

    score = compute_trust_score(agent_id=agent_id, owner=owner)
    assert "review_burst_detected" in score["flags"]
    assert "low_reviewer_diversity_detected" in score["flags"]
    assert "community_usage_mismatch_penalty_applied" in score["flags"]
    assert score["breakdown"]["manipulation_penalty"] > 0


def test_trust_score_stability_under_adversarial_unverified_reviews() -> None:
    agent_id = "@demo:stable-agent"
    owner = "owner-stable"

    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 200, "publisher_agent_count": 6, "independent_usage_agents": 6},
    )
    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 0.9},
            "completed_at": _iso_now(),
        }
    )
    trust_storage.append("security_audits", {"agent_id": agent_id, "score": 0.85, "occurred_at": _iso_now()})
    for idx in range(5):
        trust_storage.append("usage_events", {"agent_id": agent_id, "success": True, "occurred_at": _iso_now()})
        trust_storage.append(
            "reviews",
            {
                "agent_id": agent_id,
                "rating": 4,
                "verified_usage": True,
                "reviewer_id": f"legit-{idx}",
                "occurred_at": _iso_now(),
            },
        )

    baseline = compute_trust_score(agent_id=agent_id, owner=owner)["score"]

    # Adversarial input: many unverified 5-star reviews should be ignored.
    for idx in range(30):
        trust_storage.append(
            "reviews",
            {"agent_id": agent_id, "rating": 5, "verified_usage": False, "reviewer_id": f"bot-{idx}"},
        )

    after_attack = compute_trust_score(agent_id=agent_id, owner=owner)["score"]
    assert abs(after_attack - baseline) <= 5
