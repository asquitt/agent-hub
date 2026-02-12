from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.eval import storage as eval_storage
from src.trust import storage as trust_storage
from src.trust.scoring import compute_trust_score


def _iso(days_ago: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


@pytest.fixture(autouse=True)
def isolated_trust_paths(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "eval_results.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_USAGE_EVENTS_PATH", str(tmp_path / "usage_events.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_REVIEWS_PATH", str(tmp_path / "reviews.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SECURITY_AUDITS_PATH", str(tmp_path / "security_audits.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_INCIDENTS_PATH", str(tmp_path / "incidents.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_PUBLISHER_PROFILES_PATH", str(tmp_path / "publisher_profiles.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_INTERACTION_GRAPH_PATH", str(tmp_path / "interaction_graph.json"))
    monkeypatch.setenv("AGENTHUB_TRUST_SCORES_PATH", str(tmp_path / "scores.json"))


def _seed_base_trust_signals(agent_id: str, owner: str) -> None:
    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 0.94},
            "completed_at": _iso(),
        }
    )
    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 180, "publisher_agent_count": 8, "independent_usage_agents": 8},
    )
    trust_storage.append(
        "security_audits",
        {"agent_id": agent_id, "score": 0.9, "canary_failed": False, "occurred_at": _iso()},
    )
    for idx in range(8):
        trust_storage.append("usage_events", {"agent_id": agent_id, "success": True, "occurred_at": _iso()})
        trust_storage.append(
            "reviews",
            {
                "agent_id": agent_id,
                "rating": 5,
                "verified_usage": True,
                "reviewer_id": f"reviewer-{idx}",
                "occurred_at": _iso(),
            },
        )


def test_trust_graph_v3_detects_collusion_ring_patterns() -> None:
    agent_id = "@demo:graph-agent"
    owner = "owner-graph"
    _seed_base_trust_signals(agent_id=agent_id, owner=owner)

    for idx in range(8):
        source = "peer-a" if idx < 6 else "peer-b"
        trust_storage.append(
            "interaction_graph",
            {
                "source_agent_id": source,
                "target_agent_id": agent_id,
                "source_owner": "owner-peer-a" if source == "peer-a" else "owner-peer-b",
                "edge_type": "delegation",
                "occurred_at": _iso(),
            },
        )

    trust_storage.append(
        "interaction_graph",
        {"source_agent_id": agent_id, "target_agent_id": "peer-a", "source_owner": owner, "edge_type": "delegation", "occurred_at": _iso()},
    )
    trust_storage.append(
        "interaction_graph",
        {"source_agent_id": agent_id, "target_agent_id": "peer-b", "source_owner": owner, "edge_type": "delegation", "occurred_at": _iso()},
    )

    score = compute_trust_score(agent_id=agent_id, owner=owner)
    assert "collusion_ring_low_diversity_detected" in score["flags"]
    assert "collusion_reciprocal_loop_detected" in score["flags"]
    assert score["breakdown"]["graph_abuse_penalty"] > 0


def test_trust_graph_v3_detects_sybil_interaction_clusters() -> None:
    agent_id = "@demo:sybil-graph-agent"
    owner = "owner-sybil-graph"
    _seed_base_trust_signals(agent_id=agent_id, owner=owner)

    for source_owner in ("owner-sybil-1", "owner-sybil-2", "owner-sybil-3"):
        trust_storage.append(
            "publisher_profiles",
            {"owner": source_owner, "account_age_days": 4, "publisher_agent_count": 1, "independent_usage_agents": 1},
        )
    for idx in range(6):
        trust_storage.append(
            "interaction_graph",
            {
                "source_agent_id": f"sybil-peer-{idx % 3}",
                "target_agent_id": agent_id,
                "source_owner": f"owner-sybil-{(idx % 3) + 1}",
                "edge_type": "review",
                "occurred_at": _iso(),
            },
        )

    score = compute_trust_score(agent_id=agent_id, owner=owner)
    assert "sybil_cluster_interaction_detected" in score["flags"]
    assert score["breakdown"]["graph_abuse_penalty"] > 0


def test_trust_graph_v3_applies_reputation_decay_to_stale_agents() -> None:
    agent_id = "@demo:stale-agent"
    owner = "owner-stale"

    eval_storage.append_result(
        {
            "agent_id": agent_id,
            "version": "1.0.0",
            "metrics": {"accuracy": 0.95},
            "completed_at": _iso(days_ago=180),
        }
    )
    trust_storage.append(
        "publisher_profiles",
        {"owner": owner, "account_age_days": 365, "publisher_agent_count": 7, "independent_usage_agents": 7},
    )
    trust_storage.append(
        "security_audits",
        {"agent_id": agent_id, "score": 0.88, "occurred_at": _iso(days_ago=200)},
    )
    trust_storage.append("usage_events", {"agent_id": agent_id, "success": True, "occurred_at": _iso(days_ago=210)})
    trust_storage.append(
        "reviews",
        {"agent_id": agent_id, "rating": 4, "verified_usage": True, "reviewer_id": "legit-reviewer", "occurred_at": _iso(days_ago=190)},
    )

    score = compute_trust_score(agent_id=agent_id, owner=owner)
    assert "reputation_decay_applied" in score["flags"]
    assert score["breakdown"]["reputation_decay_penalty"] > 0
