"""A2A protocol endpoints — Google Agent-to-Agent protocol support.

Serves A2A agent cards for the registry itself and per registered agent.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from src.identity.a2a import build_agent_card, build_registry_agent_card
from src.registry.store import STORE

router = APIRouter(tags=["a2a"])


@router.get("/.well-known/agent.json")
def get_a2a_agent_card() -> dict[str, Any]:
    """A2A Agent Card for the AgentHub registry service (public)."""
    return build_registry_agent_card()


@router.get("/v1/a2a/agent-card/{agent_id:path}")
def get_agent_a2a_card(agent_id: str) -> dict[str, Any]:
    """A2A Agent Card for a specific registered agent."""
    try:
        agent = STORE.get_agent(agent_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="agent not found")

    manifest: dict[str, Any] = {}
    if agent.versions:
        manifest = agent.versions[-1].manifest

    trust_score: float | None = None
    try:
        from src.trust.storage import get_score
        score_result = get_score(agent_id)
        if isinstance(score_result, dict):
            raw = score_result.get("score")
            if isinstance(raw, (int, float)):
                trust_score = float(raw)
    except (ImportError, KeyError):
        pass

    return build_agent_card(
        agent_id=agent.agent_id,
        manifest=manifest,
        trust_score=trust_score,
    )
