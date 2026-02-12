from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.devhub import storage


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hydrate_review(review: dict[str, Any]) -> dict[str, Any]:
    decisions = storage.list_decisions(review_id=str(review["review_id"]))
    return {**review, "decisions": decisions}


def create_release_review(agent_id: str, version: str, requested_by: str, approvals_required: int = 2) -> dict[str, Any]:
    required = max(1, int(approvals_required))
    now = _utc_now()
    row = {
        "review_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "version": version,
        "requested_by": requested_by,
        "status": "pending",
        "approvals_required": required,
        "approvals_count": 0,
        "rejections_count": 0,
        "created_at": now,
        "updated_at": now,
    }
    storage.upsert_review(row)
    return _hydrate_review(row)


def get_release_review(review_id: str) -> dict[str, Any]:
    row = storage.get_review(review_id=review_id)
    if row is None:
        raise KeyError("review not found")
    return _hydrate_review(row)


def list_release_reviews(agent_id: str | None = None) -> list[dict[str, Any]]:
    rows = storage.list_reviews(agent_id=agent_id)
    return [_hydrate_review(row) for row in rows]


def decide_release_review(review_id: str, actor: str, decision: str, note: str | None = None) -> dict[str, Any]:
    normalized = decision.strip().lower()
    if normalized not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")

    row = storage.get_review(review_id=review_id)
    if row is None:
        raise KeyError("review not found")
    if row["status"] in {"rejected", "promoted"}:
        raise ValueError("review is in terminal state")

    storage.insert_decision(
        {
            "review_id": review_id,
            "actor": actor,
            "decision": normalized,
            "note": note,
            "created_at": _utc_now(),
        }
    )
    decisions = storage.list_decisions(review_id=review_id)
    approvals_count = len([d for d in decisions if d["decision"] == "approve"])
    rejections_count = len([d for d in decisions if d["decision"] == "reject"])

    status = "pending"
    if rejections_count > 0:
        status = "rejected"
    elif approvals_count >= int(row["approvals_required"]):
        status = "approved"

    updated = {
        **row,
        "status": status,
        "approvals_count": approvals_count,
        "rejections_count": rejections_count,
        "updated_at": _utc_now(),
    }
    storage.upsert_review(updated)
    return _hydrate_review(updated)


def promote_release_review(review_id: str, promoted_by: str) -> dict[str, Any]:
    row = storage.get_review(review_id=review_id)
    if row is None:
        raise KeyError("review not found")
    if row["status"] != "approved":
        raise ValueError("review is not approved")
    existing = storage.get_promotion_by_review(review_id=review_id)
    if existing is not None:
        return existing

    promotion = {
        "promotion_id": str(uuid.uuid4()),
        "review_id": review_id,
        "agent_id": row["agent_id"],
        "version": row["version"],
        "promoted_by": promoted_by,
        "status": "promoted",
        "created_at": _utc_now(),
    }
    storage.insert_promotion(promotion)

    updated_review = {**row, "status": "promoted", "updated_at": _utc_now()}
    storage.upsert_review(updated_review)
    return promotion


def list_promotions(agent_id: str | None = None) -> list[dict[str, Any]]:
    return storage.list_promotions(agent_id=agent_id)


def reconfigure(db_path: str | Path | None = None) -> None:
    storage.reconfigure(db_path=db_path)


def reset_for_tests(db_path: str | Path | None = None) -> None:
    storage.reset_for_tests(db_path=db_path)
