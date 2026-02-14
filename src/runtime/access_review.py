"""Agent Access Review / Certification Campaigns.

Enables periodic review of agent permissions for compliance:
- Create review campaigns (quarterly, annual, ad-hoc)
- Generate review items from current entitlements
- Certify (approve) or revoke access per item
- Track campaign completion and compliance metrics
- Auto-revoke unreviewed items after deadline
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

_log = logging.getLogger("agenthub.access_review")

# Campaign status
STATUS_ACTIVE = "active"
STATUS_COMPLETED = "completed"
STATUS_EXPIRED = "expired"

# Review item decisions
DECISION_PENDING = "pending"
DECISION_CERTIFIED = "certified"
DECISION_REVOKED = "revoked"
DECISION_AUTO_REVOKED = "auto_revoked"

# Campaign types
CAMPAIGN_QUARTERLY = "quarterly"
CAMPAIGN_ANNUAL = "annual"
CAMPAIGN_ADHOC = "ad_hoc"

VALID_CAMPAIGN_TYPES = {CAMPAIGN_QUARTERLY, CAMPAIGN_ANNUAL, CAMPAIGN_ADHOC}

# In-memory stores
_MAX_RECORDS = 10_000
_campaigns: dict[str, dict[str, Any]] = {}
_review_items: dict[str, dict[str, Any]] = {}  # item_id -> item


def create_campaign(
    *,
    name: str,
    campaign_type: str = CAMPAIGN_ADHOC,
    scope: str | None = None,
    reviewer: str | None = None,
    deadline_seconds: int = 604800,  # 7 days default
    description: str = "",
    agent_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Create an access review campaign."""
    if campaign_type not in VALID_CAMPAIGN_TYPES:
        raise ValueError(f"invalid campaign type: {campaign_type}")
    if deadline_seconds < 3600 or deadline_seconds > 7776000:  # 1 hour to 90 days
        raise ValueError("deadline must be between 1 hour and 90 days")

    now = time.time()
    campaign_id = f"campaign-{uuid.uuid4().hex[:12]}"

    campaign: dict[str, Any] = {
        "campaign_id": campaign_id,
        "name": name,
        "campaign_type": campaign_type,
        "scope": scope,
        "reviewer": reviewer,
        "description": description,
        "status": STATUS_ACTIVE,
        "created_at": now,
        "deadline": now + deadline_seconds,
        "completed_at": None,
        "total_items": 0,
        "certified_count": 0,
        "revoked_count": 0,
        "pending_count": 0,
    }

    # Auto-generate review items if agent_ids provided
    if agent_ids:
        for aid in agent_ids:
            item = _create_review_item(
                campaign_id=campaign_id,
                agent_id=aid,
                entitlement_type="agent_access",
                entitlement_detail=f"full access for {aid}",
            )
            campaign["total_items"] += 1
            campaign["pending_count"] += 1

    _campaigns[campaign_id] = campaign
    if len(_campaigns) > _MAX_RECORDS:
        oldest = sorted(_campaigns, key=lambda k: _campaigns[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _campaigns[k]

    _log.info("campaign created: id=%s name=%s", campaign_id, name)
    return campaign


def get_campaign(campaign_id: str) -> dict[str, Any]:
    """Get campaign details with progress."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        raise KeyError(f"campaign not found: {campaign_id}")

    # Check if expired
    if campaign["status"] == STATUS_ACTIVE and time.time() > campaign["deadline"]:
        _expire_campaign(campaign_id)

    return campaign


def list_campaigns(
    *,
    status: str | None = None,
    campaign_type: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List campaigns with optional filters."""
    results: list[dict[str, Any]] = []
    for c in _campaigns.values():
        # Auto-expire check
        if c["status"] == STATUS_ACTIVE and time.time() > c["deadline"]:
            _expire_campaign(c["campaign_id"])

        if status and c["status"] != status:
            continue
        if campaign_type and c["campaign_type"] != campaign_type:
            continue
        results.append(c)
        if len(results) >= limit:
            break
    return results


def add_review_item(
    *,
    campaign_id: str,
    agent_id: str,
    entitlement_type: str,
    entitlement_detail: str = "",
    resource: str | None = None,
) -> dict[str, Any]:
    """Add a review item to an active campaign."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        raise KeyError(f"campaign not found: {campaign_id}")
    if campaign["status"] != STATUS_ACTIVE:
        raise ValueError(f"campaign is {campaign['status']}, not active")

    item = _create_review_item(
        campaign_id=campaign_id,
        agent_id=agent_id,
        entitlement_type=entitlement_type,
        entitlement_detail=entitlement_detail,
        resource=resource,
    )
    campaign["total_items"] += 1
    campaign["pending_count"] += 1
    return item


def list_review_items(
    *,
    campaign_id: str,
    decision: str | None = None,
    agent_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """List review items for a campaign."""
    results: list[dict[str, Any]] = []
    for item in _review_items.values():
        if item["campaign_id"] != campaign_id:
            continue
        if decision and item["decision"] != decision:
            continue
        if agent_id and item["agent_id"] != agent_id:
            continue
        results.append(item)
        if len(results) >= limit:
            break
    return results


def decide_review_item(
    *,
    item_id: str,
    decision: str,
    decided_by: str,
    reason: str = "",
) -> dict[str, Any]:
    """Certify or revoke an access review item."""
    item = _review_items.get(item_id)
    if not item:
        raise KeyError(f"review item not found: {item_id}")

    if item["decision"] != DECISION_PENDING:
        raise ValueError(f"item already decided: {item['decision']}")

    campaign = _campaigns.get(item["campaign_id"])
    if not campaign:
        raise KeyError(f"campaign not found: {item['campaign_id']}")

    if decision not in (DECISION_CERTIFIED, DECISION_REVOKED):
        raise ValueError(f"invalid decision: {decision} (must be certified or revoked)")

    item["decision"] = decision
    item["decided_by"] = decided_by
    item["decided_at"] = time.time()
    item["reason"] = reason

    campaign["pending_count"] -= 1
    if decision == DECISION_CERTIFIED:
        campaign["certified_count"] += 1
    else:
        campaign["revoked_count"] += 1

    # Auto-complete campaign if all items decided
    if campaign["pending_count"] <= 0 and campaign["status"] == STATUS_ACTIVE:
        campaign["status"] = STATUS_COMPLETED
        campaign["completed_at"] = time.time()

    return item


def get_campaign_progress(campaign_id: str) -> dict[str, Any]:
    """Get detailed progress metrics for a campaign."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        raise KeyError(f"campaign not found: {campaign_id}")

    total = campaign["total_items"]
    decided = campaign["certified_count"] + campaign["revoked_count"]
    completion_rate = round(decided / total, 3) if total > 0 else 0.0

    remaining_time = max(0, campaign["deadline"] - time.time())

    return {
        "campaign_id": campaign_id,
        "status": campaign["status"],
        "total_items": total,
        "certified": campaign["certified_count"],
        "revoked": campaign["revoked_count"],
        "pending": campaign["pending_count"],
        "completion_rate": completion_rate,
        "remaining_seconds": round(remaining_time),
        "overdue": time.time() > campaign["deadline"],
    }


def get_compliance_summary() -> dict[str, Any]:
    """Get overall access review compliance summary."""
    total_campaigns = len(_campaigns)
    completed = sum(1 for c in _campaigns.values() if c["status"] == STATUS_COMPLETED)
    active = sum(1 for c in _campaigns.values() if c["status"] == STATUS_ACTIVE)
    expired = sum(1 for c in _campaigns.values() if c["status"] == STATUS_EXPIRED)

    total_items = len(_review_items)
    certified = sum(1 for i in _review_items.values() if i["decision"] == DECISION_CERTIFIED)
    revoked = sum(1 for i in _review_items.values() if i["decision"] == DECISION_REVOKED)
    auto_revoked = sum(1 for i in _review_items.values() if i["decision"] == DECISION_AUTO_REVOKED)
    pending = sum(1 for i in _review_items.values() if i["decision"] == DECISION_PENDING)

    certification_rate = round(certified / total_items, 3) if total_items > 0 else 0.0
    completion_rate = round((total_items - pending) / total_items, 3) if total_items > 0 else 0.0

    return {
        "total_campaigns": total_campaigns,
        "campaigns_completed": completed,
        "campaigns_active": active,
        "campaigns_expired": expired,
        "total_items": total_items,
        "items_certified": certified,
        "items_revoked": revoked,
        "items_auto_revoked": auto_revoked,
        "items_pending": pending,
        "certification_rate": certification_rate,
        "completion_rate": completion_rate,
    }


# ── Internal helpers ─────────────────────────────────────────────────

def _create_review_item(
    *,
    campaign_id: str,
    agent_id: str,
    entitlement_type: str,
    entitlement_detail: str = "",
    resource: str | None = None,
) -> dict[str, Any]:
    """Create a review item (internal)."""
    item_id = f"review-{uuid.uuid4().hex[:12]}"
    item: dict[str, Any] = {
        "item_id": item_id,
        "campaign_id": campaign_id,
        "agent_id": agent_id,
        "entitlement_type": entitlement_type,
        "entitlement_detail": entitlement_detail,
        "resource": resource,
        "decision": DECISION_PENDING,
        "decided_by": None,
        "decided_at": None,
        "reason": "",
        "created_at": time.time(),
    }
    _review_items[item_id] = item
    if len(_review_items) > _MAX_RECORDS:
        oldest = sorted(_review_items, key=lambda k: _review_items[k]["created_at"])
        for k in oldest[: len(oldest) - _MAX_RECORDS]:
            del _review_items[k]
    return item


def _expire_campaign(campaign_id: str) -> None:
    """Expire a campaign and auto-revoke pending items."""
    campaign = _campaigns.get(campaign_id)
    if not campaign:
        return
    campaign["status"] = STATUS_EXPIRED
    campaign["completed_at"] = time.time()

    # Auto-revoke all pending items
    for item in _review_items.values():
        if item["campaign_id"] == campaign_id and item["decision"] == DECISION_PENDING:
            item["decision"] = DECISION_AUTO_REVOKED
            item["decided_by"] = "system"
            item["decided_at"] = time.time()
            item["reason"] = "auto-revoked: campaign expired"
            campaign["pending_count"] -= 1
            campaign["revoked_count"] += 1

    _log.warning("campaign expired, pending items auto-revoked: %s", campaign_id)


def reset_for_tests() -> None:
    """Clear all access review data for testing."""
    _campaigns.clear()
    _review_items.clear()
