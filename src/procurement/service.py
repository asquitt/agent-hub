from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from src.common.time import utc_now_iso
from src.procurement import storage

ADMIN_ACTORS = {"owner-dev", "owner-platform"}


def _parse_utc(raw: str) -> datetime:
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_admin(actor: str) -> bool:
    return actor in ADMIN_ACTORS


def _normalize_sellers(allowed_sellers: list[str] | None) -> list[str]:
    if not allowed_sellers:
        return []
    return sorted({str(seller).strip() for seller in allowed_sellers if str(seller).strip()})


def _audit(
    *,
    actor: str,
    action: str,
    outcome: str,
    buyer: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = storage.load("audit")
    row = {
        "audit_id": str(uuid.uuid4()),
        "actor": actor,
        "buyer": buyer,
        "action": action,
        "outcome": outcome,
        "metadata": metadata or {},
        "created_at": utc_now_iso(),
    }
    rows.append(row)
    storage.save("audit", rows)
    return row


def _active_policy_pack(buyer: str) -> dict[str, Any] | None:
    rows = [
        row
        for row in storage.load("policy_packs")
        if row.get("buyer") == buyer and str(row.get("status", "active")) == "active"
    ]
    if not rows:
        return None
    rows.sort(key=lambda row: str(row.get("updated_at", "")), reverse=True)
    return rows[0]


def _refresh_exception_statuses(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    changed = False
    for row in rows:
        if row.get("status") != "active":
            continue
        expires_at = row.get("expires_at")
        if isinstance(expires_at, str) and expires_at.strip():
            if _parse_utc(expires_at) <= now:
                row["status"] = "expired"
                row["updated_at"] = utc_now_iso()
                changed = True
    if changed:
        storage.save("exceptions", rows)
    return rows


def list_policy_packs(buyer: str | None = None) -> list[dict[str, Any]]:
    rows = storage.load("policy_packs")
    if buyer is not None:
        rows = [row for row in rows if row.get("buyer") == buyer]
    rows.sort(key=lambda row: str(row.get("updated_at", "")), reverse=True)
    return rows


def upsert_policy_pack(
    *,
    actor: str,
    buyer: str,
    auto_approve_limit_usd: float,
    hard_stop_limit_usd: float,
    allowed_sellers: list[str] | None = None,
) -> dict[str, Any]:
    if not _is_admin(actor):
        raise PermissionError("admin actor required to manage procurement policy packs")
    if auto_approve_limit_usd <= 0:
        raise ValueError("auto_approve_limit_usd must be > 0")
    if hard_stop_limit_usd <= auto_approve_limit_usd:
        raise ValueError("hard_stop_limit_usd must be > auto_approve_limit_usd")
    normalized_buyer = buyer.strip()
    if not normalized_buyer:
        raise ValueError("buyer must be provided")

    rows = storage.load("policy_packs")
    existing = next((row for row in rows if row.get("buyer") == normalized_buyer), None)
    now = utc_now_iso()
    row = {
        "pack_id": str(existing.get("pack_id")) if existing else str(uuid.uuid4()),
        "buyer": normalized_buyer,
        "auto_approve_limit_usd": round(float(auto_approve_limit_usd), 6),
        "hard_stop_limit_usd": round(float(hard_stop_limit_usd), 6),
        "allowed_sellers": _normalize_sellers(allowed_sellers),
        "status": "active",
        "created_by": str(existing.get("created_by")) if existing else actor,
        "created_at": str(existing.get("created_at")) if existing else now,
        "updated_by": actor,
        "updated_at": now,
    }
    if existing is None:
        rows.append(row)
    else:
        index = rows.index(existing)
        rows[index] = row
    storage.save("policy_packs", rows)
    _audit(
        actor=actor,
        buyer=normalized_buyer,
        action="policy_pack.upsert",
        outcome="allow",
        metadata={"pack_id": row["pack_id"]},
    )
    return row


def create_approval_request(
    *,
    actor: str,
    buyer: str,
    listing_id: str,
    units: int,
    estimated_total_usd: float,
    note: str | None = None,
) -> dict[str, Any]:
    if actor != buyer and not _is_admin(actor):
        raise PermissionError("actor not permitted to request procurement approval")
    if units <= 0:
        raise ValueError("units must be > 0")
    if estimated_total_usd <= 0:
        raise ValueError("estimated_total_usd must be > 0")

    now = utc_now_iso()
    row = {
        "approval_id": str(uuid.uuid4()),
        "buyer": buyer,
        "listing_id": listing_id,
        "units": int(units),
        "requested_total_usd": round(float(estimated_total_usd), 6),
        "note": note,
        "status": "pending",
        "requested_by": actor,
        "created_at": now,
        "updated_at": now,
        "decision": None,
        "decided_by": None,
        "decided_at": None,
        "decision_note": None,
        "approved_max_total_usd": None,
    }
    rows = storage.load("approvals")
    rows.append(row)
    storage.save("approvals", rows)
    _audit(
        actor=actor,
        buyer=buyer,
        action="approval.request",
        outcome="pending",
        metadata={"approval_id": row["approval_id"], "listing_id": listing_id, "units": units},
    )
    return row


def list_approvals(buyer: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    rows = storage.load("approvals")
    if buyer is not None:
        rows = [row for row in rows if row.get("buyer") == buyer]
    if status is not None:
        normalized = status.strip().lower()
        rows = [row for row in rows if str(row.get("status", "")).lower() == normalized]
    rows.sort(key=lambda row: str(row.get("updated_at", "")), reverse=True)
    return rows


def decide_approval(
    *,
    actor: str,
    approval_id: str,
    decision: str,
    approved_max_total_usd: float | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if not _is_admin(actor):
        raise PermissionError("admin actor required to decide procurement approvals")
    normalized = decision.strip().lower()
    if normalized not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")

    rows = storage.load("approvals")
    row = next((item for item in rows if item.get("approval_id") == approval_id), None)
    if row is None:
        raise KeyError("approval not found")
    if row.get("status") != "pending":
        raise ValueError("approval is already decided")

    approved_limit: float | None = None
    if normalized == "approve":
        requested_total = float(row.get("requested_total_usd", 0.0))
        if approved_max_total_usd is None:
            approved_limit = requested_total
        else:
            if approved_max_total_usd <= 0:
                raise ValueError("approved_max_total_usd must be > 0")
            approved_limit = round(float(approved_max_total_usd), 6)

    updated = {
        **row,
        "status": "approved" if normalized == "approve" else "rejected",
        "decision": normalized,
        "decided_by": actor,
        "decided_at": utc_now_iso(),
        "decision_note": note,
        "approved_max_total_usd": approved_limit,
        "updated_at": utc_now_iso(),
    }
    rows[rows.index(row)] = updated
    storage.save("approvals", rows)
    _audit(
        actor=actor,
        buyer=str(updated.get("buyer")),
        action="approval.decision",
        outcome=str(updated.get("status")),
        metadata={"approval_id": approval_id, "decision": normalized},
    )
    return updated


def create_exception(
    *,
    actor: str,
    buyer: str,
    reason: str,
    override_hard_stop_limit_usd: float | None = None,
    allow_seller_id: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    if not _is_admin(actor):
        raise PermissionError("admin actor required to create procurement exceptions")
    if len(reason.strip()) < 3:
        raise ValueError("reason must be at least 3 characters")
    if override_hard_stop_limit_usd is None and not (allow_seller_id and allow_seller_id.strip()):
        raise ValueError("exception must include override_hard_stop_limit_usd and/or allow_seller_id")
    parsed_expiry: str | None = None
    if expires_at is not None and expires_at.strip():
        expires = _parse_utc(expires_at)
        if expires <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        parsed_expiry = expires.isoformat()

    row = {
        "exception_id": str(uuid.uuid4()),
        "buyer": buyer,
        "reason": reason.strip(),
        "status": "active",
        "override_hard_stop_limit_usd": round(float(override_hard_stop_limit_usd), 6)
        if override_hard_stop_limit_usd is not None
        else None,
        "allow_seller_id": allow_seller_id.strip() if allow_seller_id else None,
        "created_by": actor,
        "created_at": utc_now_iso(),
        "updated_at": utc_now_iso(),
        "expires_at": parsed_expiry,
    }
    rows = storage.load("exceptions")
    rows.append(row)
    storage.save("exceptions", rows)
    _audit(
        actor=actor,
        buyer=buyer,
        action="exception.create",
        outcome="allow",
        metadata={"exception_id": row["exception_id"]},
    )
    return row


def list_exceptions(buyer: str | None = None, active_only: bool = False) -> list[dict[str, Any]]:
    rows = _refresh_exception_statuses(storage.load("exceptions"))
    if buyer is not None:
        rows = [row for row in rows if row.get("buyer") == buyer]
    if active_only:
        rows = [row for row in rows if row.get("status") == "active"]
    rows.sort(key=lambda row: str(row.get("updated_at", "")), reverse=True)
    return rows


def _lookup_approved_approval(approval_id: str, buyer: str, listing_id: str, estimated_total_usd: float) -> dict[str, Any]:
    rows = storage.load("approvals")
    row = next((item for item in rows if item.get("approval_id") == approval_id), None)
    if row is None:
        raise KeyError("approval not found")
    if row.get("status") != "approved":
        raise PermissionError("approval is not approved")
    if row.get("buyer") != buyer:
        raise PermissionError("approval buyer mismatch")
    if row.get("listing_id") != listing_id:
        raise PermissionError("approval listing mismatch")
    cap = row.get("approved_max_total_usd")
    approved_cap = float(cap if cap is not None else row.get("requested_total_usd", 0.0))
    if estimated_total_usd > approved_cap:
        raise PermissionError("approval ceiling below purchase total")
    return row


def _lookup_active_exception(exception_id: str, buyer: str) -> dict[str, Any]:
    rows = list_exceptions(buyer=buyer, active_only=True)
    row = next((item for item in rows if item.get("exception_id") == exception_id), None)
    if row is None:
        raise KeyError("exception not found")
    return row


def evaluate_purchase_policy(
    *,
    actor: str,
    buyer: str,
    listing_id: str,
    seller: str,
    estimated_total_usd: float,
    approval_id: str | None = None,
    exception_id: str | None = None,
) -> dict[str, Any]:
    if actor != buyer and not _is_admin(actor):
        raise PermissionError("actor not permitted to evaluate procurement purchase policy")
    if estimated_total_usd <= 0:
        raise ValueError("estimated_total_usd must be > 0")

    pack = _active_policy_pack(buyer)
    if pack is None:
        decision = {
            "decision": "allow",
            "reason_codes": ["procurement.policy_pack_not_configured"],
            "policy_pack_id": None,
            "approval_id": None,
            "exception_id": None,
            "effective_hard_stop_limit_usd": None,
        }
        _audit(actor=actor, buyer=buyer, action="purchase.evaluate", outcome="allow", metadata=decision)
        return decision

    allowed_sellers = [str(seller_id) for seller_id in pack.get("allowed_sellers", [])]
    exc: dict[str, Any] | None = None
    if exception_id is not None:
        exc = _lookup_active_exception(exception_id=exception_id, buyer=buyer)

    if allowed_sellers and seller not in allowed_sellers:
        allowed_by_exception = exc is not None and exc.get("allow_seller_id") == seller
        if not allowed_by_exception:
            _audit(
                actor=actor,
                buyer=buyer,
                action="purchase.evaluate",
                outcome="deny",
                metadata={"reason_codes": ["procurement.seller_not_allowed"], "seller": seller},
            )
            raise PermissionError("seller not permitted by procurement policy pack")

    hard_stop = float(pack["hard_stop_limit_usd"])
    effective_hard_stop = hard_stop
    if exc is not None and exc.get("override_hard_stop_limit_usd") is not None:
        effective_hard_stop = max(effective_hard_stop, float(exc["override_hard_stop_limit_usd"]))

    if estimated_total_usd > effective_hard_stop:
        _audit(
            actor=actor,
            buyer=buyer,
            action="purchase.evaluate",
            outcome="deny",
            metadata={
                "reason_codes": ["procurement.budget_hard_stop"],
                "estimated_total_usd": round(float(estimated_total_usd), 6),
                "effective_hard_stop_limit_usd": round(float(effective_hard_stop), 6),
            },
        )
        raise PermissionError("purchase exceeds procurement hard stop limit")

    auto_limit = float(pack["auto_approve_limit_usd"])
    approval: dict[str, Any] | None = None
    reason_codes: list[str] = []
    if estimated_total_usd <= auto_limit:
        reason_codes.append("procurement.auto_approved")
    else:
        if not approval_id:
            _audit(
                actor=actor,
                buyer=buyer,
                action="purchase.evaluate",
                outcome="deny",
                metadata={"reason_codes": ["procurement.approval_required"]},
            )
            raise PermissionError("procurement approval required")
        approval = _lookup_approved_approval(
            approval_id=approval_id,
            buyer=buyer,
            listing_id=listing_id,
            estimated_total_usd=estimated_total_usd,
        )
        reason_codes.append("procurement.approved_purchase")

    if exc is not None:
        reason_codes.append("procurement.exception_applied")

    decision = {
        "decision": "allow",
        "reason_codes": reason_codes,
        "policy_pack_id": pack["pack_id"],
        "approval_id": str(approval.get("approval_id")) if approval is not None else None,
        "exception_id": str(exc.get("exception_id")) if exc is not None else None,
        "effective_hard_stop_limit_usd": round(float(effective_hard_stop), 6),
    }
    _audit(actor=actor, buyer=buyer, action="purchase.evaluate", outcome="allow", metadata=decision)
    return decision


def list_audit_events(*, buyer: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    rows = storage.load("audit")
    if buyer is not None:
        rows = [row for row in rows if row.get("buyer") == buyer]
    rows.sort(key=lambda row: str(row.get("created_at", "")), reverse=True)
    return rows[:limit]
