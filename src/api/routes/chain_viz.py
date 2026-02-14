"""Delegation chain visualization routes."""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request

from src.runtime.chain_viz import (
    analyze_chain_risk,
    build_tree_view,
    get_snapshot,
    list_delegation_trees,
    list_snapshots,
    snapshot_chain,
)

router = APIRouter(prefix="/v1/chain-viz", tags=["chain-viz"])


@router.get("/trees")
def get_delegation_trees(request: Request, x_api_key: str = Header(...)):
    """List all root delegation trees for the authenticated owner."""
    owner = getattr(request.state, "agenthub_owner", None)
    if not owner:
        raise HTTPException(status_code=401, detail="authentication required")
    trees = list_delegation_trees(owner)
    return {"trees": trees, "count": len(trees)}


@router.get("/tokens/{token_id}/tree")
def get_chain_tree(token_id: str, x_api_key: str = Header(...)):
    """Get full tree view of a delegation chain."""
    try:
        tree = build_tree_view(token_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return tree


@router.get("/tokens/{token_id}/risk")
def get_chain_risk(token_id: str, x_api_key: str = Header(...)):
    """Analyze risk factors in a delegation chain."""
    try:
        risk = analyze_chain_risk(token_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return risk


@router.post("/tokens/{token_id}/snapshot")
def create_chain_snapshot(
    token_id: str,
    body: dict | None = None,
    x_api_key: str = Header(...),
):
    """Take a point-in-time snapshot of a delegation chain."""
    label = ""
    if body and isinstance(body, dict):
        label = body.get("label", "")

    try:
        snap = snapshot_chain(token_id, label=label)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return snap


@router.get("/snapshots")
def get_snapshots(
    token_id: str | None = None,
    x_api_key: str = Header(...),
):
    """List chain snapshots, optionally filtered by token_id."""
    snaps = list_snapshots(token_id=token_id)
    return {"snapshots": snaps, "count": len(snaps)}


@router.get("/snapshots/{snapshot_id}")
def get_snapshot_detail(snapshot_id: str, x_api_key: str = Header(...)):
    """Retrieve a specific chain snapshot."""
    try:
        snap = get_snapshot(snapshot_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return snap
