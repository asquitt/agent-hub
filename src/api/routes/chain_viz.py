"""Delegation chain visualization routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from src.api.auth import AuthContext, require_api_key

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
def get_delegation_trees(actor: AuthContext = Depends(require_api_key)):
    """List all root delegation trees for the authenticated owner."""
    trees = list_delegation_trees(actor)
    return {"trees": trees, "count": len(trees)}


@router.get("/tokens/{token_id}/tree")
def get_chain_tree(token_id: str, actor: AuthContext = Depends(require_api_key)):
    """Get full tree view of a delegation chain."""
    try:
        tree = build_tree_view(token_id, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return tree


@router.get("/tokens/{token_id}/risk")
def get_chain_risk(token_id: str, actor: AuthContext = Depends(require_api_key)):
    """Analyze risk factors in a delegation chain."""
    try:
        risk = analyze_chain_risk(token_id, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return risk


@router.post("/tokens/{token_id}/snapshot")
def create_chain_snapshot(
    token_id: str,
    body: dict | None = None,
    actor: AuthContext = Depends(require_api_key),
):
    """Take a point-in-time snapshot of a delegation chain."""
    label = ""
    if body and isinstance(body, dict):
        label = body.get("label", "")

    try:
        snap = snapshot_chain(token_id, actor=actor, label=label)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return snap


@router.get("/snapshots")
def get_snapshots(
    token_id: str | None = None,
    actor: AuthContext = Depends(require_api_key),
):
    """List chain snapshots, optionally filtered by token_id."""
    snaps = list_snapshots(actor=actor, token_id=token_id)
    return {"snapshots": snaps, "count": len(snaps)}


@router.get("/snapshots/{snapshot_id}")
def get_snapshot_detail(snapshot_id: str, actor: AuthContext = Depends(require_api_key)):
    """Retrieve a specific chain snapshot."""
    try:
        snap = get_snapshot(snapshot_id, actor=actor)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return snap
