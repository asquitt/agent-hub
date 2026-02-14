"""Knowledge contribute, query, validate routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth import require_api_key
from src.api.models import KnowledgeContributeRequest, KnowledgeValidationRequest
from src.knowledge import contribute_entry, query_entries, validate_entry

router = APIRouter(tags=["knowledge"])


@router.post("/v1/knowledge/contribute")
def post_knowledge_contribution(
    request: KnowledgeContributeRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return contribute_entry(
            owner=owner,
            title=request.title,
            content=request.content,
            tags=request.tags,
            source_uri=request.source_uri,
            contributor=request.contributor,
            base_confidence=request.base_confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/v1/knowledge/query")
def get_knowledge_query(
    q: str = Query(min_length=2),
    limit: int = Query(default=10, ge=1, le=50),
    _owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    return {"query": q, "data": query_entries(query=q, limit=limit)}


@router.post("/v1/knowledge/validate/{entry_id}")
def post_knowledge_validation(
    entry_id: str,
    request: KnowledgeValidationRequest,
    owner: str = Depends(require_api_key),
) -> dict[str, Any]:
    try:
        return validate_entry(entry_id=entry_id, validator=owner, verdict=request.verdict, rationale=request.rationale)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="entry not found") from exc
