from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "capability_search"))

from mock_engine import (  # noqa: E402
    list_agent_capabilities,
    match_capabilities,
    recommend_capabilities,
    search_capabilities,
)


def test_q01_nl_search_invoice_extraction_policy_gated() -> None:
    result = search_capabilities(
        query="extract invoice totals",
        filters={
            "min_trust_score": 0.8,
            "max_cost_usd": 0.02,
            "allowed_protocols": ["MCP"],
        },
        pagination={"mode": "offset", "offset": 0, "limit": 10},
    )

    assert result["data"]
    top = result["data"][0]
    assert top["agent_id"] == "invoice-summarizer"
    assert top["capability_id"] == "summarize-invoice"


def test_q04_schema_match_exact_contract() -> None:
    result = match_capabilities(
        input_required=["invoice_text"],
        output_required=["vendor", "total", "due_date"],
        compatibility_mode="exact",
    )

    ids = {(row["agent_id"], row["capability_id"], row["compatibility"]) for row in result["data"]}
    assert ("invoice-summarizer", "summarize-invoice", "exact") in ids
    assert all(row["compatibility"] == "exact" for row in result["data"])


def test_q05_schema_match_backward_compatible() -> None:
    result = match_capabilities(
        input_required=["invoice_text"],
        output_required=["vendor", "total"],
        compatibility_mode="backward_compatible",
    )

    assert result["data"]
    assert any(row["capability_id"] == "summarize-invoice" for row in result["data"])


def test_q06_agent_capability_listing() -> None:
    response = list_agent_capabilities("support-orchestrator")
    capability_ids = {c["capability_id"] for c in response["capabilities"]}
    assert capability_ids == {"classify-ticket", "apply-remediation"}


def test_q07_recommendation_onboarding_gap() -> None:
    response = recommend_capabilities(
        task_description="complete customer onboarding with billing setup",
        current_capability_ids=["validate-identity", "run-policy-screening"],
        pagination={"mode": "offset", "offset": 0, "limit": 10},
    )

    assert response["data"]
    assert response["data"][0]["capability_id"] == "provision-billing"
    assert any(reason["type"] == "coverage_gap" for reason in response["data"][0]["recommendation_reasons"])


def test_q09_negative_malformed_filter_payload() -> None:
    with pytest.raises(ValueError, match="max_latency_ms must be > 0"):
        search_capabilities(query="anything", filters={"max_latency_ms": -5})


def test_q10_negative_no_candidate_passes_policy() -> None:
    result = search_capabilities(
        query="provision billing",
        filters={
            "min_trust_score": 0.95,
            "max_cost_usd": 0.01,
        },
    )
    assert result["data"] == []


def test_cursor_pagination_contract() -> None:
    first_page = search_capabilities(
        query="support ticket",
        pagination={"mode": "cursor", "cursor": "idx:0", "limit": 1},
    )
    assert len(first_page["data"]) == 1
    next_cursor = first_page["pagination"]["next_cursor"]
    assert isinstance(next_cursor, str)

    second_page = search_capabilities(
        query="support ticket",
        pagination={"mode": "cursor", "cursor": next_cursor, "limit": 1},
    )
    assert len(second_page["data"]) == 1
    assert first_page["data"][0]["capability_id"] != second_page["data"][0]["capability_id"]
