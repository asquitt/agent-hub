from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RANKING_DOC = ROOT / "docs" / "capability-search" / "ranking-algorithm.md"
SCENARIOS_DOC = ROOT / "docs" / "capability-search" / "query-scenarios.md"
OPENAPI_SPEC = ROOT / "specs" / "capability-search" / "openapi-capability-search-v0.1.yaml"


def test_d02_deliverable_artifacts_exist() -> None:
    assert OPENAPI_SPEC.exists()
    assert RANKING_DOC.exists()
    assert SCENARIOS_DOC.exists()


def test_ranking_document_contains_required_weights_and_pseudocode() -> None:
    text = RANKING_DOC.read_text(encoding="utf-8")
    assert "0.30" in text
    assert "0.25" in text
    assert "0.15" in text
    assert "0.10" in text
    assert "Policy-First Gate" in text
    assert "Pseudocode" in text


def test_query_scenarios_document_has_ten_examples() -> None:
    text = SCENARIOS_DOC.read_text(encoding="utf-8")
    scenario_count = sum(1 for line in text.splitlines() if line.startswith("### Q"))
    assert scenario_count == 10
