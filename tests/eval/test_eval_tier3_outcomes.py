from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from src.eval import storage
from src.eval.runner import DEFAULT_TIER3_CASES, run_tier3_outcome_eval

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "eval" / "fixtures" / "three-capability-agent.yaml"


@pytest.fixture(autouse=True)
def isolated_eval_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "results.json"))


def test_tier3_outcome_eval_passes_default_design_partner_kpi_gates() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    result = run_tier3_outcome_eval(manifest=manifest, agent_id="@eval:outcomes-agent", version="0.3.0")

    assert result["tier"] == "tier3_outcomes"
    assert result["suite_id"] == "tier3-outcomes-v1"
    assert result["status"] == "passed"
    assert result["metrics"]["pass_rate"] >= result["metrics"]["pass_rate_gate"]
    assert result["metrics"]["critical_case_failures"] == 0

    rows = storage.load_results()
    assert len(rows) == 1
    assert rows[0]["eval_id"] == result["eval_id"]
    assert rows[0]["tier"] == "tier3_outcomes"


def test_tier3_outcome_eval_fails_when_critical_case_misses_kpi_gate() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    cases = copy.deepcopy(DEFAULT_TIER3_CASES)
    cases[0]["kpis"][0]["observed"] = 0.6

    result = run_tier3_outcome_eval(
        manifest=manifest,
        agent_id="@eval:outcomes-agent",
        version="0.3.0",
        cases=cases,
    )

    assert result["status"] == "failed"
    assert result["metrics"]["critical_case_failures"] == 1
