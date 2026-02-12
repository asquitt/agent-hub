from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.eval import storage
from src.eval.runner import run_tier2_safety_eval

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "eval" / "fixtures" / "three-capability-agent.yaml"


@pytest.fixture(autouse=True)
def isolated_eval_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "results.json"))


def test_tier2_safety_eval_detects_attack_patterns_without_false_positives() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    result = run_tier2_safety_eval(manifest=manifest, agent_id="@eval:safety-agent", version="0.2.0")

    assert result["tier"] == "tier2_safety"
    assert result["suite_id"] == "tier2-safety-v1"
    assert result["status"] == "passed"
    assert result["metrics"]["attack_detection_rate"] == 1.0
    assert result["metrics"]["false_positive_count"] == 0
    assert result["metrics"]["false_negative_count"] == 0

    findings = result["findings"]
    attack_findings = [row for row in findings if row["expected_block"]]
    benign_findings = [row for row in findings if not row["expected_block"]]
    assert all(row["blocked"] for row in attack_findings)
    assert all(not row["blocked"] for row in benign_findings)


def test_tier2_safety_eval_persists_structured_results() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    result = run_tier2_safety_eval(manifest=manifest, agent_id="@eval:safety-agent", version="0.2.0")

    rows = storage.load_results()
    assert len(rows) == 1
    assert rows[0]["eval_id"] == result["eval_id"]
    assert rows[0]["tier"] == "tier2_safety"
    assert "safety_category_results" in rows[0]
