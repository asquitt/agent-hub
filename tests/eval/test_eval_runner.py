from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.eval import storage
from src.eval.runner import run_tier1_eval

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "eval" / "fixtures" / "three-capability-agent.yaml"


@pytest.fixture(autouse=True)
def isolated_eval_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTHUB_EVAL_RESULTS_PATH", str(tmp_path / "results.json"))


def test_tier1_eval_covers_three_capability_types() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    result = run_tier1_eval(manifest=manifest, agent_id="@eval:three-capability", version="0.1.0")

    assert result["tier"] == "tier1_contract"
    assert result["suite_id"] == "tier1-contract-v1"
    assert result["seed"] == 42
    assert result["status"] == "passed"

    by_type = result["capability_type_results"]
    assert by_type["reasoning"]["passed"] == 1
    assert by_type["transformation"]["passed"] == 1
    assert by_type["action"]["passed"] == 1


def test_tier1_eval_persists_structured_metrics_and_trace() -> None:
    manifest = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    result = run_tier1_eval(manifest=manifest, agent_id="@eval:three-capability", version="0.1.0")

    assert result["metrics"]["accuracy"] == 1.0
    assert result["metrics"]["cost_usd"] > 0
    assert result["metrics"]["latency_ms"] >= 0
    assert any(event["event"] == "sandbox.start" for event in result["trace"])

    rows = storage.load_results()
    assert len(rows) == 1
    assert rows[0]["eval_id"] == result["eval_id"]
