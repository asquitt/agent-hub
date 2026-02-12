from __future__ import annotations

import sys
from pathlib import Path

import pytest

from src.api.store import STORE
from src.discovery.service import DISCOVERY_SERVICE

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "discovery"))

from quality_v3 import DEFAULT_DATASET, run_quality_eval  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_quality_eval_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    DISCOVERY_SERVICE.refresh_index(force=True)


def test_search_quality_v3_metrics_and_latency_gates() -> None:
    summary = run_quality_eval(
        dataset_path=DEFAULT_DATASET,
        top_k=5,
        repeats_per_query=4,
        output_path=None,
    )
    metrics = summary["metrics"]
    assert metrics["ndcg_at_k_mean"] >= 0.65
    assert metrics["mrr_mean"] >= 0.65
    assert metrics["latency_p95_ms"] < 250
