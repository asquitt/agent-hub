from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from src.api.app import app

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "capability_search"))

from benchmark import DEFAULT_DATASET, run_benchmark  # noqa: E402
from mock_engine import search_capabilities  # noqa: E402


def test_search_v2_returns_explainability_blocks() -> None:
    response = search_capabilities(
        query="execute approved outbound payments",
        filters={"required_permissions": ["payments.execute"], "min_trust_score": 0.9},
        pagination={"mode": "offset", "offset": 0, "limit": 10},
    )
    assert response["data"]
    assert all("payments.execute" in row["permissions"] for row in response["data"])
    assert "explainability" in response
    assert response["explainability"]["why_selected"]
    assert isinstance(response["explainability"]["why_rejected"], list)
    assert response["explainability"]["ranking_mode"] == "v2"
    assert response["data"][0]["why_selected"]


def test_search_v2_policy_rejection_reasons_are_exposed() -> None:
    response = search_capabilities(
        query="execute payment",
        filters={"required_permissions": ["payments.execute"], "min_trust_score": 0.9},
        pagination={"mode": "offset", "offset": 0, "limit": 10},
    )
    rejected = response["explainability"]["why_rejected"]
    assert rejected
    reasons = {reason["code"] for row in rejected for reason in row["reasons"]}
    assert "policy.required_permissions" in reasons


def test_search_api_rejects_malformed_query_payload() -> None:
    client = TestClient(app)
    response = client.post("/v1/capabilities/search", json={"query": "x"})
    assert response.status_code == 422


def test_search_v2_benchmark_improves_over_baseline() -> None:
    summary = run_benchmark(dataset_path=DEFAULT_DATASET, output_path=None)
    assert summary["improvement"]["top1_accuracy_delta"] >= 0
    assert summary["improvement"]["mrr_delta"] >= 0
    assert summary["v2"]["top3_accuracy"] >= summary["baseline"]["top3_accuracy"]
    assert summary["policy_regression"] is False


def test_search_v2_latency_budget() -> None:
    latencies = []
    for _ in range(200):
        started = time.perf_counter()
        result = search_capabilities(
            query="classify support ticket severity",
            filters={"min_trust_score": 0.8, "max_latency_ms": 150},
            pagination={"mode": "offset", "offset": 0, "limit": 10},
        )
        latencies.append((time.perf_counter() - started) * 1000)
        assert result["data"]
    p95 = statistics.quantiles(latencies, n=100)[94]
    assert p95 < 120, f"search v2 p95 too high: {p95:.3f}ms"
