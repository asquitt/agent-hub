from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.launch import evaluate_onboarding_funnel, run_demo_smoke

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def reset_store() -> None:
    STORE.namespaces.clear()
    STORE.agents.clear()
    STORE.idempotency_cache.clear()


def test_onboarding_funnel_threshold_checks() -> None:
    metrics = json.loads((ROOT / "data" / "launch" / "onboarding_metrics.json").read_text(encoding="utf-8"))
    report = evaluate_onboarding_funnel(metrics)
    assert report["passed"] is True
    assert all(check["passed"] for check in report["checks"])

    fail = evaluate_onboarding_funnel({"visitors": 100, "signups": 5, "activated": 1, "paid": 0})
    assert fail["passed"] is False


def test_demo_smoke_reproducibility_flow() -> None:
    manifest = yaml.safe_load((ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml").read_text(encoding="utf-8"))
    with TestClient(app) as client:
        report = run_demo_smoke(client=client, manifest=manifest)
    assert report["passed"] is True
    assert len(report["steps"]) == 5
