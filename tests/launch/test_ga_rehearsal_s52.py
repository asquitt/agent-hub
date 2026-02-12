from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.store import STORE
from src.launch import build_ga_launch_rehearsal_report
from src.lease import service as lease_service

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def reset_runtime_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry_db = tmp_path / "registry.db"
    monkeypatch.setenv("AGENTHUB_REGISTRY_DB_PATH", str(registry_db))
    STORE.reset_for_tests(db_path=registry_db)
    lease_service.LEASES.clear()
    lease_service.INSTALLS.clear()


def _load_manifest() -> dict:
    return yaml.safe_load((ROOT / "specs" / "manifest" / "examples" / "simple-tool-agent.yaml").read_text(encoding="utf-8"))


def _load_metrics() -> dict:
    return json.loads((ROOT / "data" / "launch" / "onboarding_metrics.json").read_text(encoding="utf-8"))


def _gate_review(decision: str) -> dict:
    upper = decision.upper()
    return {
        "decision": upper,
        "blocking_reasons": ["Reliability target met in pilot workloads"] if upper != "GO" else [],
        "gate_version": "v3",
        "generated_at": "2026-02-12T23:05:00+00:00",
    }


def test_s52_ga_rehearsal_report_passes_when_gate_is_go() -> None:
    manifest = _load_manifest()
    metrics = _load_metrics()

    with TestClient(app) as client:
        report = build_ga_launch_rehearsal_report(
            client=client,
            manifest=manifest,
            onboarding_metrics=metrics,
            gate_review=_gate_review("GO"),
        )

    assert report["ga_candidate_ready"] is True
    assert all(check["passed"] for check in report["checks"])
    assert report["incident_drills"]["passed"] is True
    assert report["rollback_simulation"]["passed"] is True
    assert len(report["incident_drills"]["drills"]) == 3

    for drill in report["incident_drills"]["drills"]:
        assert "incident_id" in drill
        assert "occurred_at" in drill
        assert "severity" in drill
        assert "category" in drill
        assert "affected_flow" in drill
        assert "resolved" in drill
        assert "mitigation" in drill
        assert "owner" in drill


def test_s52_ga_rehearsal_report_blocks_when_gate_is_no_go() -> None:
    with TestClient(app) as client:
        report = build_ga_launch_rehearsal_report(
            client=client,
            manifest=_load_manifest(),
            onboarding_metrics=_load_metrics(),
            gate_review=_gate_review("NO_GO"),
        )

    assert report["ga_candidate_ready"] is False
    assert report["gate_review"]["decision"] == "NO_GO"
    assert any(reason.startswith("Gate review blocking reasons:") for reason in report["blocking_reasons"])


def test_s52_rehearsal_script_generates_artifacts(tmp_path: Path) -> None:
    gate_review = tmp_path / "gate_review.json"
    out_json = tmp_path / "s52_rehearsal.json"
    out_md = tmp_path / "s52_rehearsal.md"
    gate_review.write_text(json.dumps(_gate_review("GO")), encoding="utf-8")

    run = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "launch" / "rehearse_ga_candidate.py"),
            "--metrics",
            "data/launch/onboarding_metrics.json",
            "--manifest",
            "specs/manifest/examples/simple-tool-agent.yaml",
            "--gate-review",
            str(gate_review),
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
        ],
        check=False,
        text=True,
        capture_output=True,
    )

    assert run.returncode == 0, run.stderr
    payload = json.loads(out_json.read_text(encoding="utf-8"))
    assert payload["launch_rehearsal_version"] == "s52"
    assert payload["ga_candidate_ready"] is True
    assert out_md.exists()
    assert "# S52 GA Launch Rehearsal" in out_md.read_text(encoding="utf-8")
