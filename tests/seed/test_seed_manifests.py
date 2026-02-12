from __future__ import annotations

from pathlib import Path

import yaml

from src.api.manifest_validation import validate_manifest_object

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "seed" / "agents"


def test_three_seed_manifests_are_schema_valid() -> None:
    manifests = [
        SEED / "web-researcher.yaml",
        SEED / "data-normalizer.yaml",
        SEED / "pipeline-planner.yaml",
    ]

    for path in manifests:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors = validate_manifest_object(loaded)
        assert errors == [], f"{path} has validation errors: {errors}"


def test_pipeline_planner_declares_discovery_orchestration_capability() -> None:
    planner = yaml.safe_load((SEED / "pipeline-planner.yaml").read_text(encoding="utf-8"))
    capability_ids = {c["id"] for c in planner["capabilities"]}
    assert "plan-pipeline" in capability_ids
