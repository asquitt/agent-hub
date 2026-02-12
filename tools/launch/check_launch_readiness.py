#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api.app import app
from src.api.store import STORE
from src.launch import evaluate_onboarding_funnel, run_demo_smoke


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AgentHub S16 launch readiness checks.")
    parser.add_argument("--metrics", default="data/launch/onboarding_metrics.json")
    parser.add_argument("--manifest", default="specs/manifest/examples/simple-tool-agent.yaml")
    parser.add_argument("--out", default="docs/launch/S16_READINESS.json")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    metrics = json.loads((ROOT / args.metrics).read_text(encoding="utf-8"))
    manifest = yaml.safe_load((ROOT / args.manifest).read_text(encoding="utf-8"))

    STORE.namespaces.clear()
    STORE.agents.clear()
    STORE.idempotency_cache.clear()

    with TestClient(app) as client:
        demo = run_demo_smoke(client=client, manifest=manifest)
    funnel = evaluate_onboarding_funnel(metrics)

    report = {
        "demo_reproducibility": demo,
        "onboarding_funnel": funnel,
        "launch_ready": bool(demo["passed"] and funnel["passed"]),
    }

    output = ROOT / args.out
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["launch_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
