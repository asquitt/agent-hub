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
from src.launch import build_ga_launch_rehearsal_report, render_ga_rehearsal_markdown
from src.lease import service as lease_service

DEFAULT_METRICS = "data/launch/onboarding_metrics.json"
DEFAULT_MANIFEST = "specs/manifest/examples/simple-tool-agent.yaml"
DEFAULT_GATE_REVIEW = "docs/gate/S51_GATE_REVIEW.json"
DEFAULT_OUT_JSON = "docs/launch/S52_LAUNCH_REHEARSAL.json"
DEFAULT_OUT_MD = "docs/launch/S52_LAUNCH_REHEARSAL.md"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AgentHub S52 GA launch rehearsal checks.")
    parser.add_argument("--metrics", default=DEFAULT_METRICS)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--gate-review", default=DEFAULT_GATE_REVIEW)
    parser.add_argument("--out-json", default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", default=DEFAULT_OUT_MD)
    return parser


def main() -> int:
    args = build_parser().parse_args()

    metrics = json.loads((ROOT / args.metrics).read_text(encoding="utf-8"))
    manifest = yaml.safe_load((ROOT / args.manifest).read_text(encoding="utf-8"))
    gate_review = json.loads((ROOT / args.gate_review).read_text(encoding="utf-8"))

    STORE.namespaces.clear()
    STORE.agents.clear()
    STORE.idempotency_cache.clear()
    lease_service.LEASES.clear()
    lease_service.INSTALLS.clear()

    with TestClient(app) as client:
        report = build_ga_launch_rehearsal_report(
            client=client,
            manifest=manifest,
            onboarding_metrics=metrics,
            gate_review=gate_review,
        )

    out_json = ROOT / args.out_json
    out_md = ROOT / args.out_md
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(render_ga_rehearsal_markdown(report), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["ga_candidate_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
