#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.gate import evaluate_gate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate AgentHub S10 gate decision from pilot metrics.")
    parser.add_argument("--metrics", required=True, help="Path to pilot metrics JSON.")
    parser.add_argument("--out", help="Optional output JSON path for the gate report.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    metrics_path = Path(args.metrics)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    report = evaluate_gate(metrics)

    if args.out:
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["decision"] == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
