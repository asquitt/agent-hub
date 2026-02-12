#!/usr/bin/env python3
"""AgentHub eval CLI shim (D09)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.eval.runner import run_eval_from_manifest_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="agenthub", description="AgentHub CLI shim")
    sub = parser.add_subparsers(dest="command", required=True)

    eval_parser = sub.add_parser("eval", help="Run local eval suite against a manifest")
    eval_parser.add_argument("--manifest", required=True, help="Path to agent manifest YAML")
    eval_parser.add_argument("--agent-id", required=False, help="Agent identifier override")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.command == "eval":
        result = run_eval_from_manifest_path(manifest_path=args.manifest, agent_id=args.agent_id)
        print(json.dumps(result, indent=2))
        return 0

    print("unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
