#!/usr/bin/env python3
"""Recompute trust score for a given agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.trust.scoring import compute_trust_score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agenthub-trust")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--owner", required=True)
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    row = compute_trust_score(agent_id=args.agent_id, owner=args.owner)
    print(json.dumps(row, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
