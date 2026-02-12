from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.economics import DEFAULT_THRESHOLDS, aggregate_pilot_economics, optimize_economics

DEFAULT_PILOT_A = ROOT / "data" / "pilots" / "pilot_a_weekly.json"
DEFAULT_PILOT_B = ROOT / "data" / "pilots" / "pilot_b_weekly.json"
DEFAULT_OUTPUT = ROOT / "data" / "pilots" / "economics_hardening.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run economics hardening optimization loop for pilot metrics.")
    parser.add_argument("--pilot-a", type=Path, default=DEFAULT_PILOT_A)
    parser.add_argument("--pilot-b", type=Path, default=DEFAULT_PILOT_B)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    pilot_a = _load(args.pilot_a)
    pilot_b = _load(args.pilot_b)
    snapshot = aggregate_pilot_economics([pilot_a["metrics"], pilot_b["metrics"]])
    optimization = optimize_economics(snapshot, thresholds=DEFAULT_THRESHOLDS)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {"pilot_a": str(args.pilot_a), "pilot_b": str(args.pilot_b)},
        "economics_snapshot": snapshot,
        "optimization": optimization,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
