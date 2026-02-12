from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "eval" / "agenthub_eval.py"
FIXTURE = ROOT / "tests" / "eval" / "fixtures" / "three-capability-agent.yaml"


def test_cli_runs_local_eval_suite(tmp_path: Path) -> None:
    results_path = tmp_path / "cli-results.json"
    env = dict(**os.environ)
    env["AGENTHUB_EVAL_RESULTS_PATH"] = str(results_path)

    result = subprocess.run(
        [sys.executable, str(CLI), "eval", "--manifest", str(FIXTURE), "--agent-id", "@eval:cli-agent"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["agent_id"] == "@eval:cli-agent"
    assert payload["tier"] == "tier1_contract"
    assert payload["suite_id"] == "tier1-contract-v1"
