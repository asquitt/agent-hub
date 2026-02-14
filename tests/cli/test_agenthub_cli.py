from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_cli(
    args: list[str],
    cwd: Path,
    state_home: Path,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["AGENTHUB_HOME"] = str(state_home)
    env["PYTHONPATH"] = str(ROOT)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "agenthub.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def parse_json_stdout(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def test_all_commands_with_json_support(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    # 1) init
    state_home = tmp_path / ".agenthub-test"

    init_res = run_cli(["init", "seed-agent", "--json"], cwd=workspace, state_home=state_home)
    assert init_res.returncode == 0, init_res.stderr
    init_payload = parse_json_stdout(init_res)
    manifest_path = Path(init_payload["created"])
    if not manifest_path.is_absolute():
        manifest_path = workspace / manifest_path
    assert manifest_path.exists()

    # 2) validate (offline)
    validate_res = run_cli(["validate", str(manifest_path), "--json"], cwd=workspace, state_home=state_home)
    assert validate_res.returncode == 0, validate_res.stdout + validate_res.stderr
    assert parse_json_stdout(validate_res)["valid"] is True

    # 3) login
    login_res = run_cli(["login", "--api-key", "dev-owner-key", "--api-url", "http://127.0.0.1:8000", "--json"], cwd=workspace, state_home=state_home)
    assert login_res.returncode == 0

    # 4) whoami
    whoami_res = run_cli(["whoami", "--json"], cwd=workspace, state_home=state_home)
    assert whoami_res.returncode == 0
    assert parse_json_stdout(whoami_res)["api_key"].startswith("dev-")

    # 5) publish (local)
    publish1 = run_cli(["publish", str(ROOT / "seed" / "agents" / "web-researcher.yaml"), "--namespace", "@seed", "--local", "--json"], cwd=workspace, state_home=state_home)
    publish2 = run_cli(["publish", str(ROOT / "seed" / "agents" / "data-normalizer.yaml"), "--namespace", "@seed", "--local", "--json"], cwd=workspace, state_home=state_home)
    publish3 = run_cli(["publish", str(ROOT / "seed" / "agents" / "pipeline-planner.yaml"), "--namespace", "@seed", "--local", "--json"], cwd=workspace, state_home=state_home)
    assert publish1.returncode == publish2.returncode == publish3.returncode == 0

    # 6) search (local)
    search_res = run_cli(["search", "normalize records", "--local", "--json"], cwd=workspace, state_home=state_home)
    assert search_res.returncode == 0
    assert parse_json_stdout(search_res)["results"]

    # 7) install
    install_res = run_cli(["install", "@seed:pipeline-planner", "--json"], cwd=workspace, state_home=state_home)
    assert install_res.returncode == 0
    assert (workspace / "agenthub.lock").exists()

    # 8) run
    run_res = run_cli(["run", "@seed:pipeline-planner", "--input", "task=plan", "--json"], cwd=workspace, state_home=state_home)
    assert run_res.returncode == 0
    assert parse_json_stdout(run_res)["status"] == "completed"

    # 9) eval
    eval_res = run_cli(["eval", "--manifest", str(ROOT / "seed" / "agents" / "pipeline-planner.yaml"), "--agent-id", "@seed:pipeline-planner", "--json"], cwd=workspace, state_home=state_home)
    assert eval_res.returncode == 0
    assert parse_json_stdout(eval_res)["suite_id"] == "tier1-contract-v1"

    # 10) versions (local)
    versions_res = run_cli(["versions", "@seed:pipeline-planner", "--local", "--json"], cwd=workspace, state_home=state_home)
    assert versions_res.returncode == 0
    versions_payload = parse_json_stdout(versions_res)
    assert versions_payload["agent_id"] == "@seed:pipeline-planner"
    assert versions_payload["versions"]

    # 11) doctor (local)
    doctor_env = {
        "AGENTHUB_API_KEYS_JSON": '{"dev-owner-key":"owner-dev"}',
        "AGENTHUB_AUTH_TOKEN_SECRET": "doctor-secret",
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": '{"partner-east":"token"}',
        "AGENTHUB_POLICY_SIGNING_SECRET": "doctor-policy-secret",
        "AGENTHUB_PROVENANCE_SIGNING_SECRET": "doctor-provenance-secret",
    }
    doctor_res = run_cli(["doctor", "--local", "--json"], cwd=workspace, state_home=state_home, extra_env=doctor_env)
    assert doctor_res.returncode == 0
    doctor_payload = parse_json_stdout(doctor_res)
    assert doctor_payload["mode"] == "local"
    assert doctor_payload["startup_ready"] is True
    assert doctor_payload["overall_ready"] is True


def test_doctor_local_returns_nonzero_for_invalid_startup_env(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    state_home = tmp_path / ".agenthub-test"
    bad_env = {
        "AGENTHUB_API_KEYS_JSON": "{bad-json",
        "AGENTHUB_AUTH_TOKEN_SECRET": "",
        "AGENTHUB_FEDERATION_DOMAIN_TOKENS_JSON": "{}",
        "AGENTHUB_POLICY_SIGNING_SECRET": "",
        "AGENTHUB_PROVENANCE_SIGNING_SECRET": "",
    }
    doctor_res = run_cli(["doctor", "--local", "--json"], cwd=workspace, state_home=state_home, extra_env=bad_env)
    assert doctor_res.returncode == 1
    payload = parse_json_stdout(doctor_res)
    assert payload["mode"] == "local"
    assert payload["startup_ready"] is False
    assert payload["overall_ready"] is False
    assert "AGENTHUB_API_KEYS_JSON" in payload["missing_or_invalid"]


def test_doctor_remote_requires_api_key(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    state_home = tmp_path / ".agenthub-test"
    doctor_res = run_cli(["doctor", "--remote", "--json"], cwd=workspace, state_home=state_home)
    assert doctor_res.returncode == 1
    payload = parse_json_stdout(doctor_res)
    assert payload["mode"] == "remote"
    assert "missing API key" in payload["error"]
