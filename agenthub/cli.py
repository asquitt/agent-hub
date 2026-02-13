from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api.manifest_validation import validate_manifest_object
from src.api.startup_diagnostics import build_startup_diagnostics
from src.eval.runner import run_eval_from_manifest_path
from tools.capability_search.mock_engine import search_capabilities as local_search

console = Console()


def _agenthub_home() -> Path:
    root = os.getenv("AGENTHUB_HOME")
    if root:
        return Path(root).expanduser().resolve()
    return Path.home() / ".agenthub"


def _config_path() -> Path:
    return _agenthub_home() / "config.json"


def _local_registry_path() -> Path:
    return _agenthub_home() / "local_registry.json"


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _config() -> dict[str, Any]:
    return _load_json(_config_path(), {"api_url": "http://127.0.0.1:8000", "api_key": None})


def _registry() -> dict[str, Any]:
    return _load_json(_local_registry_path(), {"agents": {}})


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        if isinstance(data, str):
            console.print(data)
        else:
            console.print_json(data=json.dumps(data))


def _auth_headers(config: dict[str, Any]) -> dict[str, str]:
    headers = {}
    if config.get("api_key"):
        headers["X-API-Key"] = config["api_key"]
    return headers


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.name)
    target.mkdir(parents=True, exist_ok=True)
    manifest_path = target / "agent.yaml"
    if manifest_path.exists() and not args.force:
        console.print(f"[red]Manifest exists:[/red] {manifest_path}")
        return 1

    manifest = {
        "schema_version": "0.1",
        "identity": {
            "id": args.name.replace("_", "-").lower(),
            "name": f"{args.name} Agent",
            "version": "0.1.0",
            "description": "Template manifest scaffolded by agenthub init.",
            "owner": "local-dev",
            "type": "tool",
        },
        "capabilities": [
            {
                "id": "example-capability",
                "name": "Example Capability",
                "category": "transformation",
                "description": "Template capability description for scaffolded manifest.",
                "input_schema": {"type": "object", "properties": {"input": {"type": "string"}}, "required": ["input"]},
                "output_schema": {"type": "object", "properties": {"output": {"type": "string"}}, "required": ["output"]},
                "protocols": ["MCP"],
                "idempotency_key_required": False,
                "side_effect_level": "none",
            }
        ],
        "interfaces": [
            {
                "name": "mcp",
                "protocol": "MCP",
                "endpoint": "https://example.local/mcp",
                "auth": "signed_jwt",
                "privileged": False,
            }
        ],
        "trust": {
            "minimum_trust_score": 0.7,
            "allowed_trust_sources": ["first_party"],
            "policy": {
                "injection_protection": "strict",
                "pii_handling": "deny",
                "data_retention_days": 7,
                "high_risk_approval_required": True,
            },
            "budget_guardrails": {"soft_alert_pct": 80, "reauthorization_pct": 100, "hard_stop_pct": 120},
            "credential_policy": {"short_lived_credentials": True, "max_ttl_minutes": 60},
        },
        "runtime": {
            "execution_mode": "deterministic_workflow",
            "sandbox": "container",
            "max_retries": 1,
            "timeout_seconds": 20,
            "idempotency_required": True,
            "replay_safe": True,
            "observability": {"log_privileged_actions": True, "emit_cost_metrics": True, "emit_latency_metrics": True},
        },
    }
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    _emit({"created": str(manifest_path)}, args.json)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    manifest = yaml.safe_load(Path(args.manifest).read_text(encoding="utf-8"))
    errors = validate_manifest_object(manifest)
    if errors:
        _emit({"valid": False, "errors": errors}, args.json)
        return 1
    _emit({"valid": True, "manifest": args.manifest}, args.json)
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    if args.local:
        reg = _registry()
        agent_id = f"{args.namespace}:{manifest['identity']['id']}"
        reg["agents"][agent_id] = {
            "namespace": args.namespace,
            "manifest": manifest,
            "versions": reg["agents"].get(agent_id, {}).get("versions", []) + [manifest["identity"]["version"]],
        }
        _save_json(_local_registry_path(), reg)
        _emit({"published": True, "agent_id": agent_id, "mode": "local"}, args.json)
        return 0

    config = _config()
    api_url = args.api_url or config["api_url"]
    headers = _auth_headers(config)
    if args.api_key:
        headers["X-API-Key"] = args.api_key
    headers["Idempotency-Key"] = args.idempotency_key or str(uuid.uuid4())

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Publishing manifest", total=None)
        response = httpx.post(
            f"{api_url}/v1/agents",
            json={"namespace": args.namespace, "manifest": manifest},
            headers=headers,
            timeout=10,
        )

    if response.status_code >= 400:
        _emit({"published": False, "status_code": response.status_code, "error": response.text}, args.json)
        return 1

    _emit(response.json(), args.json)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    filters = {}
    if args.max_cost is not None:
        filters["max_cost_usd"] = args.max_cost
    if args.min_trust is not None:
        filters["min_trust_score"] = args.min_trust

    if args.local:
        response = local_search(args.query, filters=filters or None, pagination={"mode": "offset", "offset": 0, "limit": args.limit})
        rows = response["data"]
    else:
        config = _config()
        api_url = args.api_url or config["api_url"]
        payload = {"query": args.query, "filters": filters or None, "pagination": {"mode": "offset", "offset": 0, "limit": args.limit}}
        response = httpx.post(f"{api_url}/v1/capabilities/search", json=payload, timeout=10)
        if response.status_code >= 400:
            _emit({"error": response.text, "status_code": response.status_code}, args.json)
            return 1
        rows = response.json()["data"]

    if args.json:
        _emit({"results": rows}, True)
        return 0

    table = Table(title="Capability Search Results")
    table.add_column("Agent")
    table.add_column("Capability")
    table.add_column("Trust")
    table.add_column("Cost")
    for row in rows:
        table.add_row(row["agent_id"], row["capability_id"], str(row["trust_score"]), str(row["estimated_cost_usd"]))
    console.print(table)
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    lock_path = Path("agenthub.lock")
    lock = _load_json(lock_path, {"dependencies": []})
    lock["dependencies"].append({"agent": args.agent_ref})
    _save_json(lock_path, lock)
    _emit({"installed": args.agent_ref, "lockfile": str(lock_path)}, args.json)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    output = {
        "agent": args.agent_ref,
        "input": args.input,
        "status": "completed",
        "output": f"Simulated run output for {args.agent_ref}",
    }
    _emit(output, args.json)
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    result = run_eval_from_manifest_path(args.manifest, agent_id=args.agent_id)
    _emit(result, args.json)
    return 0


def cmd_versions(args: argparse.Namespace) -> int:
    if args.local:
        reg = _registry()
        row = reg["agents"].get(args.agent_id)
        if not row:
            _emit({"error": "agent not found", "agent_id": args.agent_id}, args.json)
            return 1
        _emit({"agent_id": args.agent_id, "versions": row.get("versions", [])}, args.json)
        return 0

    config = _config()
    api_url = args.api_url or config["api_url"]
    response = httpx.get(f"{api_url}/v1/agents/{args.agent_id}/versions", timeout=10)
    if response.status_code >= 400:
        _emit({"error": response.text, "status_code": response.status_code}, args.json)
        return 1
    _emit(response.json(), args.json)
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    payload = {"api_url": args.api_url, "api_key": args.api_key}
    _save_json(_config_path(), payload)
    _emit({"logged_in": True, "api_url": args.api_url}, args.json)
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    cfg = _config()
    key = cfg.get("api_key")
    masked = None if not key else f"{key[:4]}...{key[-4:]}"
    _emit({"api_url": cfg.get("api_url"), "api_key": masked}, args.json)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    if args.local:
        payload = build_startup_diagnostics()
        payload["mode"] = "local"
        _emit(payload, args.json)
        return 0 if payload.get("startup_ready") else 1

    cfg = _config()
    api_url = args.api_url or cfg.get("api_url") or "http://127.0.0.1:8000"
    headers = _auth_headers(cfg)
    if args.api_key:
        headers["X-API-Key"] = args.api_key
    if not headers.get("X-API-Key"):
        _emit({"ok": False, "error": "missing API key (run login or pass --api-key)", "mode": "remote"}, args.json)
        return 1

    response = httpx.get(f"{api_url}/v1/system/startup-diagnostics", headers=headers, timeout=10)
    if response.status_code >= 400:
        _emit(
            {
                "ok": False,
                "status_code": response.status_code,
                "error": response.text,
                "mode": "remote",
                "api_url": api_url,
            },
            args.json,
        )
        return 1
    payload = response.json()
    payload["mode"] = "remote"
    payload["api_url"] = api_url
    _emit(payload, args.json)
    return 0 if payload.get("startup_ready") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agenthub")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("name")
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--json", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate")
    p_validate.add_argument("manifest")
    p_validate.add_argument("--json", action="store_true")
    p_validate.set_defaults(func=cmd_validate)

    p_publish = sub.add_parser("publish")
    p_publish.add_argument("manifest")
    p_publish.add_argument("--namespace", default="@local")
    p_publish.add_argument("--api-url")
    p_publish.add_argument("--api-key")
    p_publish.add_argument("--idempotency-key")
    p_publish.add_argument("--local", action="store_true")
    p_publish.add_argument("--json", action="store_true")
    p_publish.set_defaults(func=cmd_publish)

    p_search = sub.add_parser("search")
    p_search.add_argument("query")
    p_search.add_argument("--api-url")
    p_search.add_argument("--local", action="store_true")
    p_search.add_argument("--limit", type=int, default=10)
    p_search.add_argument("--max-cost", type=float)
    p_search.add_argument("--min-trust", type=float)
    p_search.add_argument("--json", action="store_true")
    p_search.set_defaults(func=cmd_search)

    p_install = sub.add_parser("install")
    p_install.add_argument("agent_ref")
    p_install.add_argument("--json", action="store_true")
    p_install.set_defaults(func=cmd_install)

    p_run = sub.add_parser("run")
    p_run.add_argument("agent_ref")
    p_run.add_argument("--input", default="")
    p_run.add_argument("--json", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_eval = sub.add_parser("eval")
    p_eval.add_argument("--manifest", required=True)
    p_eval.add_argument("--agent-id")
    p_eval.add_argument("--json", action="store_true")
    p_eval.set_defaults(func=cmd_eval)

    p_versions = sub.add_parser("versions")
    p_versions.add_argument("agent_id")
    p_versions.add_argument("--api-url")
    p_versions.add_argument("--local", action="store_true")
    p_versions.add_argument("--json", action="store_true")
    p_versions.set_defaults(func=cmd_versions)

    p_login = sub.add_parser("login")
    p_login.add_argument("--api-url", default=os.getenv("AGENTHUB_API_URL", "http://127.0.0.1:8000"))
    p_login.add_argument("--api-key", required=True)
    p_login.add_argument("--json", action="store_true")
    p_login.set_defaults(func=cmd_login)

    p_whoami = sub.add_parser("whoami")
    p_whoami.add_argument("--json", action="store_true")
    p_whoami.set_defaults(func=cmd_whoami)

    p_doctor = sub.add_parser("doctor")
    p_doctor.add_argument("--local", action="store_true")
    p_doctor.add_argument("--api-url")
    p_doctor.add_argument("--api-key")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
