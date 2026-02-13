from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.api.access_policy import route_policy_map
from src.api.app import app


ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = ROOT / "src"


def test_route_policy_map_snapshot_stable() -> None:
    rows = route_policy_map(app.routes)
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert len(rows) == 88
    assert digest == "9e15cc17ffcd2fde102676fb90cf47a06743f9748ab6b33152cc02570de404a5"


def test_route_policy_map_has_no_unclassified_v1_routes() -> None:
    rows = route_policy_map(app.routes)
    classifications = {row["classification"] for row in rows if row["path"].startswith("/v1/")}
    assert classifications.issubset({"public", "authenticated", "tenant_scoped", "admin_scoped"})
    assert "tenant_scoped" in classifications
    assert "authenticated" in classifications


def test_domain_modules_do_not_import_tooling_or_api_layer_directly() -> None:
    python_files = sorted(path for path in SRC_ROOT.rglob("*.py") if "__pycache__" not in str(path))
    violations: list[str] = []
    for path in python_files:
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("src/api/"):
            continue
        source = path.read_text(encoding="utf-8")
        if "from tools." in source or "import tools." in source:
            violations.append(f"{rel}: imports tools package")
        if "from src.api" in source or "import src.api" in source:
            violations.append(f"{rel}: imports src.api package directly")
    assert violations == []
