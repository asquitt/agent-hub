from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _requirement_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _normalized(requirement: str) -> str:
    return requirement.replace(" ", "").lower()


@pytest.fixture(scope="module")
def built_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    workspace = tmp_path_factory.mktemp("agenthub-wheel-source")
    source = workspace / "source"
    source.mkdir()

    for filename in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / filename, source / filename)
    for dirname in ("agenthub", "src", "sdk", "tools", "db", "specs"):
        shutil.copytree(ROOT / dirname, source / dirname)

    wheel_dir = workspace / "wheelhouse"
    wheel_dir.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheel_dir),
            str(source),
        ],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(wheel_dir.glob("agenthub-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_runtime_requirements_match_package_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    metadata_dependencies = {_normalized(item) for item in project["dependencies"]}
    runtime_dependencies = {
        _normalized(item) for item in _requirement_lines(ROOT / "requirements-runtime.txt")
    }

    assert runtime_dependencies == metadata_dependencies
    assert any(item.startswith("python-multipart==") for item in runtime_dependencies)
    assert all("pytest" not in item for item in runtime_dependencies)


def test_test_dependencies_are_separate_from_production() -> None:
    development = _requirement_lines(ROOT / "requirements.txt")

    assert "-r requirements-runtime.txt" in development
    assert any(_normalized(item).startswith("pytest==") for item in development)


def test_wheel_contains_service_cli_sdk_tools_and_runtime_assets(built_wheel: Path) -> None:
    with zipfile.ZipFile(built_wheel) as archive:
        members = set(archive.namelist())

    required_members = {
        "agenthub/cli.py",
        "src/api/main.py",
        "sdk/identity/client.py",
        "tools/capability_search/mock_engine.py",
    }
    for pattern in (
        "src/ui/*.html",
        "db/migrations/**/*.sql",
        "specs/**/*.json",
        "specs/**/*.yaml",
        "tools/capability_search/*.json",
        "tools/discovery/*.json",
    ):
        required_members.update(path.relative_to(ROOT).as_posix() for path in ROOT.glob(pattern))
    assert required_members <= members


def test_wheel_imports_from_an_isolated_path(built_wheel: Path, tmp_path: Path) -> None:
    extracted = tmp_path / "installed"
    extracted.mkdir()
    with zipfile.ZipFile(built_wheel) as archive:
        archive.extractall(extracted)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(extracted)
    probe = """
import agenthub.cli
import sdk.identity
import src.api.main
import tools.capability_search.mock_engine
from src.api.main import app

assert app.title == "AgentHub Registry Service"
for module in (agenthub.cli, sdk.identity, src.api.main, tools.capability_search.mock_engine):
    assert module.__file__.startswith(%r), module.__file__
""" % str(extracted)
    subprocess.run(
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
