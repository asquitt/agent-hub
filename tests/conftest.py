from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.idempotency import storage as idempotency_storage


@pytest.fixture(autouse=True)
def isolate_idempotency_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "idempotency.db"
    monkeypatch.setenv("AGENTHUB_IDEMPOTENCY_DB_PATH", str(db_path))
    idempotency_storage.reset_for_tests(db_path=db_path)
