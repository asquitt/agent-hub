from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_d03_required_artifacts_exist() -> None:
    assert (ROOT / "schema.sql").exists()
    assert (ROOT / "erd.md").exists()
    assert (ROOT / "cost-model.md").exists()
    assert (ROOT / "cost-model.csv").exists()
    assert (ROOT / "db" / "migrations" / "0001_initial_schema.sql").exists()
    assert (ROOT / "db" / "migrations" / "0002_retention_indexes.sql").exists()


def test_schema_includes_core_entities_and_pgvector_index_design() -> None:
    schema = _read(ROOT / "schema.sql")

    required_tables = [
        "users",
        "organizations",
        "namespaces",
        "agents",
        "agent_versions",
        "capability_catalog",
        "eval_runs",
        "reputation_scores",
        "delegation_records",
        "billing_events",
    ]

    for table in required_tables:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in schema

    assert "CREATE EXTENSION IF NOT EXISTS vector;" in schema
    assert "embedding VECTOR(1536)" in schema
    assert "USING hnsw (embedding vector_cosine_ops)" in schema


def test_erd_contains_mermaid_and_retention_policy() -> None:
    erd = _read(ROOT / "erd.md")
    assert "```mermaid" in erd
    assert "Data Retention and Archival Policies" in erd
    assert "api_events" in erd
    assert "delegation_records" in erd


def test_cost_model_projects_year0_to_year3() -> None:
    model = _read(ROOT / "cost-model.md")
    assert "Year 0" in model or "| 0 |" in model
    assert "| 3 |" in model

    rows = list(csv.DictReader((ROOT / "cost-model.csv").read_text(encoding="utf-8").splitlines()))
    years = {row["year"] for row in rows}
    assert years == {"0", "1", "2", "3"}
    y0 = next(row for row in rows if row["year"] == "0")
    y3 = next(row for row in rows if row["year"] == "3")
    assert float(y0["monthly_min_usd"]) == 0
    assert float(y3["monthly_max_usd"]) >= 5000


def test_d04_required_artifacts_exist() -> None:
    assert (ROOT / "architecture.md").exists()
    assert (ROOT / "security-design.md").exists()
    assert (ROOT / "infra" / "terraform" / "main.tf").exists()
    assert (ROOT / "infra" / "terraform" / "variables.tf").exists()
    assert (ROOT / "infra" / "terraform" / "outputs.tf").exists()
    assert (ROOT / "infra" / "terraform" / "versions.tf").exists()


def test_architecture_includes_c4_dr_and_cost_dashboard_design() -> None:
    architecture = _read(ROOT / "architecture.md")
    assert "C4 - Context Level" in architecture
    assert "C4 - Container Level" in architecture
    assert "C4 - Component Level" in architecture
    assert "RTO target: `< 4 hours`" in architecture
    assert "RPO target: `< 1 hour`" in architecture
    assert "Cost Monitoring Dashboard Design" in architecture


def test_security_design_covers_api_keys_ratelimits_and_rbac() -> None:
    security = _read(ROOT / "security-design.md")
    assert "API Key Management" in security
    assert "Rate Limiting" in security
    assert "RBAC Model" in security


def test_terraform_templates_cover_core_infra_components() -> None:
    main_tf = _read(ROOT / "infra" / "terraform" / "main.tf")
    assert "resource \"aws_vpc\"" in main_tf
    assert "resource \"aws_db_instance\"" in main_tf
    assert "resource \"aws_s3_bucket\"" in main_tf
    assert "resource \"aws_cloudwatch_dashboard\"" in main_tf
