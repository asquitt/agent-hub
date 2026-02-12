from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OPENAPI_PATH = ROOT / "specs" / "capability-search" / "openapi-capability-search-v0.1.yaml"


def load_openapi() -> dict:
    loaded = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_openapi_has_required_endpoints() -> None:
    spec = load_openapi()
    paths = spec["paths"]

    assert "/v1/capabilities/search" in paths
    assert "post" in paths["/v1/capabilities/search"]

    assert "/v1/capabilities/match" in paths
    assert "post" in paths["/v1/capabilities/match"]

    assert "/v1/agents/{id}/capabilities" in paths
    assert "get" in paths["/v1/agents/{id}/capabilities"]

    assert "/v1/capabilities/recommend" in paths
    assert "post" in paths["/v1/capabilities/recommend"]


def test_openapi_has_request_response_schemas() -> None:
    spec = load_openapi()
    schemas = spec["components"]["schemas"]

    for schema_name in [
        "SearchRequest",
        "SearchResponse",
        "MatchRequest",
        "MatchResponse",
        "RecommendRequest",
        "RecommendResponse",
        "AgentCapabilitiesResponse",
        "ConstraintFilters",
        "PaginationRequest",
        "ErrorResponse",
    ]:
        assert schema_name in schemas

    search_body_ref = (
        spec["paths"]["/v1/capabilities/search"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    )
    assert search_body_ref == "#/components/schemas/SearchRequest"

    recommend_response_ref = (
        spec["paths"]["/v1/capabilities/recommend"]["post"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["$ref"]
    )
    assert recommend_response_ref == "#/components/schemas/RecommendResponse"


def test_openapi_includes_rate_limit_and_pagination_design() -> None:
    spec = load_openapi()

    search_meta = spec["paths"]["/v1/capabilities/search"]["post"]["x-rate-limit-design"]
    assert "per_user_tiers" in search_meta
    assert "per_agent_tiers" in search_meta
    assert search_meta["per_user_tiers"]["anonymous_rpm"] == 60

    pagination = spec["components"]["schemas"]["PaginationRequest"]
    assert pagination["properties"]["mode"]["enum"] == ["cursor", "offset"]
    assert "allOf" in pagination


def test_openapi_supports_policy_first_constraints() -> None:
    spec = load_openapi()
    filters = spec["components"]["schemas"]["ConstraintFilters"]["properties"]

    for required_filter in [
        "max_latency_ms",
        "max_cost_usd",
        "min_trust_score",
        "required_permissions",
        "allowed_protocols",
        "compatibility_mode",
    ]:
        assert required_filter in filters
