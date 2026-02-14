"""S79: Sandbox foundation — profiles, storage, resource limits."""

from __future__ import annotations

import json
import os

os.environ.setdefault("AGENTHUB_API_KEYS_JSON", json.dumps({"test-key-001": "test-owner"}))
os.environ.setdefault("AGENTHUB_IDENTITY_SIGNING_SECRET", "test-signing-secret-s79")

from starlette.testclient import TestClient

from src.api.app import app
from src.runtime.storage import reset_for_tests

HEADERS = {"X-API-Key": "test-key-001"}

client = TestClient(app)
reset_for_tests()


# ---- Profile CRUD ----


def test_default_profiles_seeded():
    """Default profiles (micro/small/medium/large) are seeded on first access."""
    resp = client.get("/v1/runtime/profiles", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    names = {p["name"] for p in data["profiles"]}
    assert {"micro", "small", "medium", "large"} <= names
    assert data["total"] >= 4
    print("PASS: default profiles seeded")


def test_create_custom_profile():
    """Create a custom resource profile."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "custom-s79",
            "description": "Custom test profile",
            "cpu_cores": 1.5,
            "memory_mb": 2048,
            "timeout_seconds": 120,
            "network_mode": "egress_only",
            "disk_io_mb": 512,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["name"] == "custom-s79"
    assert data["resource_limits"]["cpu_cores"] == 1.5
    assert data["resource_limits"]["memory_mb"] == 2048
    assert data["resource_limits"]["network_mode"] == "egress_only"
    assert data["profile_id"].startswith("prof-")
    print("PASS: create custom profile")


def test_create_duplicate_profile_rejected():
    """Creating a profile with the same name fails."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "micro",
            "description": "duplicate",
            "cpu_cores": 0.5,
            "memory_mb": 256,
            "timeout_seconds": 30,
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 409, resp.text
    print("PASS: duplicate profile rejected")


def test_get_profile_by_id():
    """Fetch a profile by ID."""
    # Get the list first to find a profile_id
    resp = client.get("/v1/runtime/profiles", headers=HEADERS)
    profiles = resp.json()["profiles"]
    micro = next(p for p in profiles if p["name"] == "micro")

    resp = client.get(f"/v1/runtime/profiles/{micro['profile_id']}", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["name"] == "micro"
    assert data["resource_limits"]["cpu_cores"] == 0.25
    assert data["resource_limits"]["memory_mb"] == 256
    assert data["resource_limits"]["timeout_seconds"] == 30
    print("PASS: get profile by id")


def test_get_nonexistent_profile_404():
    """Fetching a nonexistent profile returns 404."""
    resp = client.get("/v1/runtime/profiles/prof-nonexistent", headers=HEADERS)
    assert resp.status_code == 404, resp.text
    print("PASS: nonexistent profile 404")


def test_delete_profile():
    """Delete a custom profile."""
    # Create one to delete
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "delete-me-s79",
            "description": "Will be deleted",
            "cpu_cores": 0.5,
            "memory_mb": 256,
            "timeout_seconds": 30,
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200, resp.text
    profile_id = resp.json()["profile_id"]

    resp = client.delete(f"/v1/runtime/profiles/{profile_id}", headers=HEADERS)
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] is True

    # Verify it's gone
    resp = client.get(f"/v1/runtime/profiles/{profile_id}", headers=HEADERS)
    assert resp.status_code == 404, resp.text
    print("PASS: delete profile")


def test_delete_nonexistent_profile_404():
    """Deleting a nonexistent profile returns 404."""
    resp = client.delete("/v1/runtime/profiles/prof-nonexistent", headers=HEADERS)
    assert resp.status_code == 404, resp.text
    print("PASS: delete nonexistent profile 404")


# ---- Resource limit validation ----


def test_invalid_network_mode_rejected():
    """Invalid network mode is rejected."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "bad-network-s79",
            "cpu_cores": 0.5,
            "memory_mb": 256,
            "timeout_seconds": 30,
            "network_mode": "invalid_mode",
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 400, resp.text
    print("PASS: invalid network mode rejected")


def test_cpu_exceeding_max_rejected():
    """CPU cores exceeding maximum are rejected by Pydantic validation."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "too-much-cpu-s79",
            "cpu_cores": 10.0,
            "memory_mb": 256,
            "timeout_seconds": 30,
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 422, resp.text
    print("PASS: excessive CPU rejected")


def test_memory_exceeding_max_rejected():
    """Memory exceeding maximum is rejected."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "too-much-mem-s79",
            "cpu_cores": 0.5,
            "memory_mb": 99999,
            "timeout_seconds": 30,
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 422, resp.text
    print("PASS: excessive memory rejected")


def test_timeout_exceeding_max_rejected():
    """Timeout exceeding maximum is rejected."""
    resp = client.post(
        "/v1/runtime/profiles",
        json={
            "name": "too-long-timeout-s79",
            "cpu_cores": 0.5,
            "memory_mb": 256,
            "timeout_seconds": 99999,
            "disk_io_mb": 100,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 422, resp.text
    print("PASS: excessive timeout rejected")


# ---- Storage layer direct ----


def test_storage_profile_list_returns_defaults():
    """Storage layer returns default profiles."""
    from src.runtime.storage import RUNTIME_STORAGE

    profiles = RUNTIME_STORAGE.list_profiles()
    names = {p["name"] for p in profiles}
    assert "micro" in names
    assert "large" in names
    print("PASS: storage layer returns defaults")


def test_storage_reset_clears_data():
    """reset_for_tests() clears all sandbox data."""
    from src.runtime.storage import RUNTIME_STORAGE

    reset_for_tests()
    # After reset, profiles are cleared but will be re-seeded on next access
    profiles = RUNTIME_STORAGE.list_profiles()
    # Should have default profiles (re-seeded)
    assert len(profiles) >= 4
    print("PASS: storage reset clears data")


# ---- Profile preset verification ----


def test_micro_profile_limits():
    """Micro profile has correct resource limits."""
    resp = client.get("/v1/runtime/profiles", headers=HEADERS)
    profiles = resp.json()["profiles"]
    micro = next(p for p in profiles if p["name"] == "micro")
    limits = micro["resource_limits"]
    assert limits["cpu_cores"] == 0.25
    assert limits["memory_mb"] == 256
    assert limits["timeout_seconds"] == 30
    assert limits["network_mode"] == "disabled"
    assert limits["disk_io_mb"] == 100
    print("PASS: micro profile limits correct")


def test_large_profile_limits():
    """Large profile has correct resource limits."""
    resp = client.get("/v1/runtime/profiles", headers=HEADERS)
    profiles = resp.json()["profiles"]
    large = next(p for p in profiles if p["name"] == "large")
    limits = large["resource_limits"]
    assert limits["cpu_cores"] == 2.0
    assert limits["memory_mb"] == 4096
    assert limits["timeout_seconds"] == 600
    assert limits["network_mode"] == "full"
    assert limits["disk_io_mb"] == 1024
    print("PASS: large profile limits correct")


def test_auth_required():
    """Endpoints require authentication."""
    resp = client.get("/v1/runtime/profiles")
    assert resp.status_code in (401, 403), resp.text
    print("PASS: auth required")


if __name__ == "__main__":
    test_default_profiles_seeded()
    test_create_custom_profile()
    test_create_duplicate_profile_rejected()
    test_get_profile_by_id()
    test_get_nonexistent_profile_404()
    test_delete_profile()
    test_delete_nonexistent_profile_404()
    test_invalid_network_mode_rejected()
    test_cpu_exceeding_max_rejected()
    test_memory_exceeding_max_rejected()
    test_timeout_exceeding_max_rejected()
    test_storage_profile_list_returns_defaults()
    test_storage_reset_clears_data()
    test_micro_profile_limits()
    test_large_profile_limits()
    test_auth_required()
    print("\nAll S79 tests passed!")
