from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from src.api.auth import AuthContext
from src.identity import storage as identity_storage
from src.identity.capability_tokens import (
    issue_capability_token,
    revoke_capability_token,
    verify_capability_token,
)
from src.identity.did import (
    create_did,
    deactivate_did,
    issue_verifiable_credential,
    resolve_did,
    revoke_verifiable_credential,
    verify_verifiable_credential,
)
from src.identity.revocation import revoke_agent
from src.identity.authority_fence import authority_fence


AUDIENCE = "agenthub://s165-persistence"
RESOURCE = "urn:agenthub:s165:persistence"


@pytest.fixture()
def authority_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    db_path = tmp_path / "identity-authority.db"
    monkeypatch.setenv("AGENTHUB_IDENTITY_DB_PATH", str(db_path))
    monkeypatch.setenv("AGENTHUB_IDENTITY_SIGNING_SECRET", "s165-persistence-secret")
    monkeypatch.setenv("AGENTHUB_SPIFFE_TRUST_DOMAIN", "persistence.agenthub.test")
    identity_storage.reset_for_tests(db_path=db_path)
    yield db_path
    identity_storage.reset_for_tests(db_path=db_path)


def _actor() -> AuthContext:
    return AuthContext(
        "owner-s165",
        scopes=("*",),
        roles=("admin",),
        tenant_id="tenant-s165",
        auth_method="api_key",
    )


def _register_agents(actor: AuthContext, *agent_ids: str) -> None:
    for agent_id in agent_ids:
        identity_storage.register_agent_identity_for_actor(
            actor=actor,
            agent_id=agent_id,
            credential_type="api_key",
        )


def _issue_capability(
    actor: AuthContext,
    issuer_agent_id: str,
    subject_agent_id: str,
) -> dict[str, Any]:
    return issue_capability_token(
        actor=actor,
        issuer_agent_id=issuer_agent_id,
        subject_agent_id=subject_agent_id,
        scopes=["authority.read"],
        audience=AUDIENCE,
        resource=RESOURCE,
        ttl_seconds=3600,
    )


def _verify_capability(actor: AuthContext, token: dict[str, Any]) -> dict[str, Any]:
    return verify_capability_token(
        token,
        actor=actor,
        source_ip="127.0.0.1",
        audience=AUDIENCE,
        resource=RESOURCE,
        required_scope="authority.read",
    )


def _issue_vc(
    actor: AuthContext,
    issuer_agent_id: str,
    subject_agent_id: str,
) -> tuple[dict[str, Any], str, str]:
    issuer_did = str(create_did(agent_id=issuer_agent_id, actor=actor)["id"])
    subject_did = str(create_did(agent_id=subject_agent_id, actor=actor)["id"])
    credential = issue_verifiable_credential(
        actor=actor,
        issuer_did=issuer_did,
        subject_did=subject_did,
        claims={"authority": "read"},
        ttl_seconds=3600,
    )
    return credential, issuer_did, subject_did


def test_capability_did_and_vc_records_survive_reconfigure(
    authority_runtime: Path,
) -> None:
    actor = _actor()
    _register_agents(actor, "persist-issuer", "persist-subject")
    token = _issue_capability(actor, "persist-issuer", "persist-subject")
    credential, issuer_did, subject_did = _issue_vc(
        actor,
        "persist-issuer",
        "persist-subject",
    )

    assert _verify_capability(actor, token)["valid"] is True
    assert (
        verify_verifiable_credential(str(credential["vc_id"]), actor=actor)["valid"]
        is True
    )

    identity_storage.reconfigure(db_path=authority_runtime)
    reloaded_actor = _actor()

    assert _verify_capability(reloaded_actor, token)["valid"] is True
    assert (
        resolve_did(issuer_did, actor=reloaded_actor)["didDocument"]["id"] == issuer_did
    )
    assert (
        resolve_did(subject_did, actor=reloaded_actor)["didDocument"]["id"]
        == subject_did
    )
    assert (
        verify_verifiable_credential(str(credential["vc_id"]), actor=reloaded_actor)[
            "valid"
        ]
        is True
    )


def test_explicit_capability_and_vc_revocation_survive_reconfigure(
    authority_runtime: Path,
) -> None:
    actor = _actor()
    _register_agents(actor, "revoked-issuer", "revoked-subject")
    token = _issue_capability(actor, "revoked-issuer", "revoked-subject")
    credential, _, _ = _issue_vc(actor, "revoked-issuer", "revoked-subject")

    revoked_token = revoke_capability_token(
        str(token["token_id"]),
        actor=actor,
        reason="persistence-test",
    )
    revoked_vc = revoke_verifiable_credential(
        str(credential["vc_id"]),
        actor=actor,
        reason="persistence-test",
    )
    assert revoked_token["revoked"] is True
    assert revoked_vc["revoked"] is True

    identity_storage.reconfigure(db_path=authority_runtime)

    token_result = _verify_capability(actor, token)
    vc_result = verify_verifiable_credential(str(credential["vc_id"]), actor=actor)
    assert token_result["valid"] is False
    assert "revoked" in str(token_result["reason"]).lower()
    assert vc_result["valid"] is False
    assert vc_result["revoked"] is True
    assert "revoked" in vc_result["reasons"]


def test_did_deactivation_is_resolvable_and_terminal_after_reconfigure(
    authority_runtime: Path,
) -> None:
    actor = _actor()
    _register_agents(actor, "terminal-did-agent")
    did_document = create_did(agent_id="terminal-did-agent", actor=actor)
    did = str(did_document["id"])

    deactivated = deactivate_did(did, actor=actor, reason="retired")
    assert deactivated["deactivated"] is True

    identity_storage.reconfigure(db_path=authority_runtime)

    resolution = resolve_did(did, actor=actor)
    assert resolution["didDocument"]["id"] == did
    assert resolution["didResolutionMetadata"]["deactivated"] is True
    with pytest.raises(
        ValueError, match="(permanently deactivated|cannot be recreated)"
    ):
        create_did(agent_id="terminal-did-agent", actor=actor)


@pytest.mark.parametrize("changed_agent", ["generation-issuer", "generation-subject"])
def test_suspension_and_reactivation_do_not_revive_old_authority(
    authority_runtime: Path,
    changed_agent: str,
) -> None:
    actor = _actor()
    _register_agents(actor, "generation-issuer", "generation-subject")
    token = _issue_capability(actor, "generation-issuer", "generation-subject")
    credential, _, _ = _issue_vc(actor, "generation-issuer", "generation-subject")
    vc_id = str(credential["vc_id"])

    assert _verify_capability(actor, token)["valid"] is True
    assert verify_verifiable_credential(vc_id, actor=actor)["valid"] is True

    identity_storage.update_agent_identity_status_for_actor(
        changed_agent, "suspended", actor
    )
    assert _verify_capability(actor, token)["valid"] is False
    assert verify_verifiable_credential(vc_id, actor=actor)["valid"] is False

    identity_storage.update_agent_identity_status_for_actor(
        changed_agent, "active", actor
    )
    identity_storage.reconfigure(db_path=authority_runtime)

    token_result = _verify_capability(actor, token)
    vc_result = verify_verifiable_credential(vc_id, actor=actor)
    assert token_result["valid"] is False
    assert "generation" in str(token_result["reason"]).lower()
    assert vc_result["valid"] is False
    generation_key = (
        "issuer_identity_generation_current"
        if changed_agent == "generation-issuer"
        else "subject_identity_generation_current"
    )
    assert vc_result[generation_key] is False
    assert any("generation changed" in reason for reason in vc_result["reasons"])

    replacement, _, _ = _issue_vc(actor, "generation-issuer", "generation-subject")
    assert (
        verify_verifiable_credential(str(replacement["vc_id"]), actor=actor)["valid"]
        is True
    )


def test_configuration_checksum_change_rotates_generation_and_invalidates_old_authority(
    authority_runtime: Path,
) -> None:
    actor = _actor()
    _register_agents(actor, "checksum-issuer", "checksum-subject")
    token = _issue_capability(actor, "checksum-issuer", "checksum-subject")
    credential, _, _ = _issue_vc(actor, "checksum-issuer", "checksum-subject")
    vc_id = str(credential["vc_id"])
    _, generation_before, _ = identity_storage.get_agent_identity_auth_snapshot(
        "checksum-issuer"
    )

    identity_storage.set_configuration_checksum_for_actor(
        "checksum-issuer",
        "sha256:changed-agent-configuration",
        actor,
    )
    _, generation_after, _ = identity_storage.get_agent_identity_auth_snapshot(
        "checksum-issuer"
    )
    identity_storage.set_configuration_checksum_for_actor(
        "checksum-issuer",
        "sha256:changed-agent-configuration",
        actor,
    )
    _, generation_after_idempotent_write, _ = (
        identity_storage.get_agent_identity_auth_snapshot("checksum-issuer")
    )
    identity_storage.reconfigure(db_path=authority_runtime)

    assert generation_before is not None
    assert generation_after is not None
    assert generation_after != generation_before
    assert generation_after_idempotent_write == generation_after
    token_result = _verify_capability(actor, token)
    vc_result = verify_verifiable_credential(vc_id, actor=actor)
    assert token_result["valid"] is False
    assert "generation" in str(token_result["reason"]).lower()
    assert vc_result["valid"] is False
    assert vc_result["issuer_identity_generation_current"] is False


def test_configuration_checksum_mutation_waits_for_authority_fence(
    authority_runtime: Path,
) -> None:
    del authority_runtime
    actor = _actor()
    _register_agents(actor, "checksum-fenced")
    started = threading.Event()
    finished = threading.Event()

    def mutate() -> None:
        started.set()
        identity_storage.set_configuration_checksum_for_actor(
            "checksum-fenced", "sha256:new-configuration", actor
        )
        finished.set()

    worker = threading.Thread(target=mutate)
    with authority_fence():
        worker.start()
        assert started.wait(timeout=1)
        time.sleep(0.05)
        assert finished.is_set() is False
    worker.join(timeout=1)
    assert finished.is_set() is True


def test_legacy_version_one_capability_token_fails_closed(
    authority_runtime: Path,
) -> None:
    del authority_runtime
    result = _verify_capability(
        _actor(),
        {
            "token_id": "cap-legacy-v1",
            "version": 1,
            "authority": {},
            "blocks": [],
            "signatures": [],
        },
    )

    assert result["valid"] is False
    assert result["reason"] == "unsupported capability token version"


def test_agent_revocation_cascades_to_capability_and_vc_authority(
    authority_runtime: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del authority_runtime
    actor = _actor()
    _register_agents(actor, "cascade-issuer", "cascade-subject")
    token = _issue_capability(actor, "cascade-issuer", "cascade-subject")
    credential, _, _ = _issue_vc(actor, "cascade-issuer", "cascade-subject")
    monkeypatch.setattr("src.lease.service.revoke_leases_for_agent", lambda *_args: 0)

    result = revoke_agent(agent_id="cascade-issuer", actor=actor, reason="incident")

    assert result["revoked_capability_tokens"] == 1
    assert result["revoked_verifiable_credentials"] == 1
    assert _verify_capability(actor, token)["valid"] is False
    assert (
        verify_verifiable_credential(str(credential["vc_id"]), actor=actor)["valid"]
        is False
    )


def test_reset_for_tests_clears_authority_tables_in_fk_safe_order(
    authority_runtime: Path,
) -> None:
    actor = _actor()
    _register_agents(actor, "reset-issuer", "reset-subject")
    token = _issue_capability(actor, "reset-issuer", "reset-subject")
    credential, issuer_did, subject_did = _issue_vc(
        actor, "reset-issuer", "reset-subject"
    )
    assert token["token_id"]
    assert credential["vc_id"]
    assert issuer_did != subject_did

    identity_storage.reset_for_tests(db_path=authority_runtime)

    with sqlite3.connect(authority_runtime) as connection:
        counts = {
            table: int(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
            for table in (
                "verifiable_credentials",
                "capability_token_roots",
                "agent_dids",
                "agent_identities",
            )
        }
    assert counts == {
        "verifiable_credentials": 0,
        "capability_token_roots": 0,
        "agent_dids": 0,
        "agent_identities": 0,
    }
