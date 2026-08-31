from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, is_dataclass
import hashlib
from typing import Any, NoReturn, Protocol, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from src.common.time import utc_now_iso
from src.identity.authority_fence import authority_fence
from src.identity.capability_tokens import (
    get_capability_token,
    verify_capability_token,
)
from src.identity.storage import ResourceAuthContext, require_resource_actor
from src.policy.mcp_relay import evaluate_mcp_relay_policy
from src.relay.receipts import canonical_json_bytes, sign_receipt
from src.relay.storage import (
    RELAY_STORAGE,
    RelayBudgetError,
    RelayConflictError,
    RelayStorage,
)

RELAY_AUDIENCE = "agenthub://mcp-relay"


class RelayPrincipal(ResourceAuthContext, Protocol):
    @property
    def auth_method(self) -> str: ...

    @property
    def roles(self) -> frozenset[str]: ...

    def allows_scope(self, required_scope: str) -> bool: ...


class RelayTransport(Protocol):
    async def inspect(self, target: dict[str, Any]) -> dict[str, Any]: ...

    async def call(
        self,
        target: dict[str, Any],
        *,
        arguments: dict[str, Any],
        before_dispatch: Callable[[], None],
        expected_schema_digest: str,
    ) -> dict[str, Any]: ...


class RelayServiceError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        record: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.record = record


class RelayCrashAfterRemoteResult(BaseException):
    """Test harness crash point; production callers never raise this intentionally."""


def relay_resource(target_id: str, tool_name: str) -> str:
    return f"urn:agenthub:mcp-relay:{target_id}:{tool_name}"


def relay_scope(tool_name: str) -> str:
    return f"mcp.tools.{tool_name}.invoke"


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return cast(dict[str, Any], asdict(value))
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="json", by_alias=True)
        if isinstance(dumped, dict):
            return dict(dumped)
    raise TypeError("relay component returned a non-object value")


def _principal(value: object) -> RelayPrincipal:
    context = require_resource_actor(value)
    if not hasattr(context, "auth_method") or not hasattr(context, "allows_scope"):
        raise PermissionError("relay requires a complete revocation-aware auth context")
    return cast(RelayPrincipal, context)


class RelayService:
    def __init__(
        self,
        *,
        transport: RelayTransport,
        config_loader: Callable[[str], object],
        storage: RelayStorage = RELAY_STORAGE,
        after_remote_result: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._transport = transport
        self._config_loader = config_loader
        self._storage = storage
        self._after_remote_result = after_remote_result

    async def import_target(self, target_id: str, *, actor: object) -> dict[str, Any]:
        context = _principal(actor)
        if "admin" not in context.roles:
            raise RelayServiceError(
                "relay.admin_required", "admin role required", status_code=403
            )
        configured = _mapping(self._config_loader(target_id))
        if configured["tenant_id"] != context.tenant_id:
            raise RelayServiceError(
                "relay.target_not_found", "relay target not found", status_code=404
            )
        if configured.get("operator_attests_read_only") is not True:
            raise RelayServiceError(
                "relay.operator_attestation_required",
                "operator must attest that the exact target tool is read-only",
                status_code=409,
            )
        try:
            inspected = _mapping(await self._transport.inspect(configured))
        except Exception as exc:
            if bool(getattr(exc, "definite_failure", False)):
                raise RelayServiceError(
                    str(getattr(exc, "code", "relay.upstream_pre_dispatch_failed")),
                    "configured upstream MCP tool listing was rejected",
                    status_code=502,
                ) from exc
            raise RelayServiceError(
                "relay.upstream_unavailable",
                "configured upstream MCP server could not be inspected",
                status_code=502,
            ) from exc
        try:
            tool = _mapping(inspected["tool"])
            annotations = _mapping(tool["annotations"])
            input_schema = _mapping(tool.get("input_schema"))
            output_schema = _mapping(tool.get("output_schema"))
        except (KeyError, TypeError) as exc:
            raise RelayServiceError(
                "relay.tool_contract_invalid",
                "upstream tool contract is incomplete or malformed",
                status_code=409,
            ) from exc
        expected_safety = {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        }
        if any(
            annotations.get(key) is not value for key, value in expected_safety.items()
        ):
            raise RelayServiceError(
                "relay.tool_safety_denied",
                "upstream tool lacks the required read-only idempotent declaration",
                status_code=409,
            )
        try:
            Draft202012Validator.check_schema(input_schema)
            Draft202012Validator.check_schema(output_schema)
        except SchemaError as exc:
            raise RelayServiceError(
                "relay.schema_invalid",
                "upstream tool schema is invalid",
                status_code=409,
            ) from exc
        if tool.get("name") != configured["tool_name"]:
            raise RelayServiceError(
                "relay.tool_not_found",
                "configured upstream tool was not listed",
                status_code=409,
            )

        schema_digest = str(tool.get("schema_digest", "")) or _digest(
            {"input_schema": input_schema, "output_schema": output_schema}
        )
        policy_revision = _digest(
            {
                "version": "mcp-relay-policy-v1",
                "target_id": configured["target_id"],
                "tenant_id": configured["tenant_id"],
                "endpoint_digest": configured["endpoint_digest"],
                "tool_name": configured["tool_name"],
                "schema_digest": schema_digest,
                "max_call_cost_usd": configured["max_call_cost_usd"],
                "operator_attests_read_only": True,
                "safety": expected_safety,
            }
        )
        with authority_fence():
            if _mapping(self._config_loader(target_id)) != configured:
                raise RelayServiceError(
                    "relay.config_drift",
                    "operator relay configuration changed during import",
                    status_code=409,
                )
            return self._storage.upsert_target(
                {
                    **configured,
                    "server_name": str(inspected.get("server_name", "")),
                    "server_version": str(inspected.get("server_version", "")),
                    "protocol_version": str(inspected.get("protocol_version", "")),
                    "input_schema": input_schema,
                    "output_schema": output_schema,
                    "schema_digest": schema_digest,
                    "annotations": annotations,
                    "policy_revision": policy_revision,
                }
            )

    def set_budget(
        self,
        *,
        capability_token_id: str,
        max_budget_usd: float,
        actor: object,
    ) -> dict[str, Any]:
        context = _principal(actor)
        if "admin" not in context.roles:
            raise RelayServiceError(
                "relay.admin_required", "admin role required", status_code=403
            )
        with authority_fence():
            get_capability_token(capability_token_id, actor=context)
            return self._storage.set_budget(
                owner=context.owner,
                tenant_id=context.tenant_id,
                capability_token_id=capability_token_id,
                max_budget_usd=max_budget_usd,
            )

    def set_target_enabled(
        self, target_id: str, *, enabled: bool, actor: object
    ) -> dict[str, Any]:
        context = _principal(actor)
        if "admin" not in context.roles:
            raise RelayServiceError(
                "relay.admin_required", "admin role required", status_code=403
            )
        with authority_fence():
            configured = _mapping(self._config_loader(target_id))
            if configured["tenant_id"] != context.tenant_id:
                raise RelayServiceError(
                    "relay.target_not_found", "relay target not found", status_code=404
                )
            return self._storage.set_target_enabled(target_id, enabled)

    async def invoke(
        self,
        *,
        target_id: str,
        capability_token: dict[str, Any],
        arguments: dict[str, Any],
        idempotency_key: str,
        source_ip: str | None,
        reauthenticate: Callable[[], object],
    ) -> dict[str, Any]:
        configured = _mapping(self._config_loader(target_id))
        try:
            target = self._storage.get_target(target_id)
        except KeyError as exc:
            raise RelayServiceError(
                "relay.target_not_imported",
                "relay target is not imported",
                status_code=404,
            ) from exc

        try:
            context = _principal(reauthenticate())
        except Exception as exc:
            raise RelayServiceError(
                "relay.authentication_failed",
                "relay authentication failed",
                status_code=int(getattr(exc, "status_code", 401)),
            ) from exc
        if context.agent_id is None:
            raise RelayServiceError(
                "relay.agent_required",
                "relay calls require an agent-bound principal",
                status_code=403,
            )
        token_id = str(capability_token.get("token_id", "")).strip()
        if not token_id:
            raise RelayServiceError(
                "relay.capability_required",
                "capability token is required",
                status_code=403,
            )
        input_hash = _digest(arguments)
        request_hash = _digest(
            {
                "target_id": target_id,
                "capability_token_id": token_id,
                "arguments": arguments,
            }
        )
        try:
            invocation, created = self._storage.reserve_invocation(
                owner=context.owner,
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                target_id=target_id,
                capability_token_id=token_id,
                input_hash=input_hash,
            )
        except RelayConflictError as exc:
            raise RelayServiceError(
                "relay.idempotency_conflict", str(exc), status_code=409
            ) from exc
        if not created:
            if invocation["agent_id"] != context.agent_id:
                raise RelayServiceError(
                    "relay.idempotency_conflict",
                    "idempotency key belongs to a different agent principal",
                    status_code=409,
                )
            if invocation["status"] in {"pending", "indeterminate"}:
                raise RelayServiceError(
                    "relay.replay_blocked",
                    "relay invocation may have reached the upstream and cannot be replayed",
                    status_code=409,
                    record=invocation,
                )
            return {**invocation, "idempotent_replay": True}

        required_scope = relay_scope(str(target["tool_name"]))
        resource = relay_resource(target_id, str(target["tool_name"]))
        try:
            Draft202012Validator(target["input_schema"]).validate(arguments)
        except (SchemaError, ValidationError) as exc:
            return self._reject_before_dispatch(
                invocation=invocation,
                target=target,
                capability={"token_id": token_id},
                code="relay.input_schema_denied",
                message="tool arguments do not match the imported schema",
                status_code=422,
                cause=exc,
            )

        try:
            capability = verify_capability_token(
                capability_token,
                actor=context,
                source_ip=source_ip,
                audience=RELAY_AUDIENCE,
                resource=resource,
                required_scope=required_scope,
            )
        except Exception as exc:
            return self._reject_before_dispatch(
                invocation=invocation,
                target=target,
                capability={"token_id": token_id},
                code="relay.capability_denied",
                message="relay capability verification failed",
                status_code=403,
                cause=exc,
            )
        policy = evaluate_mcp_relay_policy(
            actor=context,
            target=target,
            configured_target=configured,
            capability=capability,
            required_scope=required_scope,
        )
        if not policy["allowed"]:
            return self._reject_before_dispatch(
                invocation=invocation,
                target=target,
                capability=capability,
                code="relay.policy_denied",
                message="relay policy denied the call",
                status_code=403,
                policy=policy,
            )
        budget: dict[str, Any] | None = None

        def refreshed_authority() -> tuple[
            dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
        ]:
            try:
                refreshed_context = _principal(reauthenticate())
            except Exception as exc:
                self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=capability,
                    code="relay.authority_revoked",
                    message="relay authority changed before remote dispatch",
                    status_code=403,
                    policy=policy,
                    budget=budget,
                    cause=exc,
                )
            if (
                refreshed_context.owner != context.owner
                or refreshed_context.tenant_id != context.tenant_id
                or refreshed_context.agent_id != context.agent_id
                or refreshed_context.auth_method != context.auth_method
            ):
                self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=capability,
                    code="relay.principal_changed",
                    message="authenticated principal changed before remote dispatch",
                    status_code=403,
                    policy=policy,
                    budget=budget,
                )
            try:
                refreshed_capability = verify_capability_token(
                    capability_token,
                    actor=refreshed_context,
                    source_ip=source_ip,
                    audience=RELAY_AUDIENCE,
                    resource=resource,
                    required_scope=required_scope,
                )
                refreshed_target = self._storage.get_target(target_id)
                refreshed_config = _mapping(self._config_loader(target_id))
                refreshed_policy = evaluate_mcp_relay_policy(
                    actor=refreshed_context,
                    target=refreshed_target,
                    configured_target=refreshed_config,
                    capability=refreshed_capability,
                    required_scope=required_scope,
                )
            except Exception as exc:
                self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=capability,
                    code="relay.authority_revoked",
                    message="relay authority changed before remote dispatch",
                    status_code=403,
                    policy=policy,
                    budget=budget,
                    cause=exc,
                )
            if not refreshed_policy["allowed"]:
                self._reject_before_dispatch(
                    invocation=invocation,
                    target=refreshed_target,
                    capability=refreshed_capability,
                    code="relay.authority_revoked",
                    message="relay authority changed before remote dispatch",
                    status_code=403,
                    policy=refreshed_policy,
                    budget=budget,
                )
            return (
                refreshed_capability,
                refreshed_target,
                refreshed_config,
                refreshed_policy,
            )

        with authority_fence():
            final_capability, final_target, _, final_policy = (
                refreshed_authority()
            )
            try:
                budget = self._storage.reserve_budget(
                    invocation_id=invocation["invocation_id"],
                    policy=final_policy,
                    cost_usd=float(target["max_call_cost_usd"]),
                )
            except RelayBudgetError as exc:
                return self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=final_capability,
                    code=exc.code,
                    message=str(exc),
                    status_code=409,
                    policy=final_policy,
                    budget=exc.budget,
                    cause=exc,
                )
            target = final_target
            capability = final_capability
            policy = final_policy

        assert budget is not None
        transport_target = {**configured, **target}
        dispatch_admitted = False

        def before_dispatch() -> None:
            nonlocal invocation, target, capability, policy, dispatch_admitted
            with authority_fence():
                (
                    dispatch_capability,
                    dispatch_target,
                    dispatch_configured,
                    dispatch_policy,
                ) = refreshed_authority()
                if (
                    dispatch_target != target
                    or dispatch_configured != configured
                ):
                    self._reject_before_dispatch(
                        invocation=invocation,
                        target=dispatch_target,
                        capability=dispatch_capability,
                        code="relay.authority_revoked",
                        message="relay authority changed before remote dispatch",
                        status_code=403,
                        policy=dispatch_policy,
                        budget=budget,
                    )
                invocation = self._storage.mark_network_started(
                    str(invocation["invocation_id"]),
                    target_snapshot=dispatch_target,
                )
                target = dispatch_target
                capability = dispatch_capability
                policy = dispatch_policy
                dispatch_admitted = True

        try:
            raw_result = await self._transport.call(
                transport_target,
                arguments=arguments,
                before_dispatch=before_dispatch,
                expected_schema_digest=str(target["schema_digest"]),
            )
            if not dispatch_admitted:
                return self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=capability,
                    code="relay.transport_dispatch_not_admitted",
                    message="relay transport returned without dispatch admission",
                    status_code=502,
                    policy=policy,
                    budget=budget,
                )
            result = _mapping(raw_result)
            if self._after_remote_result is not None:
                self._after_remote_result(result)
        except RelayCrashAfterRemoteResult:
            raise
        except RelayServiceError:
            raise
        except Exception as exc:
            definite = bool(getattr(exc, "definite_failure", False))
            if not dispatch_admitted:
                return self._reject_before_dispatch(
                    invocation=invocation,
                    target=target,
                    capability=capability,
                    code=(
                        str(getattr(exc, "code", "relay.upstream_pre_dispatch_failed"))
                        if definite
                        else "relay.upstream_pre_dispatch_failed"
                    ),
                    message="upstream discovery failed before remote dispatch",
                    status_code=502,
                    policy=policy,
                    budget=budget,
                    cause=exc,
                )
            return self._finalize_remote(
                invocation=invocation,
                target=target,
                capability=capability,
                policy=policy,
                budget=budget,
                status="failed" if definite else "indeterminate",
                result=None,
                output_hash=None,
                error_code=(
                    str(getattr(exc, "code", "relay.upstream_failed"))
                    if definite
                    else "relay.upstream_indeterminate"
                ),
                error_message=(
                    "upstream rejected the imported tool snapshot"
                    if definite
                    else "upstream completion could not be proven"
                ),
                remote_result_observed=False,
                charge_reserved=not definite,
                raise_status=409 if definite else 502,
                cause=exc,
            )

        observed_schema_digest = str(result.get("schema_digest", ""))
        if observed_schema_digest != target["schema_digest"]:
            return self._finalize_remote(
                invocation=invocation,
                target=target,
                capability=capability,
                policy=policy,
                budget=budget,
                status="failed",
                result=None,
                output_hash=None,
                error_code="relay.schema_drift",
                error_message="upstream tool schema changed after import",
                remote_result_observed=True,
                charge_reserved=False,
                raise_status=409,
            )
        if bool(result.get("is_error")):
            return self._finalize_remote(
                invocation=invocation,
                target=target,
                capability=capability,
                policy=policy,
                budget=budget,
                status="failed",
                result=None,
                output_hash=_digest(result),
                error_code="relay.upstream_tool_error",
                error_message="upstream returned a definite MCP tool error",
                remote_result_observed=True,
                charge_reserved=True,
                raise_status=502,
            )
        structured = result.get("structured_content")
        try:
            canonical = canonical_json_bytes(structured)
            if len(canonical) > 65_536:
                raise ValueError("structured output exceeds 65536 bytes")
            Draft202012Validator(target["output_schema"]).validate(structured)
        except (SchemaError, ValidationError, ValueError) as exc:
            return self._finalize_remote(
                invocation=invocation,
                target=target,
                capability=capability,
                policy=policy,
                budget=budget,
                status="failed",
                result=None,
                output_hash=_digest(result),
                error_code="relay.output_schema_denied",
                error_message="upstream output failed strict validation",
                remote_result_observed=True,
                charge_reserved=True,
                raise_status=502,
                cause=exc,
            )
        return self._finalize_remote(
            invocation=invocation,
            target=target,
            capability=capability,
            policy=policy,
            budget=budget,
            status="succeeded",
            result=cast(dict[str, Any], structured),
            output_hash=hashlib.sha256(canonical).hexdigest(),
            error_code=None,
            error_message=None,
            remote_result_observed=True,
            charge_reserved=True,
            raise_status=None,
        )

    def get_invocation(self, invocation_id: str, *, actor: object) -> dict[str, Any]:
        context = _principal(actor)
        record = self._storage.get_invocation(
            invocation_id, owner=context.owner, tenant_id=context.tenant_id
        )
        if context.agent_id is not None and record["agent_id"] != context.agent_id:
            raise KeyError(f"relay invocation not found: {invocation_id}")
        return record

    def reconcile_abandoned(self) -> list[dict[str, Any]]:
        finalized: list[dict[str, Any]] = []
        for record in self._storage.recover_abandoned():
            if record.get("receipt"):
                finalized.append(record)
                continue
            target = record.get("target_snapshot")
            if not isinstance(target, dict):
                raise RuntimeError(
                    "relay recovery requires an immutable target snapshot"
                )
            receipt = sign_receipt(
                self._receipt_payload(
                    invocation=record,
                    target=target,
                    capability={"token_id": record["capability_token_id"]},
                    status=str(record["status"]),
                    policy=record.get("policy"),
                    budget=record.get("budget"),
                    output_hash=record.get("output_hash"),
                    error_code=record.get("error_code"),
                    remote_result_observed=bool(record["remote_result_observed"]),
                )
            )
            finalized.append(
                self._storage.attach_receipt(str(record["invocation_id"]), receipt)
            )
        return finalized

    def _reject_before_dispatch(
        self,
        *,
        invocation: dict[str, Any],
        target: dict[str, Any],
        capability: dict[str, Any],
        code: str,
        message: str,
        status_code: int,
        policy: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ) -> NoReturn:
        invocation = self._storage.get_invocation_unscoped(
            str(invocation["invocation_id"])
        )
        receipt = sign_receipt(
            self._receipt_payload(
                invocation=invocation,
                target=target,
                capability=capability,
                status="failed",
                policy=policy,
                budget=budget,
                output_hash=None,
                error_code=code,
                remote_result_observed=False,
            )
        )
        record = self._storage.fail_before_dispatch(
            invocation_id=str(invocation["invocation_id"]),
            error_code=code,
            error_message=message,
            receipt=receipt,
            policy=policy,
            budget=budget,
        )
        error = RelayServiceError(code, message, status_code=status_code, record=record)
        if cause is not None:
            raise error from cause
        raise error

    def _finalize_remote(
        self,
        *,
        invocation: dict[str, Any],
        target: dict[str, Any],
        capability: dict[str, Any],
        policy: dict[str, Any],
        budget: dict[str, Any],
        status: str,
        result: dict[str, Any] | None,
        output_hash: str | None,
        error_code: str | None,
        error_message: str | None,
        remote_result_observed: bool,
        charge_reserved: bool,
        raise_status: int | None,
        cause: BaseException | None = None,
    ) -> dict[str, Any]:
        receipt = sign_receipt(
            self._receipt_payload(
                invocation=invocation,
                target=target,
                capability=capability,
                status=status,
                policy=policy,
                budget=budget,
                output_hash=output_hash,
                error_code=error_code,
                remote_result_observed=remote_result_observed,
            )
        )
        record = self._storage.finalize(
            invocation_id=str(invocation["invocation_id"]),
            status=status,
            output_hash=output_hash,
            result=result,
            error_code=error_code,
            error_message=error_message,
            receipt=receipt,
            remote_result_observed=remote_result_observed,
            charge_reserved=charge_reserved,
        )
        if raise_status is None:
            return record
        error = RelayServiceError(
            str(error_code),
            str(error_message),
            status_code=raise_status,
            record=record,
        )
        if cause is not None:
            raise error from cause
        raise error

    @staticmethod
    def _receipt_payload(
        *,
        invocation: dict[str, Any],
        target: dict[str, Any],
        capability: dict[str, Any],
        status: str,
        policy: dict[str, Any] | None,
        budget: dict[str, Any] | None,
        output_hash: str | None,
        error_code: str | None,
        remote_result_observed: bool,
    ) -> dict[str, Any]:
        return {
            "receipt_version": "mcp-relay-receipt-v1",
            "invocation_id": invocation["invocation_id"],
            "idempotency_key_hash": hashlib.sha256(
                str(invocation["idempotency_key"]).encode("utf-8")
            ).hexdigest(),
            "outcome": status,
            "owner": invocation["owner"],
            "tenant_id": invocation["tenant_id"],
            "agent_id": invocation["agent_id"],
            "capability_token_id": capability.get(
                "token_id", invocation["capability_token_id"]
            ),
            "capability_issuer": capability.get("issuer"),
            "capability_subject": capability.get("subject"),
            "capability_audience": capability.get("audience"),
            "capability_resource": capability.get("resource"),
            "capability_scopes": capability.get("effective_scopes", []),
            "target_id": target["target_id"],
            "endpoint_digest": target["endpoint_digest"],
            "server_name": target["server_name"],
            "server_version": target["server_version"],
            "protocol_version": target["protocol_version"],
            "tool_name": target["tool_name"],
            "operator_attests_read_only": target["operator_attests_read_only"],
            "schema_digest": target["schema_digest"],
            "input_hash": invocation["input_hash"],
            "output_hash": output_hash,
            "policy_revision": target["policy_revision"],
            "policy_decision_id": (policy or {}).get("decision_id"),
            "policy_input_hash": (policy or {}).get("input_hash"),
            "budget": budget,
            "reserved_cost_usd": invocation.get("reserved_cost_usd", 0),
            "network_started_at": invocation.get("network_started_at"),
            "network_started": invocation.get("network_started_at") is not None,
            "remote_result_observed": remote_result_observed,
            "attempt_count": invocation.get("attempt_count", 0),
            "error_code": error_code,
            "issued_at": utc_now_iso(),
        }
