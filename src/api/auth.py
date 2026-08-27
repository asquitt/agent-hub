from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Literal

from fastapi import Header, HTTPException

from src.common.time import iso_from_epoch, utc_now_epoch

DEFAULT_TOKEN_TTL_SECONDS = 1800
MAX_TOKEN_TTL_SECONDS = 86400


AuthMethod = Literal[
    "api_key",
    "agent_credential",
    "bearer_token",
    "jwt_bearer",
    "delegation_token",
]


class AuthContext(str):
    """Authenticated principal that remains compatible with owner-string routes."""

    scopes: frozenset[str]
    roles: frozenset[str]
    tenant_id: str
    auth_method: AuthMethod
    agent_id: str | None
    delegation_token_id: str | None

    def __new__(
        cls,
        owner: str,
        *,
        scopes: Iterable[str],
        auth_method: AuthMethod,
        roles: Iterable[str] = (),
        tenant_id: str = "tenant-default",
        agent_id: str | None = None,
        delegation_token_id: str | None = None,
    ) -> AuthContext:
        normalized_owner = str(owner).strip()
        if not normalized_owner:
            raise ValueError("authenticated owner cannot be empty")
        context = str.__new__(cls, normalized_owner)
        context.scopes = frozenset(str(scope).strip() for scope in scopes if str(scope).strip())
        context.roles = frozenset(str(role).strip() for role in roles if str(role).strip())
        context.tenant_id = str(tenant_id).strip() or "tenant-default"
        context.auth_method = auth_method
        context.agent_id = str(agent_id).strip() if agent_id else None
        context.delegation_token_id = str(delegation_token_id).strip() if delegation_token_id else None
        return context

    @property
    def owner(self) -> str:
        return str(self)

    def with_tenant(self, tenant_id: str | None) -> AuthContext:
        return AuthContext(
            self.owner,
            scopes=self.scopes,
            roles=self.roles,
            tenant_id=str(tenant_id or "tenant-default"),
            auth_method=self.auth_method,
            agent_id=self.agent_id,
            delegation_token_id=self.delegation_token_id,
        )

    def allows_scope(self, required_scope: str) -> bool:
        required = required_scope.strip()
        if not required:
            return False
        if "*" in self.scopes or required in self.scopes:
            return True
        namespace = required.split(".", 1)[0]
        return f"{namespace}.*" in self.scopes

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "auth_method": self.auth_method,
            "agent_id": self.agent_id,
            "scopes": sorted(self.scopes),
            "roles": sorted(self.roles),
            "tenant_id": self.tenant_id,
            "delegation_token_id": self.delegation_token_id,
        }


@dataclass(frozen=True)
class _ApiKeyRecord:
    owner: str
    scopes: tuple[str, ...]
    roles: tuple[str, ...]


def _default_roles(owner: str) -> tuple[str, ...]:
    if owner in {"owner-dev", "owner-platform"}:
        return ("admin",)
    return ("member",)


def _normalize_claim_list(value: object, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RuntimeError(f"{field_name} must be a JSON array")
    if any(not isinstance(item, str) for item in value):
        raise RuntimeError(f"{field_name} must contain only strings")
    return tuple(sorted({item.strip() for item in value if item.strip()}))


def _api_key_records() -> dict[str, _ApiKeyRecord]:
    raw = os.getenv("AGENTHUB_API_KEYS_JSON")
    if raw is None or not raw.strip():
        raise RuntimeError("AGENTHUB_API_KEYS_JSON is required")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("AGENTHUB_API_KEYS_JSON must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("AGENTHUB_API_KEYS_JSON must be a JSON object")
    normalized: dict[str, _ApiKeyRecord] = {}
    for key, configured in parsed.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        if isinstance(configured, str):
            owner = configured.strip()
            scopes = ("*",)
            roles = _default_roles(owner)
        elif isinstance(configured, dict):
            owner = str(configured.get("owner", "")).strip()
            scopes = _normalize_claim_list(configured.get("scopes", []), field_name=f"API key {key_str} scopes")
            raw_roles = configured.get("roles")
            roles = _default_roles(owner) if raw_roles is None else _normalize_claim_list(
                raw_roles,
                field_name=f"API key {key_str} roles",
            )
        else:
            raise RuntimeError(f"AGENTHUB_API_KEYS_JSON entry {key_str} must be a string or JSON object")
        if not owner:
            raise RuntimeError(f"AGENTHUB_API_KEYS_JSON entry {key_str} must define an owner")
        normalized[key_str] = _ApiKeyRecord(owner=owner, scopes=scopes, roles=roles)
    if not normalized:
        raise RuntimeError("AGENTHUB_API_KEYS_JSON must define at least one API key")
    return normalized


def _token_secret() -> bytes:
    secret = os.getenv("AGENTHUB_AUTH_TOKEN_SECRET")
    if secret is None or not secret.strip():
        raise RuntimeError("AGENTHUB_AUTH_TOKEN_SECRET is required")
    return secret.encode("utf-8")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("utf-8"))


def _sign(body: str) -> str:
    return hmac.new(_token_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_scoped_token(
    owner: str,
    scopes: list[str],
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> dict[str, Any]:
    ttl = max(1, min(int(ttl_seconds), MAX_TOKEN_TTL_SECONDS))
    now = utc_now_epoch()
    owner_value = owner.owner if isinstance(owner, AuthContext) else str(owner)
    roles = sorted(owner.roles) if isinstance(owner, AuthContext) else list(_default_roles(owner_value))
    tenant_id = owner.tenant_id if isinstance(owner, AuthContext) else "tenant-default"
    requested_scopes = sorted({str(scope).strip() for scope in scopes if str(scope).strip()})
    if isinstance(owner, AuthContext) and "*" not in owner.scopes:
        unauthorized = [scope for scope in requested_scopes if not owner.allows_scope(scope)]
        if unauthorized:
            raise HTTPException(status_code=403, detail="requested scopes exceed issuer authority")
    payload = {
        "sub": owner_value,
        "scopes": requested_scopes,
        "roles": roles,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + ttl,
    }
    body = _b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    token = f"{body}.{_sign(body)}"
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_at": iso_from_epoch(payload["exp"]),
        "scopes": payload["scopes"],
        "subject": payload["sub"],
    }


def verify_scoped_token(token: str) -> dict[str, Any]:
    try:
        body, signature = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token format") from exc

    expected = _sign(body)
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="invalid bearer token signature")

    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token payload") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail="invalid bearer token payload")
    if "sub" not in payload or "exp" not in payload:
        raise HTTPException(status_code=401, detail="invalid bearer token claims")
    try:
        expires_at = int(payload["exp"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token expiry") from exc
    if expires_at < utc_now_epoch():
        raise HTTPException(status_code=401, detail="bearer token expired")
    scopes = payload.get("scopes", [])
    if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes):
        raise HTTPException(status_code=401, detail="invalid bearer token scopes")
    roles = payload.get("roles", [])
    if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
        raise HTTPException(status_code=401, detail="invalid bearer token roles")
    payload["scopes"] = [str(scope) for scope in scopes]
    payload["roles"] = [str(role) for role in roles]
    payload["sub"] = str(payload["sub"])
    raw_tenant_id = payload.get("tenant_id")
    if not isinstance(raw_tenant_id, str) or not raw_tenant_id.strip():
        raise HTTPException(status_code=401, detail="bearer token missing tenant_id claim")
    payload["tenant_id"] = raw_tenant_id.strip()
    return payload


def _context_from_api_key(x_api_key: str | None, *, tenant_id: str = "tenant-default") -> AuthContext | None:
    if not x_api_key:
        return None
    record = _api_key_records().get(x_api_key)
    if record is None:
        return None
    return AuthContext(
        record.owner,
        scopes=record.scopes,
        roles=record.roles,
        tenant_id=tenant_id,
        auth_method="api_key",
    )


def _context_from_jwt(token: str, *, tenant_id: str) -> AuthContext:
    """Authenticate an agent JWT against its signed tenant and live identity."""
    from src.identity.constants import STATUS_ACTIVE
    from src.identity.jwt_tokens import verify_jwt
    from src.identity.oauth_clients import OAUTH_CLIENT_STORE
    from src.identity.storage import get_agent_identity_auth_snapshot

    try:
        claims = verify_jwt(token, require_agent_id=True)
        owner = str(claims.get("sub", ""))
        scopes = claims.get("scopes", [])
        agent_id = str(claims.get("agent_id", "")).strip()
        roles = claims.get("roles", [])
        if not owner:
            raise HTTPException(status_code=401, detail="JWT missing sub claim")
        if not agent_id:
            raise HTTPException(status_code=401, detail="JWT missing agent_id claim")
        if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes):
            raise HTTPException(status_code=401, detail="JWT has invalid scopes claim")
        if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
            raise HTTPException(status_code=401, detail="JWT has invalid roles claim")
        token_tenant_id = claims.get("tenant_id")
        if not isinstance(token_tenant_id, str) or not token_tenant_id:
            raise HTTPException(status_code=401, detail="JWT missing tenant_id claim")
        if token_tenant_id != tenant_id:
            raise HTTPException(status_code=401, detail="JWT tenant mismatch")

        try:
            identity, current_generation, identity_tenant_id = get_agent_identity_auth_snapshot(agent_id)
        except KeyError as exc:
            # OAuth client-credentials JWTs share the encoder but are not agent identities.
            oauth_client = OAUTH_CLIENT_STORE.get_client(agent_id)
            if oauth_client is None:
                raise HTTPException(status_code=401, detail="JWT agent identity not found") from exc
            if oauth_client["owner"] != owner:
                raise HTTPException(status_code=401, detail="JWT owner does not match OAuth client") from exc
            if oauth_client["tenant_id"] != token_tenant_id:
                raise HTTPException(status_code=401, detail="JWT tenant does not match OAuth client") from exc
            return AuthContext(
                owner,
                scopes=scopes,
                roles=roles or ("member",),
                tenant_id=token_tenant_id,
                auth_method="jwt_bearer",
                agent_id=agent_id,
            )

        if identity["status"] != STATUS_ACTIVE:
            raise HTTPException(status_code=401, detail="JWT agent identity is not active")
        if identity["owner"] != owner:
            raise HTTPException(status_code=401, detail="JWT owner does not match agent identity")
        if identity_tenant_id is None or identity_tenant_id != token_tenant_id:
            raise HTTPException(status_code=401, detail="JWT tenant does not match agent identity")
        token_generation = claims.get("identity_generation")
        if not isinstance(token_generation, str) or not token_generation:
            raise HTTPException(status_code=401, detail="JWT missing identity_generation claim")
        if current_generation is None or token_generation != current_generation:
            raise HTTPException(status_code=401, detail="JWT identity generation mismatch")

        return AuthContext(
            owner,
            scopes=scopes,
            roles=roles or ("member",),
            tenant_id=token_tenant_id,
            auth_method="jwt_bearer",
            agent_id=agent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"JWT auth failed: {exc}") from exc


def resolve_owner_from_headers(
    *,
    x_api_key: str | None,
    authorization: str | None,
    x_delegation_token: str | None = None,
    tenant_id: str = "tenant-default",
    strict: bool = True,
) -> AuthContext | None:
    try:
        return resolve_auth_context(
            x_api_key=x_api_key,
            authorization=authorization,
            x_delegation_token=x_delegation_token,
            tenant_id=tenant_id,
        )
    except HTTPException:
        if strict:
            raise
        return None


def resolve_auth_context(
    *,
    x_api_key: str | None = None,
    authorization: str | None = None,
    x_delegation_token: str | None = None,
    tenant_id: str = "tenant-default",
) -> AuthContext | None:
    """Resolve full auth context including agent identity, scopes, and auth method."""
    supplied_credentials = sum(bool(value and value.strip()) for value in (x_api_key, authorization, x_delegation_token))
    if supplied_credentials > 1:
        raise HTTPException(status_code=401, detail="multiple authentication credentials are not allowed")

    # An explicitly supplied credential must validate; do not silently fall through.
    if x_api_key:
        context = _context_from_api_key(x_api_key, tenant_id=tenant_id)
        if context is None:
            raise HTTPException(status_code=401, detail="invalid API key")
        return context

    # 2. Delegation token — fail loudly if provided but invalid
    if x_delegation_token:
        from src.identity.constants import STATUS_ACTIVE
        from src.identity.delegation_tokens import verify_delegation_token
        from src.identity.storage import get_agent_identity_auth_snapshot

        try:
            result = verify_delegation_token(x_delegation_token)
            token_owner = result.get("owner")
            token_tenant_id = result.get("tenant_id")
            if not isinstance(token_owner, str) or not token_owner:
                raise PermissionError("delegation token missing owner")
            if not isinstance(token_tenant_id, str) or not token_tenant_id:
                raise PermissionError("delegation token missing tenant_id")
            if token_tenant_id != tenant_id:
                raise PermissionError("delegation token tenant mismatch")
            identity, _, identity_tenant_id = get_agent_identity_auth_snapshot(result["subject_agent_id"])
            if identity["status"] != STATUS_ACTIVE:
                raise PermissionError("delegation token agent identity is not active")
            if identity["owner"] != token_owner:
                raise PermissionError("delegation token owner does not match agent identity")
            if identity_tenant_id is None or identity_tenant_id != token_tenant_id:
                raise PermissionError("delegation token tenant does not match agent identity")
            return AuthContext(
                token_owner,
                scopes=result["delegated_scopes"],
                roles=("member",),
                tenant_id=token_tenant_id,
                auth_method="delegation_token",
                agent_id=result["subject_agent_id"],
                delegation_token_id=result["token_id"],
            )
        except (PermissionError, KeyError, RuntimeError) as exc:
            raise HTTPException(status_code=401, detail=f"delegation token auth failed: {exc}") from exc

    # 3. Agent credential or bearer token — fail loudly if provided but invalid
    if authorization:
        agent_prefix = "agentcredential "
        if authorization.lower().startswith(agent_prefix):
            from src.identity.constants import STATUS_ACTIVE
            from src.identity.credentials import verify_credential
            from src.identity.storage import get_agent_identity_auth_snapshot

            secret = authorization[len(agent_prefix):].strip()
            try:
                result = verify_credential(secret)
                identity, _, identity_tenant_id = get_agent_identity_auth_snapshot(result["agent_id"])
                if identity["status"] != STATUS_ACTIVE:
                    raise PermissionError("agent credential identity is not active")
                if identity_tenant_id is None or identity_tenant_id != tenant_id:
                    raise PermissionError("agent credential tenant mismatch")
                return AuthContext(
                    identity["owner"],
                    scopes=result["scopes"],
                    roles=("member",),
                    tenant_id=identity_tenant_id,
                    auth_method="agent_credential",
                    agent_id=result["agent_id"],
                )
            except (PermissionError, KeyError, RuntimeError) as exc:
                raise HTTPException(status_code=401, detail=f"agent credential auth failed: {exc}") from exc
        prefix = "bearer "
        if not authorization.lower().startswith(prefix):
            raise HTTPException(status_code=401, detail="invalid authorization scheme")
        raw_token = authorization[len(prefix):].strip()
        if raw_token.count(".") == 2:
            return _context_from_jwt(raw_token, tenant_id=tenant_id)
        claims = verify_scoped_token(raw_token)
        token_tenant_id = claims["tenant_id"]
        if token_tenant_id != tenant_id:
            raise HTTPException(status_code=401, detail="bearer token tenant mismatch")
        return AuthContext(
            claims["sub"],
            scopes=claims.get("scopes", []),
            roles=claims.get("roles", []),
            tenant_id=token_tenant_id,
            auth_method="bearer_token",
        )

    # No credentials provided at all
    return None


def validate_auth_configuration() -> None:
    _ = _api_key_records()
    _ = _token_secret()


def require_api_key_owner(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> AuthContext:
    context = _context_from_api_key(x_api_key, tenant_id=x_tenant_id or "tenant-default")
    if context is None:
        raise HTTPException(status_code=401, detail="missing or invalid API key")
    return context


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_delegation_token: str | None = Header(default=None, alias="X-Delegation-Token"),
    x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
) -> AuthContext:
    context = resolve_owner_from_headers(
        x_api_key=x_api_key,
        authorization=authorization,
        x_delegation_token=x_delegation_token,
        tenant_id=x_tenant_id or "tenant-default",
        strict=True,
    )
    if context is not None:
        return context
    raise HTTPException(status_code=401, detail="missing or invalid authentication")


def require_scope(scope: str):
    normalized_scope = scope.strip()

    def _dependency(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_delegation_token: str | None = Header(default=None, alias="X-Delegation-Token"),
        x_tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
    ) -> AuthContext:
        context = resolve_auth_context(
            x_api_key=x_api_key,
            authorization=authorization,
            x_delegation_token=x_delegation_token,
            tenant_id=x_tenant_id or "tenant-default",
        )
        if context is None:
            raise HTTPException(status_code=401, detail="missing or invalid authentication")
        if context.allows_scope(normalized_scope):
            return context
        raise HTTPException(status_code=403, detail=f"missing required scope: {normalized_scope}")

    return _dependency
