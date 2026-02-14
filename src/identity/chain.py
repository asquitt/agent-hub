from __future__ import annotations

from src.identity.constants import MAX_DELEGATION_CHAIN_DEPTH, WILDCARD_SCOPE


def attenuate_scopes(parent_scopes: list[str], requested_scopes: list[str]) -> list[str]:
    """Compute attenuated scopes: requested MUST be a subset of parent.

    Returns the effective scopes (intersection). Raises ValueError if
    requested scopes exceed parent permissions.
    """
    if WILDCARD_SCOPE in parent_scopes:
        return sorted(set(requested_scopes))

    parent_set = set(parent_scopes)
    requested_set = set(requested_scopes)
    excess = requested_set - parent_set
    if excess:
        raise ValueError(f"scope escalation denied: {sorted(excess)} not in parent scopes")

    return sorted(requested_set)


def validate_chain_depth(current_depth: int) -> None:
    """Enforce maximum delegation chain depth."""
    if current_depth >= MAX_DELEGATION_CHAIN_DEPTH:
        raise ValueError(
            f"delegation chain depth limit exceeded: {current_depth} >= {MAX_DELEGATION_CHAIN_DEPTH}"
        )


def build_chain(token_records: list[dict[str, str | int | list[str]]]) -> list[dict[str, str | int | list[str]]]:
    """Build ordered delegation chain from token records.

    Input: list of token records ordered from most-recent to root.
    Output: list ordered from root to most-recent (chronological).
    """
    return list(reversed(token_records))
