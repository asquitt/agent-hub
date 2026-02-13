"""Compatibility bridge to the canonical registry store module.

The registry store moved to ``src.registry.store`` to keep domain state out of the API package.
This module remains as an import-stable shim for existing tests/tools.
"""

from src.registry.store import (
    AgentRecord,
    DEFAULT_DB_PATH,
    ROOT,
    STORE,
    RegistryStore,
    VersionRecord,
)

__all__ = [
    "ROOT",
    "DEFAULT_DB_PATH",
    "VersionRecord",
    "AgentRecord",
    "RegistryStore",
    "STORE",
]
