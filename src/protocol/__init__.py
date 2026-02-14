"""Protocol adapters — canonical contract ↔ protocol-specific translation.

Supports MCP (Model Context Protocol) and A2A (Agent-to-Agent) protocol
translation from AgentHub's canonical internal contract format.
"""
from __future__ import annotations

SUPPORTED_PROTOCOLS = ["MCP", "A2A", "HTTP"]
