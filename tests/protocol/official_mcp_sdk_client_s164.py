"""Official MCP SDK client probe executed from an isolated test environment."""
from __future__ import annotations

import asyncio
from importlib.metadata import version
import json
import os
import sys
from typing import Any

import httpx2
from mcp import ClientSession
from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
from mcp.client.streamable_http import streamable_http_client


class MemoryTokenStorage:
    def __init__(self) -> None:
        self.tokens: Any | None = None
        self.client_info: Any | None = None

    async def get_tokens(self) -> Any | None:
        return self.tokens

    async def set_tokens(self, tokens: Any) -> None:
        self.tokens = tokens

    async def get_client_info(self) -> Any | None:
        return self.client_info

    async def set_client_info(self, client_info: Any) -> None:
        self.client_info = client_info


async def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: official_mcp_sdk_client_s164.py <mcp-url>")
    mcp_url = sys.argv[1]
    auth_mode = os.getenv("AGENTHUB_OFFICIAL_MCP_AUTH_MODE", "api_key")
    if auth_mode == "api_key":
        headers = {"X-API-Key": os.environ["AGENTHUB_OFFICIAL_MCP_API_KEY"]}
        auth = None
    elif auth_mode == "oauth":
        headers = {}
        auth = ClientCredentialsOAuthProvider(
            server_url=mcp_url,
            storage=MemoryTokenStorage(),
            client_id=os.environ["AGENTHUB_OFFICIAL_MCP_CLIENT_ID"],
            client_secret=os.environ["AGENTHUB_OFFICIAL_MCP_CLIENT_SECRET"],
            token_endpoint_auth_method="client_secret_post",
            scope="discovery.read discovery.search",
        )
    else:
        raise SystemExit(f"unsupported auth mode: {auth_mode}")

    async with httpx2.AsyncClient(headers=headers, auth=auth) as http_client:
        async with streamable_http_client(mcp_url, http_client=http_client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                result = await session.call_tool(
                    "search_capabilities",
                    {
                        "query": "extract invoice totals",
                        "constraints": {"max_cost_usd": 0.02, "min_trust_score": 0.8},
                    },
                )
                print(
                    json.dumps(
                        {
                            "auth_mode": auth_mode,
                            "protocol_version": initialized.protocol_version,
                            "sdk_version": version("mcp"),
                            "server_name": initialized.server_info.name,
                            "tool_names": sorted(tool.name for tool in tools.tools),
                            "is_error": result.is_error,
                            "result_count": len((result.structured_content or {}).get("data", [])),
                        },
                        sort_keys=True,
                    )
                )


asyncio.run(main())
