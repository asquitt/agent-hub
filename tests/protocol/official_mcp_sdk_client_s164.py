"""Official MCP SDK client probe executed from an isolated test environment."""
from __future__ import annotations

import asyncio
from importlib.metadata import version
import json
import os
import sys

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: official_mcp_sdk_client_s164.py <mcp-url>")
    mcp_url = sys.argv[1]
    api_key = os.environ["AGENTHUB_OFFICIAL_MCP_API_KEY"]
    async with httpx2.AsyncClient(headers={"X-API-Key": api_key}) as http_client:
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
