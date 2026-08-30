from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict


class LookupResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--counter", required=True, type=Path)
    args = parser.parse_args()

    server = MCPServer(name="agenthub-relay-fixture", version="1.0.0")

    @server.tool(
        name="lookup",
        structured_output=True,
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def lookup(q: str) -> LookupResult:
        current = int(args.counter.read_text(encoding="utf-8"))
        args.counter.write_text(str(current + 1), encoding="utf-8")
        return LookupResult(answer=f"found:{q}")

    @server.tool(
        name="oversized_lookup",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def oversized_lookup(q: str) -> CallToolResult:
        current = int(args.counter.read_text(encoding="utf-8"))
        args.counter.write_text(str(current + 1), encoding="utf-8")
        return CallToolResult(
            content=[TextContent(type="text", text="x" * 70_000)],
            structured_content={"answer": f"found:{q}"},
            is_error=False,
        )

    server.run(
        "streamable-http",
        host="127.0.0.1",
        port=args.port,
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
    )


if __name__ == "__main__":
    main()
