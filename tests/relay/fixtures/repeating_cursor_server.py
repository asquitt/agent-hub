from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.types import ListToolsResult, ToolAnnotations
from pydantic import BaseModel, ConfigDict


class LookupResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: str


def _increment(path: Path) -> None:
    path.write_text(str(int(path.read_text(encoding="utf-8")) + 1), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--list-counter", required=True, type=Path)
    parser.add_argument("--call-counter", required=True, type=Path)
    args = parser.parse_args()

    class RepeatingCursorServer(MCPServer):
        async def _handle_list_tools(
            self, ctx: object, params: object
        ) -> ListToolsResult:
            del ctx, params
            _increment(args.list_counter)
            return ListToolsResult(
                tools=await self.list_tools(), next_cursor="opaque-repeat"
            )

    server = RepeatingCursorServer(name="repeating-cursor", version="1.0.0")

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
        _increment(args.call_counter)
        return LookupResult(answer=q)

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
