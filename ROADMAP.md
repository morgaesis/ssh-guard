# Roadmap

- Stabilize the MCP interface around the single guarded execution tool and keep it compatible with the existing daemon protocol.
- Add integration coverage for `mcp serve` against a live local guard daemon so MCP behavior is validated end to end.
- If users need richer agent workflows, add more MCP tools only when they map cleanly onto existing guard capabilities instead of creating parallel policy paths.
- Consider Streamable HTTP MCP transport only after there is a concrete deployment need and an authentication model for it.
