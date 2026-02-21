#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";

const server = new McpServer({
  name: "skillsmp",
  version: "1.0.0",
});

registerTools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[skillsmp] MCP server running on stdio");

  // Graceful shutdown
  const shutdown = async () => {
    console.error("[skillsmp] Shutting down...");
    try {
      await server.close();
    } catch {
      // ignore close errors
    }
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("[skillsmp] Fatal error:", error);
  process.exit(1);
});
