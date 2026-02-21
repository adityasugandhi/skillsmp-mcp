#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";
import { skillManager } from "./skill-manager.js";
import { syncEngine } from "./sync-engine.js";

const server = new McpServer({
  name: "skillsync",
  version: "1.3.0",
});

registerTools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[skillsync] MCP server running on stdio");

  // Background: discover and scan installed skills (non-blocking)
  skillManager.initialize().catch((err) => {
    console.error("[skillsync] Skill manager init error:", err instanceof Error ? err.message : err);
  });

  // Background: start periodic sync if configured
  syncEngine.startPeriodicSync().catch((err) => {
    console.error("[skillsync] Sync engine error:", err instanceof Error ? err.message : err);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.error("[skillsync] Shutting down...");
    syncEngine.shutdown();
    skillManager.shutdown();
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
  console.error("[skillsync] Fatal error:", error);
  process.exit(1);
});
