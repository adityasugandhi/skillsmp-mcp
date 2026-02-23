#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";
import { getSkillManager, shutdownAllManagers } from "./skill-manager.js";
import { getSyncEngine, shutdownAllEngines } from "./sync-engine.js";

const server = new McpServer({
  name: "skillsync",
  version: "1.4.1",
});

registerTools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[skillsync] MCP server running on stdio");

  // Background: discover and scan installed skills in global scope (non-blocking)
  // Project-scope managers are created lazily when tools are called with scope="project"
  getSkillManager("global").initialize().catch((err) => {
    console.error("[skillsync] Skill manager init error:", err instanceof Error ? err.message : err);
  });

  // Background: start periodic sync if configured (global scope)
  getSyncEngine("global").startPeriodicSync().catch((err) => {
    console.error("[skillsync] Sync engine error:", err instanceof Error ? err.message : err);
  });

  // Graceful shutdown
  const shutdown = async () => {
    console.error("[skillsync] Shutting down...");
    shutdownAllEngines();
    shutdownAllManagers();
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

/**
 * Smithery sandbox server for capability scanning.
 * Returns a configured McpServer without connecting transport.
 */
export function createSandboxServer() {
  const sandboxServer = new McpServer({
    name: "skillsync",
    version: "1.4.1",
  });
  registerTools(sandboxServer);
  return sandboxServer;
}
