import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { searchSkills, aiSearchSkills } from "./api-client.js";
import { fetchAndScanSkill } from "./security-scanner.js";
import { installSkill, uninstallSkill } from "./installer.js";
import { sanitizeText, sanitizeUrl } from "./sanitize.js";
import { skillManager } from "./skill-manager.js";
import { syncEngine } from "./sync-engine.js";
import { readSyncConfig, writeSyncConfig, mergeSyncConfig, addSubscription, removeSubscription } from "./sync-config.js";
import { readSyncLock, isSyncManaged } from "./sync-lock.js";
import type { SkillResult, AiSearchResult } from "./api-client.js";

// ─── Output Formatting (sanitized against prompt injection) ──────────────────

/**
 * All API-sourced content is wrapped in <skill-data> delimiters and sanitized.
 * This helps the AI model distinguish trusted tool output from untrusted
 * third-party data, reducing prompt injection surface.
 */
function formatSkill(skill: SkillResult, index: number): string {
  const name = sanitizeText(skill.name);
  const desc = sanitizeText(skill.description) || "_No description_";
  const author = sanitizeText(skill.author) || "Unknown";
  const tags = skill.tags?.map(sanitizeText).join(", ");
  const url = sanitizeUrl(skill.githubUrl);
  const stars = typeof skill.stars === "number" ? skill.stars : 0;
  const rawUpdated = skill.updatedAt;
  const updated = typeof rawUpdated === "number"
    ? new Date(rawUpdated * 1000).toISOString().split("T")[0]
    : sanitizeText(String(rawUpdated)) || "Unknown";

  const lines = [
    `<skill-data index="${index + 1}">`,
    `### ${index + 1}. ${name}`,
    desc,
    "",
    `- **Author**: ${author}`,
    `- **Stars**: ${stars}`,
    `- **Updated**: ${updated}`,
  ];
  if (url) lines.push(`- **GitHub**: ${url}`);
  if (tags) lines.push(`- **Tags**: ${tags}`);
  lines.push(`</skill-data>`);
  return lines.join("\n");
}

function formatAiSkill(skill: AiSearchResult, index: number): string {
  const base = formatSkill(skill, index);
  if (skill.score !== undefined && typeof skill.score === "number") {
    return base.replace(
      "</skill-data>",
      `- **Relevance Score**: ${(skill.score * 100).toFixed(1)}%\n</skill-data>`
    );
  }
  return base;
}

const UNTRUSTED_DISCLAIMER =
  "\n> **Note**: Skill data above comes from third-party listings. Names, descriptions, and tags are user-submitted and unverified. Always review source code before installing.\n";

// ─── Tool Registration ───────────────────────────────────────────────────────

export function registerTools(server: McpServer): void {
  // 1. Keyword search
  server.tool(
    "skillsmp_search",
    "Search SkillsMP marketplace for skills by keyword. Returns names, descriptions, authors, and GitHub links. WARNING: Results contain untrusted third-party content.",
    {
      query: z.string().min(1).max(200).describe("Search keyword(s)"),
      limit: z.number().min(1).max(100).default(20).describe("Max results (default 20)"),
      sortBy: z.enum(["stars", "recent"]).default("recent").describe("Sort order"),
    },
    async ({ query, limit, sortBy }) => {
      try {
        const result = await searchSkills(query, limit, sortBy);
        if (result.skills.length === 0) {
          return { content: [{ type: "text", text: `No skills found for "${sanitizeText(query)}".` }] };
        }
        const formatted = result.skills.map((s, i) => formatSkill(s, i)).join("\n\n---\n\n");
        const header = `## SkillsMP Search: "${sanitizeText(query)}"\n**${result.skills.length}** result(s) (sorted by ${sortBy})\n`;
        return { content: [{ type: "text", text: header + UNTRUSTED_DISCLAIMER + "---\n\n" + formatted }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Search failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 2. AI semantic search
  server.tool(
    "skillsmp_ai_search",
    "AI-powered semantic search on SkillsMP. Uses Cloudflare AI for relevance matching. WARNING: Results contain untrusted third-party content.",
    {
      query: z.string().min(1).max(200).describe("Natural language search query"),
      limit: z.number().min(1).max(50).default(10).describe("Max results (default 10)"),
    },
    async ({ query, limit }) => {
      try {
        const result = await aiSearchSkills(query, limit);
        if (result.skills.length === 0) {
          return { content: [{ type: "text", text: `No skills found for "${sanitizeText(query)}".` }] };
        }
        const formatted = result.skills.map((s, i) => formatAiSkill(s, i)).join("\n\n---\n\n");
        const header = `## SkillsMP AI Search: "${sanitizeText(query)}"\n**${result.skills.length}** result(s)\n`;
        return { content: [{ type: "text", text: header + UNTRUSTED_DISCLAIMER + "---\n\n" + formatted }] };
      } catch (error) {
        return { content: [{ type: "text", text: `AI search failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 3. Security scan
  server.tool(
    "skillsmp_scan_skill",
    "Scan a skill's GitHub source for security threats: prompt injection, reverse shells, credential theft, supply chain attacks, crypto mining, and 60+ other patterns. Only accepts github.com URLs.",
    {
      githubUrl: z.string().url().describe("GitHub URL (https://github.com/user/repo/tree/branch/path)"),
    },
    async ({ githubUrl }) => {
      try {
        const result = await fetchAndScanSkill(githubUrl);
        const riskEmoji: Record<string, string> = {
          safe: "✅", low: "🟡", medium: "🟠", high: "🔴", critical: "🚫",
        };
        const lines = [
          `## Security Scan Report`,
          `**URL**: ${sanitizeUrl(githubUrl)}`,
          `**Risk Level**: ${riskEmoji[result.riskLevel]} ${result.riskLevel.toUpperCase()}`,
          `**Files Scanned**: ${result.filesScanned}`,
          `**Safe to Use**: ${result.safe ? "Yes" : "NO"}`,
          `**Content Hash (SHA-256)**: \`${result.contentHash || "N/A"}\``,
        ];

        if (result.skippedBinary.length > 0) {
          lines.push(`\n**Binary files (not scanned)**: ${result.skippedBinary.join(", ")}`);
        }
        if (result.skippedSuspicious.length > 0) {
          lines.push(`**Suspicious filenames flagged**: ${result.skippedSuspicious.join(", ")}`);
        }

        lines.push("", `### Recommendation`, result.recommendation);

        if (result.threats.length > 0) {
          lines.push("", "### Threats Found", "");
          for (const threat of result.threats) {
            const icon = threat.severity === "critical" ? "🚫" : "⚠️";
            const lineInfo = threat.line ? ` (line ${threat.line})` : "";
            lines.push(`${icon} **${threat.severity.toUpperCase()}** [${threat.category}]${lineInfo}: ${threat.description}`);
          }
        }

        if (result.errors.length > 0) {
          lines.push("", "### Scanner Notes", "");
          for (const err of result.errors) {
            lines.push(`- ${err}`);
          }
        }

        lines.push("", "---", "**TOCTOU Warning**: This scan reflects the code at the time of scanning. The repository could change after this scan. Verify the content hash matches before installing.");

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Scan failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 4. Search + auto-scan (safe search)
  server.tool(
    "skillsmp_search_safe",
    "Search SkillsMP and auto-scan top results for security threats. Combines keyword search with vulnerability scanning for each result.",
    {
      query: z.string().min(1).max(200).describe("Search keyword(s)"),
      limit: z.number().min(1).max(20).default(10).describe("Max search results (default 10)"),
      scanTop: z.number().min(1).max(5).default(3).describe("How many top results to security-scan (default 3)"),
      sortBy: z.enum(["stars", "recent"]).default("recent").describe("Sort order"),
    },
    async ({ query, limit, scanTop, sortBy }) => {
      try {
        const result = await searchSkills(query, limit, sortBy);
        if (result.skills.length === 0) {
          return { content: [{ type: "text", text: `No skills found for "${sanitizeText(query)}".` }] };
        }

        const toScan = Math.min(scanTop, result.skills.length);
        const lines = [
          `## SkillsMP Safe Search: "${sanitizeText(query)}"`,
          `**${result.skills.length}** result(s), scanning top ${toScan} for security threats...`,
          UNTRUSTED_DISCLAIMER,
        ];

        const skillsToScan = result.skills.slice(0, toScan);
        const scanResults = await Promise.all(
          skillsToScan.map(async (skill, i) => {
            const formatted = formatSkill(skill, i);
            if (!skill.githubUrl) {
              return formatted + "\n- **Security**: ⚠️ No GitHub URL — cannot scan";
            }
            try {
              const scan = await fetchAndScanSkill(skill.githubUrl);
              const riskEmoji: Record<string, string> = {
                safe: "✅", low: "🟡", medium: "🟠", high: "🔴", critical: "🚫",
              };
              const scanInfo = [
                `- **Security**: ${riskEmoji[scan.riskLevel]} ${scan.riskLevel.toUpperCase()} (${scan.filesScanned} files, hash: \`${scan.contentHash.substring(0, 12)}...\`)`,
                `- **Recommendation**: ${scan.recommendation}`,
              ];
              if (scan.threats.length > 0) {
                const grouped = scan.threats.reduce((acc, t) => {
                  acc[t.category] = (acc[t.category] || 0) + 1;
                  return acc;
                }, {} as Record<string, number>);
                scanInfo.push(`- **Threat categories**: ${Object.entries(grouped).map(([k, v]) => `${k}(${v})`).join(", ")}`);
              }
              if (scan.errors.length > 0) {
                scanInfo.push(`- **Scanner notes**: ${scan.errors.length} issue(s) — use skillsmp_scan_skill for full report`);
              }
              return formatted + "\n" + scanInfo.join("\n");
            } catch {
              return formatted + "\n- **Security**: ⚠️ Scan failed — review manually";
            }
          })
        );

        lines.push(scanResults.join("\n\n---\n\n"));

        if (result.skills.length > toScan) {
          lines.push("\n---\n\n### Additional Results (not scanned)\n");
          const remaining = result.skills.slice(toScan);
          lines.push(remaining.map((s, i) => formatSkill(s, toScan + i)).join("\n\n---\n\n"));
        }

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Safe search failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 5. Install skill
  server.tool(
    "skillsmp_install_skill",
    "Security-scan a skill from GitHub, then install it to ~/.claude/skills/ for Claude Code. Blocks on critical threats. Requires force=true for medium/high risk or to overwrite existing skills.",
    {
      githubUrl: z.string().url().describe("GitHub URL (https://github.com/user/repo/tree/branch/path)"),
      name: z.string().min(1).max(64).optional().describe("Skill name (inferred from URL if omitted)"),
      force: z.boolean().default(false).describe("Force install: skip medium/high risk block, overwrite existing"),
    },
    async ({ githubUrl, name, force }) => {
      try {
        const result = await installSkill(githubUrl, name, force);

        // Update skill registry
        const skillName = result.installPath.split("/").pop();
        if (skillName) {
          try {
            await skillManager.scanLocalSkill(skillName);
          } catch {
            // Non-fatal — registry will catch up on next sync
          }
        }

        const lines = [
          `## Skill Installed Successfully`,
          "",
          `- **Path**: \`${result.installPath}\``,
          `- **Files**: ${result.filesCount}`,
          `- **Content Hash**: \`${result.contentHash.substring(0, 16)}...\``,
          `- **SKILL.md**: ${result.hasSkillMd ? "Found" : "Missing (skill may not load)"}`,
          `- **Security**: ${result.scanSummary}`,
        ];
        if (result.npmInstalled) {
          lines.push(`- **npm install**: Completed (--ignore-scripts)`);
        }
        if (result.warnings.length > 0) {
          lines.push("", "### Warnings");
          for (const w of result.warnings) {
            lines.push(`- ${w}`);
          }
        }
        lines.push("", "Restart Claude Code to load the new skill.");
        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        const msg = error instanceof Error ? error.message : "Unknown error";
        return { content: [{ type: "text", text: `Install failed: ${msg}` }], isError: true };
      }
    }
  );

  // 6. Uninstall skill
  server.tool(
    "skillsmp_uninstall_skill",
    "Remove an installed skill from ~/.claude/skills/ by name.",
    {
      name: z.string().min(1).max(64).describe("Name of the skill directory to remove"),
    },
    async ({ name }) => {
      try {
        const result = await uninstallSkill(name);
        skillManager.removeSkill(name);
        return {
          content: [{
            type: "text",
            text: `## Skill Uninstalled\n\n- **Removed**: \`${result.removedPath}\`\n\n${result.message} Restart Claude Code to apply changes.`,
          }],
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : "Unknown error";
        return { content: [{ type: "text", text: `Uninstall failed: ${msg}` }], isError: true };
      }
    }
  );

  // 7. List installed skills
  server.tool(
    "skillsmp_list_installed",
    "List all installed skills with security status. Discovers skills in ~/.claude/skills/ and shows their risk levels from the last security scan.",
    {
      refresh: z.boolean().default(false).describe("Force re-sync before listing (re-scans all skills)"),
    },
    async ({ refresh }) => {
      try {
        if (refresh) {
          const sync = await skillManager.syncRegistry();
          const syncLines: string[] = [];
          if (sync.added.length > 0) syncLines.push(`**Added**: ${sync.added.join(", ")}`);
          if (sync.removed.length > 0) syncLines.push(`**Removed**: ${sync.removed.join(", ")}`);
          if (sync.modified.length > 0) syncLines.push(`**Modified**: ${sync.modified.join(", ")}`);
          if (syncLines.length > 0) {
            syncLines.unshift("### Sync Changes\n");
            syncLines.push("");
          }
        }

        const summary = skillManager.getSummary();

        if (summary.total === 0) {
          const notReady = !skillManager.initialized
            ? "\n\n> Skill scanning is still in progress. Try again with `refresh: true` in a moment."
            : "";
          return {
            content: [{
              type: "text",
              text: `## Installed Skills\n\nNo skills found in \`~/.claude/skills/\`.${notReady}`,
            }],
          };
        }

        const riskEmoji: Record<string, string> = {
          safe: "\\u2705", low: "\\uD83D\\uDFE1", medium: "\\uD83D\\uDFE0", high: "\\uD83D\\uDD34", critical: "\\uD83D\\uDEAB",
        };

        const lines = [
          `## Installed Skills (${summary.total})`,
          "",
          `| Skill | Risk | Files | SKILL.md | Last Scanned |`,
          `|-------|------|-------|----------|--------------|`,
        ];

        for (const s of summary.skills) {
          const emoji = riskEmoji[s.riskLevel] || "";
          const md = s.hasSkillMd ? "Yes" : "No";
          const scanned = s.lastScanned.split("T")[0];
          lines.push(`| ${s.name} | ${emoji} ${s.riskLevel.toUpperCase()} | ${s.filesCount} | ${md} | ${scanned} |`);
        }

        lines.push("");
        const riskSummary = Object.entries(summary.byRisk)
          .filter(([, count]) => count > 0)
          .map(([level, count]) => `${level}: ${count}`)
          .join(", ");
        lines.push(`**Risk Summary**: ${riskSummary || "none"}`);

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `List failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 8. Audit a specific installed skill
  server.tool(
    "skillsmp_audit_installed",
    "Deep security audit of a specific installed skill. Forces a fresh scan and returns a detailed threat report.",
    {
      name: z.string().min(1).max(64).describe("Name of the installed skill to audit"),
    },
    async ({ name }) => {
      try {
        const skill = await skillManager.scanLocalSkill(name);
        const riskEmoji: Record<string, string> = {
          safe: "\\u2705", low: "\\uD83D\\uDFE1", medium: "\\uD83D\\uDFE0", high: "\\uD83D\\uDD34", critical: "\\uD83D\\uDEAB",
        };

        const lines = [
          `## Security Audit: "${name}"`,
          `**Path**: \`${skill.path}\``,
          `**Risk Level**: ${riskEmoji[skill.scanResult.riskLevel] || ""} ${skill.scanResult.riskLevel.toUpperCase()}`,
          `**Files Scanned**: ${skill.filesCount}`,
          `**Total Size**: ${Math.round(skill.totalSize / 1024)}KB`,
          `**Safe to Use**: ${skill.scanResult.safe ? "Yes" : "NO"}`,
          `**SKILL.md**: ${skill.hasSkillMd ? "Found" : "Missing"}`,
          `**Content Hash (SHA-256)**: \`${skill.contentHash}\``,
          `**Last Scanned**: ${new Date(skill.lastScanned).toISOString()}`,
        ];

        lines.push("", `### Recommendation`, skill.scanResult.recommendation);

        if (skill.scanResult.threats.length > 0) {
          lines.push("", "### Threats Found", "");
          for (const threat of skill.scanResult.threats) {
            const icon = threat.severity === "critical" ? "\\uD83D\\uDEAB" : "\\u26A0\\uFE0F";
            const lineInfo = threat.line ? ` (line ${threat.line})` : "";
            lines.push(`${icon} **${threat.severity.toUpperCase()}** [${threat.category}]${lineInfo}: ${threat.description}`);
          }
        } else {
          lines.push("", "### No Threats Found", "This skill passed all security checks.");
        }

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Audit failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 9. Configure sync subscriptions
  server.tool(
    "skillsync_configure",
    "Manage sync subscriptions and settings. Add/remove search subscriptions, configure sync interval, risk threshold, and conflict policy.",
    {
      action: z.enum(["add", "remove", "list", "set"]).describe("Action: add subscription, remove subscription, list config, or set global options"),
      query: z.string().min(1).max(200).optional().describe("Search query for new subscription (action=add)"),
      authors: z.array(z.string()).optional().describe("Filter by authors (action=add)"),
      tags: z.array(z.string()).optional().describe("Filter by tags (action=add)"),
      limit: z.number().min(1).max(100).optional().describe("Max results per subscription (action=add, default 20)"),
      sortBy: z.enum(["stars", "recent"]).optional().describe("Sort order for subscription (action=add)"),
      subscriptionId: z.string().optional().describe("Subscription ID to remove (action=remove)"),
      syncIntervalHours: z.number().min(0).max(168).optional().describe("Sync interval in hours, 0=manual only (action=set)"),
      maxRiskLevel: z.enum(["safe", "low", "medium"]).optional().describe("Max risk level for auto-install (action=set)"),
      conflictPolicy: z.enum(["skip", "overwrite", "unmanage"]).optional().describe("How to handle locally modified skills (action=set)"),
      autoRemove: z.boolean().optional().describe("Auto-remove skills no longer in subscriptions (action=set)"),
      enabled: z.boolean().optional().describe("Enable/disable sync engine (action=set)"),
    },
    async ({ action, query, authors, tags, limit, sortBy, subscriptionId, syncIntervalHours, maxRiskLevel, conflictPolicy, autoRemove, enabled }) => {
      try {
        if (action === "add") {
          if (!query) {
            return { content: [{ type: "text", text: "Missing required `query` parameter for add action." }], isError: true };
          }
          const { config, subscription } = await addSubscription({ query, authors, tags, limit, sortBy });
          const lines = [
            `## Subscription Added`,
            "",
            `- **ID**: \`${subscription.id}\``,
            `- **Query**: "${sanitizeText(query)}"`,
          ];
          if (authors?.length) lines.push(`- **Authors**: ${authors.join(", ")}`);
          if (tags?.length) lines.push(`- **Tags**: ${tags.join(", ")}`);
          if (limit) lines.push(`- **Limit**: ${limit}`);
          if (sortBy) lines.push(`- **Sort**: ${sortBy}`);
          lines.push("", `Total subscriptions: ${config.subscriptions.length}`);
          return { content: [{ type: "text", text: lines.join("\n") }] };
        }

        if (action === "remove") {
          if (!subscriptionId) {
            return { content: [{ type: "text", text: "Missing required `subscriptionId` parameter for remove action." }], isError: true };
          }
          const { config, removed } = await removeSubscription(subscriptionId);
          if (!removed) {
            return { content: [{ type: "text", text: `Subscription \`${subscriptionId}\` not found.` }], isError: true };
          }
          return { content: [{ type: "text", text: `## Subscription Removed\n\nID: \`${subscriptionId}\`\nRemaining subscriptions: ${config.subscriptions.length}` }] };
        }

        if (action === "set") {
          const partial: Record<string, unknown> = {};
          if (syncIntervalHours !== undefined) partial.syncIntervalHours = syncIntervalHours;
          if (maxRiskLevel !== undefined) partial.maxRiskLevel = maxRiskLevel;
          if (conflictPolicy !== undefined) partial.conflictPolicy = conflictPolicy;
          if (autoRemove !== undefined) partial.autoRemove = autoRemove;
          if (enabled !== undefined) partial.enabled = enabled;

          if (Object.keys(partial).length === 0) {
            return { content: [{ type: "text", text: "No settings provided to update. Use parameters like `syncIntervalHours`, `maxRiskLevel`, etc." }], isError: true };
          }

          const config = await mergeSyncConfig(partial as any);

          // Restart periodic sync if interval changed
          if (syncIntervalHours !== undefined) {
            syncEngine.stopPeriodicSync();
            await syncEngine.startPeriodicSync();
          }

          const lines = [
            `## Settings Updated`,
            "",
            `- **Enabled**: ${config.enabled}`,
            `- **Sync Interval**: ${config.syncIntervalHours}h (0=manual)`,
            `- **Max Risk**: ${config.maxRiskLevel}`,
            `- **Conflict Policy**: ${config.conflictPolicy}`,
            `- **Auto-Remove**: ${config.autoRemove}`,
            `- **Subscriptions**: ${config.subscriptions.length}`,
          ];
          return { content: [{ type: "text", text: lines.join("\n") }] };
        }

        // action === "list"
        const config = await readSyncConfig();
        const lines = [
          `## SkillSync Configuration`,
          "",
          `- **Enabled**: ${config.enabled}`,
          `- **Sync Interval**: ${config.syncIntervalHours}h (0=manual only)`,
          `- **Max Risk Level**: ${config.maxRiskLevel}`,
          `- **Conflict Policy**: ${config.conflictPolicy}`,
          `- **Auto-Remove**: ${config.autoRemove}`,
          "",
        ];

        if (config.subscriptions.length === 0) {
          lines.push("### Subscriptions\n\nNo subscriptions configured. Use `action: \"add\"` to create one.");
        } else {
          lines.push("### Subscriptions", "", "| # | Query | Authors | Tags | Limit | Sort | Enabled | ID |", "|---|-------|---------|------|-------|------|---------|-----|");
          config.subscriptions.forEach((sub, i) => {
            lines.push(`| ${i + 1} | ${sanitizeText(sub.query)} | ${sub.authors?.join(", ") || "-"} | ${sub.tags?.join(", ") || "-"} | ${sub.limit ?? 20} | ${sub.sortBy ?? "stars"} | ${sub.enabled !== false ? "Yes" : "No"} | \`${sub.id.substring(0, 8)}...\` |`);
          });
        }

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Configure failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 10. Run sync now
  server.tool(
    "skillsync_sync_now",
    "Run a sync cycle: poll subscriptions, diff against installed skills, install/update/remove. Use dryRun=true to preview without changes.",
    {
      dryRun: z.boolean().default(false).describe("Preview changes without executing (default false)"),
    },
    async ({ dryRun }) => {
      try {
        const report = await syncEngine.sync({ dryRun });
        const lines = [
          `## Sync ${dryRun ? "Preview (Dry Run)" : "Complete"}`,
          "",
          `- **Started**: ${report.startedAt}`,
          `- **Finished**: ${report.finishedAt}`,
          `- **Discovered**: ${report.totalDiscovered} skills`,
          `- **Installed**: ${report.installed}`,
          `- **Updated**: ${report.updated}`,
          `- **Removed**: ${report.removed}`,
          `- **Skipped**: ${report.skipped}`,
          `- **Errors**: ${report.errors}`,
        ];

        if (report.actions.length > 0) {
          const emoji: Record<string, string> = {
            install: "+", update: "~", remove: "-",
            "skip-conflict": "!", "skip-risk": "!", unmanage: "x", error: "E",
          };
          lines.push("", "### Actions", "", "| # | Type | Skill | Reason |", "|---|------|-------|--------|");
          report.actions.forEach((a, i) => {
            const icon = emoji[a.type] || "?";
            lines.push(`| ${i + 1} | [${icon}] ${a.type} | ${sanitizeText(a.skillName) || "-"} | ${sanitizeText(a.reason)} |`);
          });
        } else {
          lines.push("", "No actions needed — everything is in sync.");
        }

        if (dryRun && report.actions.some((a) => a.type === "install" || a.type === "update" || a.type === "remove")) {
          lines.push("", "> This was a dry run. Call `skillsync_sync_now` with `dryRun: false` to apply changes.");
        }

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Sync failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 11. Sync status
  server.tool(
    "skillsync_status",
    "Show sync engine status: managed vs manual skills, subscriptions, last sync time, next scheduled sync.",
    {},
    async () => {
      try {
        const status = await syncEngine.getStatus();
        const lock = await readSyncLock();
        const allSkills = skillManager.getAllSkills();
        const managedNames = new Set(Object.keys(lock.skills));
        const manualSkills = allSkills.filter((s) => !managedNames.has(s.name));

        const lines = [
          `## SkillSync Status`,
          "",
          `- **Enabled**: ${status.enabled}`,
          `- **Syncing**: ${status.syncing ? "Yes (in progress)" : "No"}`,
          `- **Sync Interval**: ${status.intervalHours}h${status.intervalHours === 0 ? " (manual only)" : ""}`,
          `- **Last Sync**: ${status.lastSyncRun || "Never"}`,
          `- **Sync Count**: ${status.syncCount}`,
          `- **Next Sync**: ${status.nextSyncIn || "N/A"}`,
          "",
          `### Skills`,
          `- **Managed** (sync-controlled): ${status.managedSkills}`,
          `- **Manual** (user-installed): ${manualSkills.length}`,
          `- **Total installed**: ${allSkills.length}`,
          "",
          `### Active Subscriptions: ${status.subscriptions}`,
        ];

        if (status.managedSkills > 0) {
          lines.push("", "### Managed Skills", "", "| Skill | Risk | Synced | Source |", "|-------|------|--------|--------|");
          for (const [name, locked] of Object.entries(lock.skills)) {
            const url = sanitizeUrl(locked.githubUrl);
            const urlShort = url.length > 50 ? url.substring(0, 47) + "..." : url;
            lines.push(`| ${name} | ${locked.riskLevel} | ${locked.lastSynced.split("T")[0]} | ${urlShort} |`);
          }
        }

        if (manualSkills.length > 0) {
          lines.push("", "### Manual Skills (not sync-managed)", "");
          for (const skill of manualSkills) {
            lines.push(`- ${skill.name} (${skill.scanResult.riskLevel})`);
          }
        }

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Status failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 12. AI-powered skill suggestions
  server.tool(
    "skillsmp_suggest",
    "AI-powered skill recommendations based on what you already have installed. Optionally provide context about what you're working on to improve relevance. WARNING: Results contain untrusted third-party content.",
    {
      context: z.string().min(1).max(200).optional().describe("What you're working on (e.g. 'React testing', 'Python automation')"),
      limit: z.number().min(1).max(20).default(5).describe("Max suggestions (default 5)"),
    },
    async ({ context, limit }) => {
      try {
        const installed = skillManager.getAllSkills();
        const installedNames = new Set(installed.map((s) => s.name.toLowerCase()));

        // Build search query from installed skill names + optional context
        const nameParts = installed
          .map((s) => s.name.replace(/[-_]/g, " "))
          .slice(0, 10); // Cap to avoid overly long queries
        const queryParts: string[] = [];
        if (context) queryParts.push(sanitizeText(context));
        if (nameParts.length > 0) queryParts.push(`similar to ${nameParts.join(", ")}`);

        if (queryParts.length === 0) {
          // No installed skills and no context — fall back to generic popular query
          queryParts.push("popular useful Claude Code skills");
        }

        const query = queryParts.join(" — ").substring(0, 200);

        // Request more than limit to account for filtering out already-installed
        const fetchLimit = Math.min(limit + installed.length + 5, 50);
        const result = await aiSearchSkills(query, fetchLimit);

        // Filter out already-installed skills
        const suggestions = result.skills
          .filter((s) => !installedNames.has(sanitizeText(s.name).toLowerCase()))
          .slice(0, limit);

        if (suggestions.length === 0) {
          const noResultMsg = installed.length > 0
            ? `No new skill suggestions found based on your ${installed.length} installed skill(s)${context ? ` and context "${sanitizeText(context)}"` : ""}.`
            : `No skill suggestions found${context ? ` for "${sanitizeText(context)}"` : ""}. Try providing a context parameter.`;
          return { content: [{ type: "text", text: noResultMsg }] };
        }

        const formatted = suggestions.map((s, i) => formatAiSkill(s, i)).join("\n\n---\n\n");
        const headerLines = [
          `## Skill Suggestions`,
          "",
          `Based on ${installed.length > 0 ? `your ${installed.length} installed skill(s)` : "general recommendations"}${context ? ` and context: "${sanitizeText(context)}"` : ""}.`,
          `**${suggestions.length}** suggestion(s)`,
        ];
        const header = headerLines.join("\n") + "\n";
        return { content: [{ type: "text", text: header + UNTRUSTED_DISCLAIMER + "---\n\n" + formatted }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Suggest failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );

  // 13. Side-by-side skill comparison
  server.tool(
    "skillsmp_compare",
    "Side-by-side comparison of two skills including security scan results. Accepts GitHub URLs or installed skill names.",
    {
      skillA: z.string().min(1).max(200).describe("GitHub URL or installed skill name for first skill"),
      skillB: z.string().min(1).max(200).describe("GitHub URL or installed skill name for second skill"),
    },
    async ({ skillA, skillB }) => {
      try {
        const resolveSkill = async (
          input: string
        ): Promise<{
          name: string;
          riskLevel: string;
          filesCount: number;
          hasSkillMd: boolean;
          threatCount: number;
          threatCategories: string[];
          safe: boolean;
          source: string;
        }> => {
          const sanitized = sanitizeText(input);

          // Case 1: GitHub URL
          if (input.startsWith("https://")) {
            const scanResult = await fetchAndScanSkill(input);
            // Derive a name from the URL
            const urlParts = input.replace(/\/+$/, "").split("/");
            const name = sanitizeText(urlParts[urlParts.length - 1] || "unknown");
            const categories = [
              ...new Set(scanResult.threats.map((t) => t.category)),
            ];
            return {
              name,
              riskLevel: scanResult.riskLevel,
              filesCount: scanResult.filesScanned,
              hasSkillMd: false, // Cannot determine from remote scan
              threatCount: scanResult.threats.length,
              threatCategories: categories,
              safe: scanResult.safe,
              source: sanitizeUrl(input),
            };
          }

          // Case 2: Installed skill name
          const local = skillManager.getSkill(input);
          if (local) {
            const categories = [
              ...new Set(local.scanResult.threats.map((t) => t.category)),
            ];
            return {
              name: local.name,
              riskLevel: local.scanResult.riskLevel,
              filesCount: local.filesCount,
              hasSkillMd: local.hasSkillMd,
              threatCount: local.scanResult.threats.length,
              threatCategories: categories,
              safe: local.scanResult.safe,
              source: "installed locally",
            };
          }

          // Case 3: Search marketplace by name
          const searchResult = await searchSkills(input, 1);
          if (searchResult.skills.length > 0 && searchResult.skills[0].githubUrl) {
            const skill = searchResult.skills[0];
            const scanResult = await fetchAndScanSkill(skill.githubUrl);
            const categories = [
              ...new Set(scanResult.threats.map((t) => t.category)),
            ];
            return {
              name: sanitizeText(skill.name),
              riskLevel: scanResult.riskLevel,
              filesCount: scanResult.filesScanned,
              hasSkillMd: false,
              threatCount: scanResult.threats.length,
              threatCategories: categories,
              safe: scanResult.safe,
              source: sanitizeUrl(skill.githubUrl),
            };
          }

          throw new Error(`Could not find skill "${sanitized}". Provide a GitHub URL or an installed skill name.`);
        };

        const [a, b] = await Promise.all([resolveSkill(skillA), resolveSkill(skillB)]);

        const riskEmoji: Record<string, string> = {
          safe: "✅", low: "🟡", medium: "🟠", high: "🔴", critical: "🚫",
        };

        // Build recommendation
        const recommendSkill = (
          s: typeof a
        ): string => {
          if (!s.safe) return "Not recommended";
          if (s.riskLevel === "safe") return "Safe to use";
          return "Use with caution";
        };

        const lines = [
          `## Skill Comparison`,
          "",
          `| Property | ${a.name} | ${b.name} |`,
          `|----------|---------|---------|`,
          `| **Source** | ${a.source} | ${b.source} |`,
          `| **Risk Level** | ${riskEmoji[a.riskLevel] || ""} ${a.riskLevel.toUpperCase()} | ${riskEmoji[b.riskLevel] || ""} ${b.riskLevel.toUpperCase()} |`,
          `| **Files** | ${a.filesCount} | ${b.filesCount} |`,
          `| **Threats** | ${a.threatCount} | ${b.threatCount} |`,
          `| **Threat Categories** | ${a.threatCategories.join(", ") || "None"} | ${b.threatCategories.join(", ") || "None"} |`,
          `| **SKILL.md** | ${a.hasSkillMd ? "Yes" : "No / Unknown"} | ${b.hasSkillMd ? "Yes" : "No / Unknown"} |`,
          `| **Safe** | ${a.safe ? "Yes" : "No"} | ${b.safe ? "Yes" : "No"} |`,
          `| **Recommendation** | ${recommendSkill(a)} | ${recommendSkill(b)} |`,
        ];

        // Summary
        if (a.riskLevel === b.riskLevel) {
          lines.push("", `Both skills have the same risk level (**${a.riskLevel.toUpperCase()}**).`);
        } else {
          const RISK_ORDER: Record<string, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
          const safer = (RISK_ORDER[a.riskLevel] ?? 5) <= (RISK_ORDER[b.riskLevel] ?? 5) ? a : b;
          lines.push("", `**${safer.name}** has a lower risk level and may be the safer choice.`);
        }

        lines.push("", "---", "**Note**: Comparison is based on point-in-time scans. Repository contents may change.");

        return { content: [{ type: "text", text: lines.join("\n") }] };
      } catch (error) {
        return { content: [{ type: "text", text: `Compare failed: ${error instanceof Error ? error.message : "Unknown error"}` }], isError: true };
      }
    }
  );
}
