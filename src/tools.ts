import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { searchSkills, aiSearchSkills } from "./api-client.js";
import { fetchAndScanSkill } from "./security-scanner.js";
import { installSkill, uninstallSkill } from "./installer.js";
import { sanitizeText, sanitizeUrl } from "./sanitize.js";
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
}
