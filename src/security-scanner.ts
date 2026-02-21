import { createHash } from "node:crypto";
import {
  CRITICAL_PATTERNS,
  CRITICAL_MULTILINE_PATTERNS,
  WARNING_PATTERNS,
} from "./patterns.js";
import {
  MAX_FILES,
  MAX_FILE_SIZE,
  MAX_TOTAL_SIZE,
  MAX_LINE_LENGTH,
  ALLOWED_GITHUB_HOSTS,
  BINARY_EXTENSIONS,
  SUSPICIOUS_FILENAMES,
  TEXT_EXTENSIONS,
} from "./constants.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Threat {
  pattern: string;
  severity: "warning" | "critical";
  description: string;
  line?: number;
  category: string;
}

export interface ScanResult {
  safe: boolean;
  riskLevel: "safe" | "low" | "medium" | "high" | "critical";
  threats: Threat[];
  recommendation: string;
  contentHash: string;
}

export interface FetchScanResult extends ScanResult {
  filesScanned: number;
  skippedBinary: string[];
  skippedSuspicious: string[];
  errors: string[];
}

// ─── Content Scanner ─────────────────────────────────────────────────────────

function computeHash(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

export function scanSkillContent(content: string): ScanResult {
  const threats: Threat[] = [];
  const lines = content.split("\n");

  // Per-line scanning with ReDoS protection
  for (const patterns of [CRITICAL_PATTERNS, WARNING_PATTERNS]) {
    for (const pattern of patterns) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > MAX_LINE_LENGTH) {
          const alreadyFlagged = threats.some(
            (t) => t.category === "obfuscation" && t.line === i + 1
          );
          if (!alreadyFlagged) {
            threats.push({
              pattern: "excessive-line-length",
              severity: "warning",
              description: `Line is ${line.length} chars — may hide obfuscated content`,
              line: i + 1,
              category: "obfuscation",
            });
          }
          continue; // skip regex on long lines to prevent ReDoS
        }
        if (pattern.regex.test(line)) {
          const alreadyFound = threats.some(
            (t) =>
              t.pattern === pattern.regex.source &&
              t.severity === pattern.severity
          );
          if (!alreadyFound) {
            threats.push({
              pattern: pattern.regex.source,
              severity: pattern.severity,
              description: pattern.description,
              line: i + 1,
              category: pattern.category,
            });
          }
        }
      }
    }
  }

  // Multi-line patterns (full content, capped at 500KB)
  const cappedContent = content.length > 512_000 ? content.substring(0, 512_000) : content;
  for (const pattern of CRITICAL_MULTILINE_PATTERNS) {
    if (pattern.regex.test(cappedContent)) {
      threats.push({
        pattern: pattern.regex.source,
        severity: pattern.severity,
        description: pattern.description,
        category: pattern.category,
      });
    }
  }

  return buildResult(threats, content);
}

function buildResult(threats: Threat[], content: string): ScanResult {
  const criticalCount = threats.filter((t) => t.severity === "critical").length;
  const warningCount = threats.filter((t) => t.severity === "warning").length;

  let riskLevel: ScanResult["riskLevel"];
  if (criticalCount > 0) riskLevel = "critical";
  else if (warningCount >= 5) riskLevel = "high";
  else if (warningCount >= 3) riskLevel = "medium";
  else if (warningCount >= 1) riskLevel = "low";
  else riskLevel = "safe";

  // Stricter safe flag: warnings >= 3 means NOT safe
  const safe = criticalCount === 0 && warningCount < 3;

  return {
    safe,
    riskLevel,
    threats,
    recommendation: buildRecommendation(riskLevel, criticalCount, warningCount),
    contentHash: computeHash(content),
  };
}

function buildRecommendation(
  riskLevel: ScanResult["riskLevel"],
  criticalCount: number,
  warningCount: number,
  filesScanned?: number
): string {
  const suffix = filesScanned !== undefined ? ` across ${filesScanned} files` : "";
  switch (riskLevel) {
    case "critical":
      return `BLOCKED: ${criticalCount} critical threat(s) found${suffix}. Do NOT install this skill.`;
    case "high":
      return `HIGH RISK: ${warningCount} suspicious patterns detected${suffix}. Manual review strongly recommended.`;
    case "medium":
      return `MODERATE RISK: ${warningCount} patterns flagged${suffix}. Review flagged lines before installing. Not considered safe.`;
    case "low":
      return `LOW RISK: ${warningCount} minor concern(s)${suffix}. Likely safe but review flagged items.`;
    default:
      return `No threats detected${suffix}. This skill appears safe to use.`;
  }
}

// ─── GitHub URL Validation (SSRF Prevention) ─────────────────────────────────

export interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  ref: string;
  path: string;
}

export function validateGithubUrl(url: string): ParsedGitHubUrl | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  // Strict domain allowlist
  if (!ALLOWED_GITHUB_HOSTS.includes(parsed.hostname)) return null;
  if (parsed.protocol !== "https:") return null;

  const match = parsed.pathname.match(
    /^\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/tree\/([A-Za-z0-9_.\-/]+?)\/(.+)$/
  );
  if (!match) return null;

  return { owner: match[1], repo: match[2], ref: match[3], path: match[4] };
}

// ─── GitHub Fetch + Scan ─────────────────────────────────────────────────────

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "raw.githubusercontent.com",
  "github.com",
  "objects.githubusercontent.com",
]);

export async function fetchAndScanSkill(githubUrl: string): Promise<FetchScanResult> {
  const parsed = validateGithubUrl(githubUrl);
  if (!parsed) {
    return {
      safe: false,
      riskLevel: "high",
      threats: [{
        pattern: "invalid-url",
        severity: "critical",
        description: `URL rejected. Only https://github.com/owner/repo/tree/ref/path is accepted. Got: ${githubUrl.substring(0, 120)}`,
        category: "ssrf-prevention",
      }],
      recommendation: "Invalid or non-GitHub URL. Only github.com is accepted (SSRF prevention).",
      contentHash: "",
      filesScanned: 0,
      skippedBinary: [],
      skippedSuspicious: [],
      errors: [],
    };
  }

  const apiUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/${parsed.path}?ref=${parsed.ref}`;
  const allContent: string[] = [];
  const allThreats: Threat[] = [];
  const skippedBinary: string[] = [];
  const skippedSuspicious: string[] = [];
  const errors: string[] = [];
  let filesScanned = 0;
  let totalSize = 0;

  try {
    const dirResp = await fetch(apiUrl, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "skillsmp-mcp-scanner/1.0",
      },
    });

    if (!dirResp.ok) {
      // Try as single file
      const rawUrl = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${parsed.ref}/${parsed.path}`;
      const rawResp = await fetch(rawUrl);
      if (!rawResp.ok) {
        return {
          safe: false, riskLevel: "medium",
          threats: [{ pattern: "fetch-failed", severity: "warning", description: `GitHub API returned HTTP ${dirResp.status}`, category: "fetch-error" }],
          recommendation: "Could not fetch skill. Verify the URL and repository visibility.",
          contentHash: "", filesScanned: 0, skippedBinary: [], skippedSuspicious: [], errors: [],
        };
      }
      const content = await rawResp.text();
      const result = scanSkillContent(content);
      return { ...result, filesScanned: 1, skippedBinary: [], skippedSuspicious: [], errors: [] };
    }

    const body = await dirResp.json();

    // Single file response
    if (!Array.isArray(body)) {
      const content =
        typeof body === "object" && body !== null && "content" in body
          ? Buffer.from((body as { content: string }).content, "base64").toString()
          : JSON.stringify(body);
      const result = scanSkillContent(content);
      return { ...result, filesScanned: 1, skippedBinary: [], skippedSuspicious: [], errors: [] };
    }

    const entries = body as Array<{
      type: string;
      download_url: string | null;
      name: string;
      size?: number;
    }>;

    for (const entry of entries) {
      if (filesScanned >= MAX_FILES) {
        errors.push(`File limit (${MAX_FILES}) reached. ${entries.length - MAX_FILES} files not scanned.`);
        break;
      }

      // Flag suspicious filenames
      if (SUSPICIOUS_FILENAMES.has(entry.name.toLowerCase())) {
        skippedSuspicious.push(entry.name);
        allThreats.push({
          pattern: "suspicious-filename",
          severity: "warning",
          description: `[${entry.name}] Suspicious filename — commonly used in supply chain attacks`,
          category: "supply-chain",
        });
      }

      // Warn about unscanned subdirectories
      if (entry.type === "dir") {
        errors.push(`Subdirectory "${entry.name}" was NOT scanned. Malicious code may hide in subdirectories.`);
        allThreats.push({
          pattern: "unscanned-directory",
          severity: "warning",
          description: `[${entry.name}/] Subdirectory not scanned — could contain hidden threats`,
          category: "incomplete-scan",
        });
        continue;
      }

      if (entry.type !== "file" || !entry.download_url) continue;

      // Detect binary files
      const ext = entry.name.includes(".")
        ? "." + entry.name.split(".").pop()!.toLowerCase()
        : "";
      if (BINARY_EXTENSIONS.has(ext)) {
        skippedBinary.push(entry.name);
        allThreats.push({
          pattern: "binary-file",
          severity: "warning",
          description: `[${entry.name}] Binary file detected — cannot scan, may contain executable code`,
          category: "binary",
        });
        continue;
      }

      if (!TEXT_EXTENSIONS.has(ext) && ext !== "") {
        skippedBinary.push(entry.name);
        continue;
      }

      // Size guard
      if (entry.size && entry.size > MAX_FILE_SIZE) {
        errors.push(`[${entry.name}] Skipped: ${Math.round(entry.size / 1024)}KB exceeds limit.`);
        allThreats.push({
          pattern: "oversized-file",
          severity: "warning",
          description: `[${entry.name}] File too large (${Math.round(entry.size / 1024)}KB) — possible DoS`,
          category: "dos",
        });
        continue;
      }

      // Validate download host (SSRF prevention on download URLs)
      try {
        const dlHost = new URL(entry.download_url).hostname;
        if (!ALLOWED_DOWNLOAD_HOSTS.has(dlHost)) {
          errors.push(`[${entry.name}] Skipped: download URL on unexpected host ${dlHost}`);
          continue;
        }
      } catch {
        errors.push(`[${entry.name}] Skipped: invalid download URL`);
        continue;
      }

      try {
        const fileResp = await fetch(entry.download_url);
        if (!fileResp.ok) {
          errors.push(`[${entry.name}] Fetch failed: HTTP ${fileResp.status}`);
          continue;
        }
        const content = await fileResp.text();
        totalSize += content.length;
        if (totalSize > MAX_TOTAL_SIZE) {
          errors.push(`Total size limit (${MAX_TOTAL_SIZE / 1024}KB) reached. Remaining files skipped.`);
          break;
        }
        allContent.push(content);
        const result = scanSkillContent(content);
        for (const t of result.threats) {
          allThreats.push({ ...t, description: `[${entry.name}] ${t.description}` });
        }
        filesScanned++;
      } catch (err) {
        errors.push(`[${entry.name}] Error: ${err instanceof Error ? err.message : "unknown"}`);
      }
    }

    const combinedHash = computeHash(allContent.join("\n---FILE-BOUNDARY---\n"));
    const criticalCount = allThreats.filter((t) => t.severity === "critical").length;
    const warningCount = allThreats.filter((t) => t.severity === "warning").length;

    let riskLevel: ScanResult["riskLevel"];
    if (criticalCount > 0) riskLevel = "critical";
    else if (warningCount >= 5) riskLevel = "high";
    else if (warningCount >= 3) riskLevel = "medium";
    else if (warningCount >= 1) riskLevel = "low";
    else riskLevel = "safe";

    return {
      safe: criticalCount === 0 && warningCount < 3,
      riskLevel,
      threats: allThreats,
      recommendation: buildRecommendation(riskLevel, criticalCount, warningCount, filesScanned),
      contentHash: combinedHash,
      filesScanned,
      skippedBinary,
      skippedSuspicious,
      errors,
    };
  } catch (error) {
    return {
      safe: false,
      riskLevel: "medium",
      threats: [{ pattern: "network-error", severity: "warning", description: `Network error: ${error instanceof Error ? error.message : "unknown"}`, category: "fetch-error" }],
      recommendation: "Failed to fetch skill content. Check network and URL.",
      contentHash: "",
      filesScanned: 0,
      skippedBinary: [],
      skippedSuspicious: [],
      errors: [],
    };
  }
}
