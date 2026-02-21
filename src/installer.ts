import { mkdir, rm, readdir, writeFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import {
  SKILLS_DIR,
  VALID_SKILL_NAME,
  MAX_FILES,
  MAX_FILE_SIZE,
  MAX_TOTAL_SIZE,
  BINARY_EXTENSIONS,
  TEXT_EXTENSIONS,
  ALLOWED_GITHUB_HOSTS,
} from "./constants.js";
import {
  fetchAndScanSkill,
  validateGithubUrl,
  type FetchScanResult,
  type ParsedGitHubUrl,
} from "./security-scanner.js";

const execFileAsync = promisify(execFile);

// ─── Types ──────────────────────────────────────────────────────────────────

export interface InstallResult {
  success: boolean;
  installPath: string;
  filesCount: number;
  contentHash: string;
  scanSummary: string;
  hasSkillMd: boolean;
  npmInstalled: boolean;
  warnings: string[];
}

export interface UninstallResult {
  success: boolean;
  removedPath: string;
  message: string;
}

// ─── Path Safety ────────────────────────────────────────────────────────────

function validateSkillName(name: string): boolean {
  return VALID_SKILL_NAME.test(name);
}

function safeSkillPath(name: string): string {
  const resolved = resolve(join(SKILLS_DIR, name));
  const resolvedSkillsDir = resolve(SKILLS_DIR);
  if (!resolved.startsWith(resolvedSkillsDir + "/")) {
    throw new Error(`Path traversal detected: "${name}" resolves outside skills directory`);
  }
  return resolved;
}

function inferSkillName(parsed: ParsedGitHubUrl): string {
  // Use last path segment as name
  const segments = parsed.path.split("/").filter(Boolean);
  return segments[segments.length - 1] || parsed.repo;
}

// ─── Install ────────────────────────────────────────────────────────────────

export async function installSkill(
  githubUrl: string,
  name?: string,
  force?: boolean,
): Promise<InstallResult> {
  const warnings: string[] = [];

  // 1. Validate URL
  const parsed = validateGithubUrl(githubUrl);
  if (!parsed) {
    throw new Error(
      "Invalid GitHub URL. Expected: https://github.com/owner/repo/tree/branch/path"
    );
  }

  // 2. Determine skill name
  const skillName = name || inferSkillName(parsed);
  if (!validateSkillName(skillName)) {
    throw new Error(
      `Invalid skill name "${skillName}". Must be alphanumeric with hyphens/underscores, 1-64 chars.`
    );
  }

  // 3. Check if already installed
  const installPath = safeSkillPath(skillName);
  let exists = false;
  try {
    await stat(installPath);
    exists = true;
  } catch {
    // Directory doesn't exist — good
  }
  if (exists && !force) {
    throw new Error(
      `Skill "${skillName}" already installed at ${installPath}. Use force=true to overwrite.`
    );
  }

  // 4. Security scan
  const scanResult = await fetchAndScanSkill(githubUrl);

  // Block on critical threats — no override
  if (scanResult.riskLevel === "critical") {
    const criticals = scanResult.threats
      .filter((t) => t.severity === "critical")
      .map((t) => `  - [${t.category}] ${t.description}`)
      .join("\n");
    throw new Error(
      `BLOCKED: Critical security threats detected. Cannot install.\n\n${scanResult.recommendation}\n\nCritical threats:\n${criticals}`
    );
  }

  // Warn on medium/high — require force
  if ((scanResult.riskLevel === "high" || scanResult.riskLevel === "medium") && !force) {
    const threatSummary = scanResult.threats
      .map((t) => `  - [${t.severity}/${t.category}] ${t.description}`)
      .join("\n");
    throw new Error(
      `Security scan flagged ${scanResult.riskLevel.toUpperCase()} risk. Use force=true to install anyway.\n\n${scanResult.recommendation}\n\nThreats:\n${threatSummary}`
    );
  }

  if (scanResult.riskLevel === "low") {
    warnings.push(`Security scan: LOW risk — ${scanResult.recommendation}`);
  }

  // 5. Fetch files from GitHub
  const files = await fetchSkillFiles(parsed);

  // 6. Create directory and write files
  if (exists) {
    await rm(installPath, { recursive: true, force: true });
  }
  await mkdir(installPath, { recursive: true });

  let hasSkillMd = false;
  const allContent: string[] = [];

  for (const file of files) {
    const filePath = join(installPath, file.name);
    // Extra path traversal check on individual filenames
    const resolvedFile = resolve(filePath);
    if (!resolvedFile.startsWith(resolve(installPath) + "/") && resolvedFile !== resolve(installPath)) {
      warnings.push(`Skipped "${file.name}": path traversal in filename`);
      continue;
    }
    await writeFile(filePath, file.content, "utf-8");
    allContent.push(file.content);
    if (file.name.toLowerCase() === "skill.md") {
      hasSkillMd = true;
    }
  }

  if (!hasSkillMd) {
    warnings.push("No SKILL.md found. This skill may not be recognized by Claude Code.");
  }

  // 7. Run npm install if package.json exists
  let npmInstalled = false;
  const hasPackageJson = files.some((f) => f.name === "package.json");
  if (hasPackageJson) {
    try {
      await execFileAsync("npm", ["install", "--ignore-scripts"], {
        cwd: installPath,
        timeout: 60_000,
      });
      npmInstalled = true;
    } catch (err) {
      warnings.push(
        `npm install failed: ${err instanceof Error ? err.message : "unknown"}. You may need to run it manually.`
      );
    }
  }

  const contentHash = createHash("sha256")
    .update(allContent.join("\n---FILE-BOUNDARY---\n"))
    .digest("hex");

  return {
    success: true,
    installPath,
    filesCount: files.length,
    contentHash,
    scanSummary: `${scanResult.riskLevel.toUpperCase()} — ${scanResult.recommendation}`,
    hasSkillMd,
    npmInstalled,
    warnings,
  };
}

// ─── Uninstall ──────────────────────────────────────────────────────────────

export async function uninstallSkill(name: string): Promise<UninstallResult> {
  if (!validateSkillName(name)) {
    throw new Error(
      `Invalid skill name "${name}". Must be alphanumeric with hyphens/underscores, 1-64 chars.`
    );
  }

  const skillPath = safeSkillPath(name);

  try {
    await stat(skillPath);
  } catch {
    throw new Error(`Skill "${name}" not found at ${skillPath}`);
  }

  await rm(skillPath, { recursive: true, force: true });

  return {
    success: true,
    removedPath: skillPath,
    message: `Skill "${name}" has been uninstalled.`,
  };
}

// ─── File Fetching ──────────────────────────────────────────────────────────

interface SkillFile {
  name: string;
  content: string;
}

const ALLOWED_DOWNLOAD_HOSTS = new Set([
  "raw.githubusercontent.com",
  "github.com",
  "objects.githubusercontent.com",
]);

async function fetchSkillFiles(parsed: ParsedGitHubUrl): Promise<SkillFile[]> {
  const apiUrl = `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/contents/${parsed.path}?ref=${parsed.ref}`;
  const files: SkillFile[] = [];
  let totalSize = 0;

  const dirResp = await fetch(apiUrl, {
    headers: {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "skillsmp-mcp-installer/1.0",
    },
  });

  if (!dirResp.ok) {
    // Try as single file
    const rawUrl = `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${parsed.ref}/${parsed.path}`;
    const rawResp = await fetch(rawUrl);
    if (!rawResp.ok) {
      throw new Error(`GitHub API returned HTTP ${dirResp.status}. Verify URL and repo visibility.`);
    }
    const content = await rawResp.text();
    const name = parsed.path.split("/").pop() || "file";
    return [{ name, content }];
  }

  const body = await dirResp.json();

  if (!Array.isArray(body)) {
    // Single file via API
    const content =
      typeof body === "object" && body !== null && "content" in body
        ? Buffer.from((body as { content: string }).content, "base64").toString()
        : JSON.stringify(body);
    const name = parsed.path.split("/").pop() || "file";
    return [{ name, content }];
  }

  const entries = body as Array<{
    type: string;
    download_url: string | null;
    name: string;
    size?: number;
  }>;

  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;
    if (entry.type !== "file" || !entry.download_url) continue;

    // Skip binary files
    const ext = entry.name.includes(".")
      ? "." + entry.name.split(".").pop()!.toLowerCase()
      : "";
    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (!TEXT_EXTENSIONS.has(ext) && ext !== "") continue;

    // Size guard
    if (entry.size && entry.size > MAX_FILE_SIZE) continue;

    // Validate download host
    try {
      const dlHost = new URL(entry.download_url).hostname;
      if (!ALLOWED_DOWNLOAD_HOSTS.has(dlHost)) continue;
    } catch {
      continue;
    }

    const fileResp = await fetch(entry.download_url);
    if (!fileResp.ok) continue;

    const content = await fileResp.text();
    totalSize += content.length;
    if (totalSize > MAX_TOTAL_SIZE) break;

    files.push({ name: entry.name, content });
  }

  return files;
}
