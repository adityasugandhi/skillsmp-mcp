import { readdir, readFile, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { createHash } from "node:crypto";
import { watch, type FSWatcher } from "node:fs";
import {
  MAX_FILES,
  MAX_FILE_SIZE,
  MAX_TOTAL_SIZE,
  BINARY_EXTENSIONS,
  TEXT_EXTENSIONS,
  WATCH_DEBOUNCE_MS,
} from "./constants.js";
import { scanSkillContent, type ScanResult } from "./security-scanner.js";
import {
  type SkillScope,
  type ResolvedPaths,
  resolvePaths,
  validateSkillName,
  safeSkillPath,
} from "./scope-resolver.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface InstalledSkill {
  name: string;
  path: string;
  filesCount: number;
  totalSize: number;
  hasSkillMd: boolean;
  scanResult: ScanResult;
  contentHash: string;
  lastScanned: number;
  scope: SkillScope;
  scopeLabel: string;
}

export interface SyncSummary {
  added: string[];
  removed: string[];
  modified: string[];
  unchanged: string[];
}

// ─── SkillManager ────────────────────────────────────────────────────────────

export class SkillManager {
  readonly registry = new Map<string, InstalledSkill>();
  initialized = false;
  private watcher: FSWatcher | null = null;
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(readonly paths: ResolvedPaths) {}

  async initialize(): Promise<void> {
    try {
      const names = await this.discoverSkills();
      for (const name of names) {
        try {
          await this.scanLocalSkill(name);
          const skill = this.registry.get(name)!;
          console.error(`[skillsync:${this.paths.scope}] Skill "${name}": ${skill.scanResult.riskLevel.toUpperCase()}`);
        } catch (err) {
          console.error(`[skillsync:${this.paths.scope}] Failed to scan "${name}": ${err instanceof Error ? err.message : "unknown"}`);
        }
      }

      const skills = this.getAllSkills();
      const safe = skills.filter((s) => s.scanResult.riskLevel === "safe").length;
      const warning = skills.filter((s) => ["low", "medium", "high"].includes(s.scanResult.riskLevel)).length;
      const critical = skills.filter((s) => s.scanResult.riskLevel === "critical").length;
      console.error(`[skillsync:${this.paths.scope}] Loaded ${skills.length} skills (${safe} safe, ${warning} warning, ${critical} critical)`);

      this.startWatching();
      this.initialized = true;
    } catch (err) {
      console.error(`[skillsync:${this.paths.scope}] Initialization failed: ${err instanceof Error ? err.message : "unknown"}`);
      this.initialized = true; // Mark initialized even on failure so tools don't hang
    }
  }

  shutdown(): void {
    this.stopWatching();
    this.registry.clear();
    this.initialized = false;
  }

  async discoverSkills(): Promise<string[]> {
    try {
      const entries = await readdir(this.paths.skillsDir, { withFileTypes: true });
      return entries
        .filter((e) => e.isDirectory() && validateSkillName(e.name))
        .map((e) => e.name);
    } catch {
      // Directory doesn't exist or is unreadable
      return [];
    }
  }

  async scanLocalSkill(name: string): Promise<InstalledSkill> {
    if (!validateSkillName(name)) {
      throw new Error(`Invalid skill name: "${name}"`);
    }

    const skillPath = safeSkillPath(this.paths.skillsDir, name);

    // Verify directory exists
    const dirStat = await stat(skillPath);
    if (!dirStat.isDirectory()) {
      throw new Error(`"${name}" is not a directory`);
    }

    const entries = await readdir(skillPath);
    const allContent: string[] = [];
    let filesCount = 0;
    let totalSize = 0;
    let hasSkillMd = false;

    for (const fileName of entries) {
      if (filesCount >= MAX_FILES) break;

      const filePath = join(skillPath, fileName);

      // Only process files (skip subdirectories)
      let fileStat;
      try {
        fileStat = await stat(filePath);
      } catch {
        continue;
      }
      if (!fileStat.isFile()) continue;

      // Skip binary files
      const ext = extname(fileName).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;
      if (!TEXT_EXTENSIONS.has(ext) && ext !== "") continue;

      // Size guard
      if (fileStat.size > MAX_FILE_SIZE) continue;
      if (totalSize + fileStat.size > MAX_TOTAL_SIZE) break;

      try {
        const content = await readFile(filePath, "utf-8");
        allContent.push(content);
        totalSize += content.length;
        filesCount++;

        if (fileName.toLowerCase() === "skill.md") {
          hasSkillMd = true;
        }
      } catch {
        // Skip unreadable files
      }
    }

    const combined = allContent.join("\n---FILE-BOUNDARY---\n");
    const scanResult = scanSkillContent(combined);
    const contentHash = createHash("sha256").update(combined).digest("hex");

    const skill: InstalledSkill = {
      name,
      path: skillPath,
      filesCount,
      totalSize,
      hasSkillMd,
      scanResult,
      contentHash,
      lastScanned: Date.now(),
      scope: this.paths.scope,
      scopeLabel: this.paths.label,
    };

    this.registry.set(name, skill);
    return skill;
  }

  getSkill(name: string): InstalledSkill | undefined {
    return this.registry.get(name);
  }

  getAllSkills(): InstalledSkill[] {
    return Array.from(this.registry.values());
  }

  removeSkill(name: string): boolean {
    return this.registry.delete(name);
  }

  getSummary(): {
    total: number;
    byRisk: Record<string, number>;
    skills: Array<{
      name: string;
      riskLevel: string;
      filesCount: number;
      hasSkillMd: boolean;
      lastScanned: string;
      scope: SkillScope;
    }>;
  } {
    const skills = this.getAllSkills();
    const byRisk: Record<string, number> = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    for (const s of skills) {
      byRisk[s.scanResult.riskLevel] = (byRisk[s.scanResult.riskLevel] || 0) + 1;
    }

    return {
      total: skills.length,
      byRisk,
      skills: skills.map((s) => ({
        name: s.name,
        riskLevel: s.scanResult.riskLevel,
        filesCount: s.filesCount,
        hasSkillMd: s.hasSkillMd,
        lastScanned: new Date(s.lastScanned).toISOString(),
        scope: s.scope,
      })),
    };
  }

  async syncRegistry(): Promise<SyncSummary> {
    const onDisk = new Set(await this.discoverSkills());
    const inRegistry = new Set(this.registry.keys());

    const added: string[] = [];
    const removed: string[] = [];
    const modified: string[] = [];
    const unchanged: string[] = [];

    // Detect removed skills
    for (const name of inRegistry) {
      if (!onDisk.has(name)) {
        this.registry.delete(name);
        removed.push(name);
      }
    }

    // Detect added and modified skills
    for (const name of onDisk) {
      if (!inRegistry.has(name)) {
        // New skill
        try {
          await this.scanLocalSkill(name);
          added.push(name);
          console.error(`[skillsync:${this.paths.scope}] New skill detected: "${name}"`);
        } catch (err) {
          console.error(`[skillsync:${this.paths.scope}] Failed to scan new skill "${name}": ${err instanceof Error ? err.message : "unknown"}`);
        }
      } else {
        // Existing skill — check for modifications via hash
        const existing = this.registry.get(name)!;
        try {
          const fresh = await this.scanLocalSkill(name);
          if (fresh.contentHash !== existing.contentHash) {
            modified.push(name);
            console.error(`[skillsync:${this.paths.scope}] Skill modified: "${name}"`);
          } else {
            unchanged.push(name);
          }
        } catch {
          unchanged.push(name);
        }
      }
    }

    return { added, removed, modified, unchanged };
  }

  startWatching(): void {
    try {
      this.watcher = watch(this.paths.skillsDir, { persistent: false }, () => {
        // Debounce rapid events
        if (this.debounceTimer) clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
          this.syncRegistry().catch((err) => {
            console.error(`[skillsync:${this.paths.scope}] Sync error: ${err instanceof Error ? err.message : "unknown"}`);
          });
        }, WATCH_DEBOUNCE_MS);
      });

      this.watcher.on("error", (err) => {
        console.error(`[skillsync:${this.paths.scope}] Watch error: ${err.message}`);
      });
    } catch {
      // Directory may not exist yet — that's fine
      console.error(`[skillsync:${this.paths.scope}] Could not watch skills directory (may not exist yet)`);
    }
  }

  stopWatching(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

const managers = new Map<string, SkillManager>();

export function getSkillManager(scope: SkillScope = "global"): SkillManager {
  const paths = resolvePaths(scope);
  const key = paths.skillsDir;
  let mgr = managers.get(key);
  if (!mgr) {
    mgr = new SkillManager(paths);
    managers.set(key, mgr);
  }
  return mgr;
}

export function getAllManagers(): SkillManager[] {
  return Array.from(managers.values());
}

export function shutdownAllManagers(): void {
  managers.forEach((m) => m.shutdown());
  managers.clear();
}

// ─── Backward Compatibility ──────────────────────────────────────────────────

export const skillManager = getSkillManager("global");
