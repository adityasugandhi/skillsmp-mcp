import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { VALID_SKILL_NAME } from "./constants.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export type SkillScope = "global" | "project";

export interface ResolvedPaths {
  scope: SkillScope;
  skillsDir: string;
  syncConfigPath: string;
  syncLockPath: string;
  label: string;
}

// ─── Path Resolution ─────────────────────────────────────────────────────────

export function resolvePaths(scope: SkillScope): ResolvedPaths {
  if (scope === "project") {
    const cwd = process.cwd();
    const base = join(cwd, ".claude");
    return {
      scope,
      skillsDir: join(base, "skills"),
      syncConfigPath: join(base, "skillsync.json"),
      syncLockPath: join(base, "skillsync.lock"),
      label: `project (${cwd})`,
    };
  }

  // global (default)
  const base = join(homedir(), ".claude");
  return {
    scope,
    skillsDir: join(base, "skills"),
    syncConfigPath: join(base, "skillsync.json"),
    syncLockPath: join(base, "skillsync.lock"),
    label: "global (~/.claude/skills/)",
  };
}

// ─── Shared Safety Utilities ─────────────────────────────────────────────────

export function validateSkillName(name: string): boolean {
  return VALID_SKILL_NAME.test(name);
}

export function safeSkillPath(skillsDir: string, name: string): string {
  const resolved = resolve(join(skillsDir, name));
  const resolvedSkillsDir = resolve(skillsDir);
  if (!resolved.startsWith(resolvedSkillsDir + "/")) {
    throw new Error(`Path traversal detected: "${name}" resolves outside skills directory`);
  }
  return resolved;
}
