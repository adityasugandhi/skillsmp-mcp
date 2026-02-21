import { searchSkills, type SkillResult } from "./api-client.js";
import { installSkill, uninstallSkill } from "./installer.js";
import { skillManager } from "./skill-manager.js";
import { readSyncConfig, type SyncConfig, type SyncSubscription } from "./sync-config.js";
import { readSyncLock, writeSyncLock, isSyncManaged, type SyncLockFile, type LockedSkill } from "./sync-lock.js";
import { SYNC_API_DELAY_MS, RISK_LEVEL_ORDER } from "./constants.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SyncAction {
  type: "install" | "update" | "remove" | "skip-conflict" | "skip-risk" | "unmanage" | "error";
  skillName: string;
  githubUrl: string;
  reason: string;
  riskLevel?: string;
}

export interface SyncReport {
  startedAt: string;
  finishedAt: string;
  totalDiscovered: number;
  actions: SyncAction[];
  installed: number;
  updated: number;
  removed: number;
  skipped: number;
  errors: number;
  dryRun: boolean;
}

export interface SyncStatus {
  enabled: boolean;
  syncing: boolean;
  lastSyncRun: string | null;
  syncCount: number;
  managedSkills: number;
  subscriptions: number;
  nextSyncIn: string | null;
  intervalHours: number;
}

// ─── Discovered Skill (from API) ─────────────────────────────────────────────

interface DiscoveredSkill {
  skill: SkillResult;
  subIds: string[];
  inferredName: string;
}

// ─── Diff Result ─────────────────────────────────────────────────────────────

export interface SyncDiffResult {
  toInstall: Array<{ name: string; githubUrl: string; subIds: string[]; updatedAt: string }>;
  toUpdate: Array<{ name: string; githubUrl: string; subIds: string[]; updatedAt: string }>;
  toRemove: Array<{ name: string; githubUrl: string }>;
  conflicts: Array<{ name: string; githubUrl: string; reason: string }>;
}

// ─── Pure Diff Function (testable without network) ───────────────────────────

export function computeSyncDiff(
  discovered: Map<string, DiscoveredSkill>,
  lock: SyncLockFile,
  config: SyncConfig,
): SyncDiffResult {
  const toInstall: SyncDiffResult["toInstall"] = [];
  const toUpdate: SyncDiffResult["toUpdate"] = [];
  const toRemove: SyncDiffResult["toRemove"] = [];
  const conflicts: SyncDiffResult["conflicts"] = [];

  const maxRisk = RISK_LEVEL_ORDER[config.maxRiskLevel] ?? 1;

  // Check discovered skills against lock
  for (const [githubUrl, disc] of discovered) {
    const locked = Object.values(lock.skills).find((s) => s.githubUrl === githubUrl);

    const updatedAt = String(disc.skill.updatedAt);

    if (!locked) {
      // New skill — schedule install
      toInstall.push({ name: disc.inferredName, githubUrl, subIds: disc.subIds, updatedAt });
    } else {
      // Existing — check for upstream changes via updatedAt
      if (updatedAt !== locked.upstreamUpdatedAt) {
        // Check local modification (conflict detection)
        const localSkill = skillManager.getSkill(locked.name);
        if (localSkill && localSkill.contentHash !== locked.installedHash) {
          // Local was modified after install
          if (config.conflictPolicy === "skip") {
            conflicts.push({
              name: locked.name,
              githubUrl,
              reason: "Locally modified — skipped (conflict policy: skip)",
            });
          } else if (config.conflictPolicy === "overwrite") {
            toUpdate.push({ name: locked.name, githubUrl, subIds: disc.subIds, updatedAt });
          } else {
            // unmanage
            conflicts.push({
              name: locked.name,
              githubUrl,
              reason: "Locally modified — unmanaged (conflict policy: unmanage)",
            });
          }
        } else {
          toUpdate.push({ name: locked.name, githubUrl, subIds: disc.subIds, updatedAt });
        }
      }
    }
  }

  // Check for skills in lock that are no longer discovered (removal candidates)
  if (config.autoRemove) {
    const discoveredUrls = new Set(discovered.keys());
    for (const [name, locked] of Object.entries(lock.skills)) {
      if (!discoveredUrls.has(locked.githubUrl)) {
        toRemove.push({ name, githubUrl: locked.githubUrl });
      }
    }
  }

  return { toInstall, toUpdate, toRemove, conflicts };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function inferNameFromUrl(githubUrl: string): string {
  const segments = githubUrl.replace(/\/+$/, "").split("/").filter(Boolean);
  return segments[segments.length - 1] || "unknown-skill";
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── SyncEngine Class ────────────────────────────────────────────────────────

class SyncEngine {
  private syncing = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastSyncStart: number | null = null;

  async sync(options?: { dryRun?: boolean }): Promise<SyncReport> {
    const dryRun = options?.dryRun ?? false;

    if (this.syncing) {
      return {
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        totalDiscovered: 0,
        actions: [{ type: "error", skillName: "", githubUrl: "", reason: "Sync already in progress" }],
        installed: 0, updated: 0, removed: 0, skipped: 0, errors: 1,
        dryRun,
      };
    }

    this.syncing = true;
    this.lastSyncStart = Date.now();
    const startedAt = new Date().toISOString();
    const actions: SyncAction[] = [];

    try {
      const config = await readSyncConfig();

      if (!config.enabled) {
        this.syncing = false;
        return {
          startedAt, finishedAt: new Date().toISOString(),
          totalDiscovered: 0, actions: [], installed: 0, updated: 0, removed: 0, skipped: 0, errors: 0,
          dryRun,
        };
      }

      const activeSubscriptions = config.subscriptions.filter((s) => s.enabled !== false);
      if (activeSubscriptions.length === 0) {
        this.syncing = false;
        return {
          startedAt, finishedAt: new Date().toISOString(),
          totalDiscovered: 0, actions: [], installed: 0, updated: 0, removed: 0, skipped: 0, errors: 0,
          dryRun,
        };
      }

      // Phase 1: Discover skills from all subscriptions
      const discovered = new Map<string, DiscoveredSkill>();

      for (const sub of activeSubscriptions) {
        try {
          const result = await searchSkills(sub.query, sub.limit ?? 20, sub.sortBy ?? "stars");

          for (const skill of result.skills) {
            if (!skill.githubUrl) continue;

            // Filter by authors if specified
            if (sub.authors && sub.authors.length > 0) {
              if (!sub.authors.some((a) => skill.author?.toLowerCase() === a.toLowerCase())) {
                continue;
              }
            }

            // Filter by tags if specified
            if (sub.tags && sub.tags.length > 0) {
              if (!skill.tags || !sub.tags.some((t) => skill.tags!.some((st) => st.toLowerCase() === t.toLowerCase()))) {
                continue;
              }
            }

            const existing = discovered.get(skill.githubUrl);
            if (existing) {
              // Deduplicate — merge subscription IDs
              if (!existing.subIds.includes(sub.id)) {
                existing.subIds.push(sub.id);
              }
            } else {
              discovered.set(skill.githubUrl, {
                skill,
                subIds: [sub.id],
                inferredName: inferNameFromUrl(skill.githubUrl),
              });
            }
          }

          // Rate limit between API calls
          if (activeSubscriptions.indexOf(sub) < activeSubscriptions.length - 1) {
            await delay(SYNC_API_DELAY_MS);
          }
        } catch (err) {
          actions.push({
            type: "error",
            skillName: "",
            githubUrl: "",
            reason: `Subscription "${sub.query}" failed: ${err instanceof Error ? err.message : "unknown"}`,
          });
        }
      }

      // Phase 2: Compute diff
      const lock = await readSyncLock();
      const diff = computeSyncDiff(discovered, lock, config);
      const maxRisk = RISK_LEVEL_ORDER[config.maxRiskLevel] ?? 1;

      // Phase 3: Handle conflicts
      for (const conflict of diff.conflicts) {
        if (config.conflictPolicy === "unmanage") {
          actions.push({
            type: "unmanage",
            skillName: conflict.name,
            githubUrl: conflict.githubUrl,
            reason: conflict.reason,
          });
          if (!dryRun) {
            delete lock.skills[conflict.name];
          }
        } else {
          actions.push({
            type: "skip-conflict",
            skillName: conflict.name,
            githubUrl: conflict.githubUrl,
            reason: conflict.reason,
          });
        }
      }

      // Phase 4: Install new skills
      for (const item of diff.toInstall) {
        if (dryRun) {
          actions.push({ type: "install", skillName: item.name, githubUrl: item.githubUrl, reason: "New skill from subscription" });
          continue;
        }

        try {
          const result = await installSkill(item.githubUrl, item.name, false);
          const skillName = result.installPath.split("/").pop() || item.name;

          // Check risk level
          const riskStr = result.scanSummary.split(" ")[0].toLowerCase();
          const riskNum = RISK_LEVEL_ORDER[riskStr] ?? 0;
          if (riskNum > maxRisk) {
            // Undo install — too risky
            try { await uninstallSkill(skillName); } catch { /* best effort */ }
            actions.push({
              type: "skip-risk",
              skillName,
              githubUrl: item.githubUrl,
              reason: `Risk level ${riskStr} exceeds max ${config.maxRiskLevel}`,
              riskLevel: riskStr,
            });
            continue;
          }

          // Update skill manager registry
          try { await skillManager.scanLocalSkill(skillName); } catch { /* non-fatal */ }

          // Update lock
          lock.skills[skillName] = {
            name: skillName,
            githubUrl: item.githubUrl,
            installedHash: result.contentHash,
            upstreamHash: result.contentHash,
            subscriptionIds: item.subIds,
            lastSynced: new Date().toISOString(),
            installedAt: new Date().toISOString(),
            riskLevel: riskStr,
            filesCount: result.filesCount,
            hasSkillMd: result.hasSkillMd,
            upstreamUpdatedAt: item.updatedAt,
          };

          actions.push({
            type: "install",
            skillName,
            githubUrl: item.githubUrl,
            reason: `Installed (${result.filesCount} files, ${riskStr} risk)`,
            riskLevel: riskStr,
          });
        } catch (err) {
          actions.push({
            type: "error",
            skillName: item.name,
            githubUrl: item.githubUrl,
            reason: `Install failed: ${err instanceof Error ? err.message : "unknown"}`,
          });
        }
      }

      // Phase 5: Update existing skills
      for (const item of diff.toUpdate) {
        if (dryRun) {
          actions.push({ type: "update", skillName: item.name, githubUrl: item.githubUrl, reason: "Upstream changed" });
          continue;
        }

        try {
          const result = await installSkill(item.githubUrl, item.name, true);
          const skillName = result.installPath.split("/").pop() || item.name;

          const riskStr = result.scanSummary.split(" ")[0].toLowerCase();
          const riskNum = RISK_LEVEL_ORDER[riskStr] ?? 0;
          if (riskNum > maxRisk) {
            actions.push({
              type: "skip-risk",
              skillName,
              githubUrl: item.githubUrl,
              reason: `Updated version risk ${riskStr} exceeds max ${config.maxRiskLevel}`,
              riskLevel: riskStr,
            });
            continue;
          }

          try { await skillManager.scanLocalSkill(skillName); } catch { /* non-fatal */ }

          if (lock.skills[skillName]) {
            lock.skills[skillName].installedHash = result.contentHash;
            lock.skills[skillName].upstreamHash = result.contentHash;
            lock.skills[skillName].lastSynced = new Date().toISOString();
            lock.skills[skillName].subscriptionIds = item.subIds;
            lock.skills[skillName].riskLevel = riskStr;
            lock.skills[skillName].filesCount = result.filesCount;
            lock.skills[skillName].hasSkillMd = result.hasSkillMd;
            lock.skills[skillName].upstreamUpdatedAt = item.updatedAt;
          }

          actions.push({
            type: "update",
            skillName,
            githubUrl: item.githubUrl,
            reason: `Updated (${result.filesCount} files, ${riskStr} risk)`,
            riskLevel: riskStr,
          });
        } catch (err) {
          actions.push({
            type: "error",
            skillName: item.name,
            githubUrl: item.githubUrl,
            reason: `Update failed: ${err instanceof Error ? err.message : "unknown"}`,
          });
        }
      }

      // Phase 6: Remove skills no longer in subscriptions
      for (const item of diff.toRemove) {
        if (dryRun) {
          actions.push({ type: "remove", skillName: item.name, githubUrl: item.githubUrl, reason: "No longer matched by any subscription" });
          continue;
        }

        try {
          await uninstallSkill(item.name);
          skillManager.removeSkill(item.name);
          delete lock.skills[item.name];
          actions.push({
            type: "remove",
            skillName: item.name,
            githubUrl: item.githubUrl,
            reason: "Removed — no longer matched by any subscription",
          });
        } catch (err) {
          actions.push({
            type: "error",
            skillName: item.name,
            githubUrl: item.githubUrl,
            reason: `Remove failed: ${err instanceof Error ? err.message : "unknown"}`,
          });
        }
      }

      // Phase 7: Write lock file
      if (!dryRun) {
        lock.lastSyncRun = new Date().toISOString();
        lock.syncCount = (lock.syncCount || 0) + 1;
        await writeSyncLock(lock);
      }

      const finishedAt = new Date().toISOString();
      return {
        startedAt,
        finishedAt,
        totalDiscovered: discovered.size,
        actions,
        installed: actions.filter((a) => a.type === "install").length,
        updated: actions.filter((a) => a.type === "update").length,
        removed: actions.filter((a) => a.type === "remove").length,
        skipped: actions.filter((a) => a.type === "skip-conflict" || a.type === "skip-risk" || a.type === "unmanage").length,
        errors: actions.filter((a) => a.type === "error").length,
        dryRun,
      };
    } catch (err) {
      return {
        startedAt,
        finishedAt: new Date().toISOString(),
        totalDiscovered: 0,
        actions: [{ type: "error", skillName: "", githubUrl: "", reason: `Sync failed: ${err instanceof Error ? err.message : "unknown"}` }],
        installed: 0, updated: 0, removed: 0, skipped: 0, errors: 1,
        dryRun,
      };
    } finally {
      this.syncing = false;
    }
  }

  async startPeriodicSync(): Promise<void> {
    const config = await readSyncConfig();

    if (!config.enabled || config.syncIntervalHours <= 0) {
      console.error("[skillsync] Periodic sync disabled (interval=0 or disabled)");
      return;
    }

    const intervalMs = config.syncIntervalHours * 60 * 60 * 1000;
    console.error(`[skillsync] Starting periodic sync every ${config.syncIntervalHours}h`);

    this.timer = setInterval(() => {
      console.error("[skillsync] Running periodic sync...");
      this.sync().then((report) => {
        console.error(`[skillsync] Periodic sync done: ${report.installed} installed, ${report.updated} updated, ${report.removed} removed, ${report.errors} errors`);
      }).catch((err) => {
        console.error(`[skillsync] Periodic sync error: ${err instanceof Error ? err.message : "unknown"}`);
      });
    }, intervalMs);

    // Unref so the timer doesn't prevent process exit
    if (this.timer && typeof this.timer === "object" && "unref" in this.timer) {
      (this.timer as NodeJS.Timeout).unref();
    }
  }

  stopPeriodicSync(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async getStatus(): Promise<SyncStatus> {
    const config = await readSyncConfig();
    const lock = await readSyncLock();

    let nextSyncIn: string | null = null;
    if (this.timer && config.syncIntervalHours > 0 && this.lastSyncStart) {
      const nextMs = this.lastSyncStart + config.syncIntervalHours * 60 * 60 * 1000 - Date.now();
      if (nextMs > 0) {
        const hours = Math.floor(nextMs / 3600000);
        const mins = Math.floor((nextMs % 3600000) / 60000);
        nextSyncIn = `${hours}h ${mins}m`;
      }
    }

    return {
      enabled: config.enabled,
      syncing: this.syncing,
      lastSyncRun: lock.lastSyncRun,
      syncCount: lock.syncCount,
      managedSkills: Object.keys(lock.skills).length,
      subscriptions: config.subscriptions.filter((s) => s.enabled !== false).length,
      nextSyncIn,
      intervalHours: config.syncIntervalHours,
    };
  }

  shutdown(): void {
    this.stopPeriodicSync();
  }
}

// ─── Singleton ───────────────────────────────────────────────────────────────

export const syncEngine = new SyncEngine();
