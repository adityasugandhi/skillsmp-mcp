import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { SYNC_LOCK_PATH } from "./constants.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface LockedSkill {
  name: string;
  githubUrl: string;
  installedHash: string;
  upstreamHash: string;
  subscriptionIds: string[];
  lastSynced: string;
  installedAt: string;
  riskLevel: string;
  filesCount: number;
  hasSkillMd: boolean;
  upstreamUpdatedAt?: string;  // raw updatedAt from API for change detection
}

export interface SyncLockFile {
  version: 1;
  skills: Record<string, LockedSkill>;
  lastSyncRun: string | null;
  syncCount: number;
}

// ─── Defaults ────────────────────────────────────────────────────────────────

export function emptyLock(): SyncLockFile {
  return {
    version: 1,
    skills: {},
    lastSyncRun: null,
    syncCount: 0,
  };
}

// ─── Read / Write ────────────────────────────────────────────────────────────

export async function readSyncLock(lockPath?: string): Promise<SyncLockFile> {
  const path = lockPath ?? SYNC_LOCK_PATH;
  try {
    const raw = await readFile(path, "utf-8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && parsed.version === 1 && typeof parsed.skills === "object") {
      return parsed as SyncLockFile;
    }
    console.error("[skillsync] Invalid lock file, using empty lock");
    return emptyLock();
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
      return emptyLock();
    }
    throw err;
  }
}

export async function writeSyncLock(lock: SyncLockFile, lockPath?: string): Promise<void> {
  const path = lockPath ?? SYNC_LOCK_PATH;
  await mkdir(dirname(path), { recursive: true });
  const tmpPath = path + ".tmp";
  await writeFile(tmpPath, JSON.stringify(lock, null, 2) + "\n", "utf-8");
  await rename(tmpPath, path);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export async function upsertLockedSkill(skill: LockedSkill, lockPath?: string): Promise<void> {
  const lock = await readSyncLock(lockPath);
  lock.skills[skill.name] = skill;
  await writeSyncLock(lock, lockPath);
}

export async function removeLockedSkill(name: string, lockPath?: string): Promise<boolean> {
  const lock = await readSyncLock(lockPath);
  if (!(name in lock.skills)) return false;
  delete lock.skills[name];
  await writeSyncLock(lock, lockPath);
  return true;
}

export function isSyncManaged(lock: SyncLockFile, skillName: string): boolean {
  return skillName in lock.skills;
}
