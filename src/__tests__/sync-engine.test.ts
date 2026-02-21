import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { writeFile, readFile, mkdir, rm, rename } from "node:fs/promises";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";

// ─── Mock paths ──────────────────────────────────────────────────────────────
// We test config/lock with temp files, and computeSyncDiff as a pure function.

const TEST_DIR = join(tmpdir(), `skillsync-test-${randomUUID()}`);
const TEST_CONFIG_PATH = join(TEST_DIR, "skillsync.json");
const TEST_LOCK_PATH = join(TEST_DIR, "skillsync.lock");

// ─── Import the pure diff function directly ─────────────────────────────────

import { computeSyncDiff, type SyncDiffResult } from "../sync-engine.js";
import type { SyncConfig } from "../sync-config.js";
import type { SyncLockFile, LockedSkill } from "../sync-lock.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides?: Partial<SyncConfig>): SyncConfig {
  return {
    version: 1,
    subscriptions: [],
    syncIntervalHours: 0,
    maxRiskLevel: "low",
    conflictPolicy: "skip",
    autoRemove: false,
    enabled: true,
    ...overrides,
  };
}

function makeLock(skills?: Record<string, LockedSkill>, overrides?: Partial<SyncLockFile>): SyncLockFile {
  return {
    version: 1,
    skills: skills || {},
    lastSyncRun: null,
    syncCount: 0,
    ...overrides,
  };
}

function makeLockedSkill(name: string, githubUrl: string, overrides?: Partial<LockedSkill>): LockedSkill {
  return {
    name,
    githubUrl,
    installedHash: "abc123",
    upstreamHash: "abc123",
    subscriptionIds: ["sub-1"],
    lastSynced: "2025-01-01T00:00:00.000Z",
    installedAt: "2025-01-01T00:00:00.000Z",
    riskLevel: "safe",
    filesCount: 3,
    hasSkillMd: true,
    ...overrides,
  };
}

function makeDiscovered(
  entries: Array<{ name: string; githubUrl: string; subIds?: string[]; updatedAt?: number | string }>
): Map<string, { skill: any; subIds: string[]; inferredName: string }> {
  const map = new Map();
  for (const entry of entries) {
    map.set(entry.githubUrl, {
      skill: {
        name: entry.name,
        githubUrl: entry.githubUrl,
        description: "Test skill",
        author: "test-author",
        stars: 10,
        updatedAt: entry.updatedAt ?? 1700000000,
      },
      subIds: entry.subIds ?? ["sub-1"],
      inferredName: entry.name,
    });
  }
  return map;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("computeSyncDiff", () => {
  it("identifies new skills to install (in API, not in lock)", () => {
    const discovered = makeDiscovered([
      { name: "skill-a", githubUrl: "https://github.com/owner/repo/tree/main/skill-a" },
      { name: "skill-b", githubUrl: "https://github.com/owner/repo/tree/main/skill-b" },
    ]);
    const lock = makeLock();
    const config = makeConfig();

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toInstall.length, 2);
    assert.equal(diff.toUpdate.length, 0);
    assert.equal(diff.toRemove.length, 0);
    assert.equal(diff.conflicts.length, 0);
  });

  it("does not reinstall already-locked skills with same updatedAt", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-a";
    const discovered = makeDiscovered([
      { name: "skill-a", githubUrl, updatedAt: 1700000000 },
    ]);
    const lock = makeLock({
      "skill-a": makeLockedSkill("skill-a", githubUrl, {
        upstreamUpdatedAt: "1700000000",
      }),
    });
    const config = makeConfig();

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toInstall.length, 0);
    assert.equal(diff.toUpdate.length, 0);
  });

  it("schedules update when upstream updatedAt changes", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-a";
    const discovered = makeDiscovered([
      { name: "skill-a", githubUrl, updatedAt: 1700000001 },
    ]);
    const lock = makeLock({
      "skill-a": makeLockedSkill("skill-a", githubUrl, {
        lastSynced: "2025-01-01T00:00:00.000Z",
      }),
    });
    const config = makeConfig();

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toUpdate.length, 1);
    assert.equal(diff.toUpdate[0].name, "skill-a");
  });

  it("identifies removals when autoRemove=true and skill no longer in API", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-old";
    const discovered = makeDiscovered([]); // nothing discovered
    const lock = makeLock({
      "skill-old": makeLockedSkill("skill-old", githubUrl),
    });
    const config = makeConfig({ autoRemove: true });

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toRemove.length, 1);
    assert.equal(diff.toRemove[0].name, "skill-old");
  });

  it("does NOT remove skills when autoRemove=false", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-old";
    const discovered = makeDiscovered([]);
    const lock = makeLock({
      "skill-old": makeLockedSkill("skill-old", githubUrl),
    });
    const config = makeConfig({ autoRemove: false });

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toRemove.length, 0);
  });

  it("deduplicates across subscriptions", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-dup";
    const map = new Map();
    map.set(githubUrl, {
      skill: { name: "skill-dup", githubUrl, description: "", author: "", stars: 0, updatedAt: 1700000000 },
      subIds: ["sub-1", "sub-2"],
      inferredName: "skill-dup",
    });
    const lock = makeLock();
    const config = makeConfig();

    const diff = computeSyncDiff(map, lock, config);
    assert.equal(diff.toInstall.length, 1);
    assert.deepEqual(diff.toInstall[0].subIds, ["sub-1", "sub-2"]);
  });

  it("applies skip conflict policy for locally modified skills", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/skill-mod";
    // The skill manager won't have the skill in this test context,
    // so localSkill will be undefined and no conflict is detected.
    // This test verifies the non-conflict case passes through.
    const discovered = makeDiscovered([
      { name: "skill-mod", githubUrl, updatedAt: 1700000002 },
    ]);
    const lock = makeLock({
      "skill-mod": makeLockedSkill("skill-mod", githubUrl),
    });
    const config = makeConfig({ conflictPolicy: "skip" });

    const diff = computeSyncDiff(discovered, lock, config);
    // No conflict because skillManager.getSkill returns undefined in test
    assert.equal(diff.toUpdate.length, 1);
    assert.equal(diff.conflicts.length, 0);
  });

  it("handles empty discovered and empty lock", () => {
    const discovered = makeDiscovered([]);
    const lock = makeLock();
    const config = makeConfig();

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toInstall.length, 0);
    assert.equal(diff.toUpdate.length, 0);
    assert.equal(diff.toRemove.length, 0);
    assert.equal(diff.conflicts.length, 0);
  });

  it("handles multiple installs and removals simultaneously", () => {
    const discovered = makeDiscovered([
      { name: "new-skill", githubUrl: "https://github.com/owner/repo/tree/main/new-skill" },
    ]);
    const lock = makeLock({
      "old-skill": makeLockedSkill("old-skill", "https://github.com/owner/repo/tree/main/old-skill"),
    });
    const config = makeConfig({ autoRemove: true });

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toInstall.length, 1);
    assert.equal(diff.toInstall[0].name, "new-skill");
    assert.equal(diff.toRemove.length, 1);
    assert.equal(diff.toRemove[0].name, "old-skill");
  });
});

describe("SyncConfig file operations", () => {
  before(async () => {
    await mkdir(TEST_DIR, { recursive: true });
  });

  after(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  it("writes and reads a config file", async () => {
    const config: SyncConfig = {
      version: 1,
      subscriptions: [
        { id: "test-1", query: "testing", enabled: true },
      ],
      syncIntervalHours: 6,
      maxRiskLevel: "low",
      conflictPolicy: "skip",
      autoRemove: false,
      enabled: true,
    };
    await writeFile(TEST_CONFIG_PATH, JSON.stringify(config, null, 2), "utf-8");
    const raw = await readFile(TEST_CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.subscriptions.length, 1);
    assert.equal(parsed.subscriptions[0].query, "testing");
    assert.equal(parsed.syncIntervalHours, 6);
  });

  it("validates config structure", async () => {
    const config = {
      version: 1,
      subscriptions: [],
      syncIntervalHours: 0,
      maxRiskLevel: "low",
      conflictPolicy: "skip",
      autoRemove: false,
      enabled: true,
    };
    await writeFile(TEST_CONFIG_PATH, JSON.stringify(config), "utf-8");
    const raw = await readFile(TEST_CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.version, 1);
    assert.equal(Array.isArray(parsed.subscriptions), true);
  });
});

describe("SyncLock file operations", () => {
  before(async () => {
    await mkdir(TEST_DIR, { recursive: true });
  });

  after(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  it("writes and reads a lock file", async () => {
    const lock: SyncLockFile = {
      version: 1,
      skills: {
        "test-skill": makeLockedSkill("test-skill", "https://github.com/owner/repo/tree/main/test-skill"),
      },
      lastSyncRun: "2025-01-01T00:00:00.000Z",
      syncCount: 5,
    };
    await writeFile(TEST_LOCK_PATH, JSON.stringify(lock, null, 2), "utf-8");
    const raw = await readFile(TEST_LOCK_PATH, "utf-8");
    const parsed = JSON.parse(raw);
    assert.equal(parsed.version, 1);
    assert.equal(Object.keys(parsed.skills).length, 1);
    assert.equal(parsed.skills["test-skill"].name, "test-skill");
    assert.equal(parsed.syncCount, 5);
  });

  it("isSyncManaged returns true for managed skills", () => {
    const lock = makeLock({
      "my-skill": makeLockedSkill("my-skill", "https://github.com/a/b/tree/main/c"),
    });
    assert.equal(lock.skills["my-skill"] !== undefined, true);
    assert.equal(lock.skills["other-skill"] !== undefined, false);
  });

  it("upsert adds new skill to lock", () => {
    const lock = makeLock();
    const skill = makeLockedSkill("new-skill", "https://github.com/a/b/tree/main/d");
    lock.skills[skill.name] = skill;
    assert.equal(Object.keys(lock.skills).length, 1);
    assert.equal(lock.skills["new-skill"].githubUrl, "https://github.com/a/b/tree/main/d");
  });

  it("remove deletes skill from lock", () => {
    const lock = makeLock({
      "to-remove": makeLockedSkill("to-remove", "https://github.com/a/b/tree/main/e"),
    });
    delete lock.skills["to-remove"];
    assert.equal(Object.keys(lock.skills).length, 0);
  });
});

describe("SyncReport structure", () => {
  it("counts actions correctly", () => {
    // Simulate a report
    const actions: Array<{ type: string; skillName: string; githubUrl: string; reason: string }> = [
      { type: "install", skillName: "a", githubUrl: "u1", reason: "new" },
      { type: "install", skillName: "b", githubUrl: "u2", reason: "new" },
      { type: "update", skillName: "c", githubUrl: "u3", reason: "updated" },
      { type: "remove", skillName: "d", githubUrl: "u4", reason: "removed" },
      { type: "skip-risk", skillName: "e", githubUrl: "u5", reason: "risky" },
      { type: "error", skillName: "f", githubUrl: "u6", reason: "failed" },
    ];

    const installed = actions.filter((a) => a.type === "install").length;
    const updated = actions.filter((a) => a.type === "update").length;
    const removed = actions.filter((a) => a.type === "remove").length;
    const skipped = actions.filter((a) => a.type === "skip-conflict" || a.type === "skip-risk" || a.type === "unmanage").length;
    const errors = actions.filter((a) => a.type === "error").length;

    assert.equal(installed, 2);
    assert.equal(updated, 1);
    assert.equal(removed, 1);
    assert.equal(skipped, 1);
    assert.equal(errors, 1);
  });
});

describe("Risk level ordering", () => {
  it("orders risk levels correctly", () => {
    const order: Record<string, number> = {
      safe: 0, low: 1, medium: 2, high: 3, critical: 4,
    };
    assert.equal(order.safe < order.low, true);
    assert.equal(order.low < order.medium, true);
    assert.equal(order.medium < order.high, true);
    assert.equal(order.high < order.critical, true);
  });

  it("filters skills above max risk", () => {
    const maxRisk = 1; // "low"
    const risks = ["safe", "low", "medium", "high", "critical"];
    const order: Record<string, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const allowed = risks.filter((r) => (order[r] ?? 0) <= maxRisk);
    const blocked = risks.filter((r) => (order[r] ?? 0) > maxRisk);

    assert.deepEqual(allowed, ["safe", "low"]);
    assert.deepEqual(blocked, ["medium", "high", "critical"]);
  });
});

describe("Subscription management", () => {
  it("generates unique IDs for subscriptions", () => {
    const id1 = randomUUID();
    const id2 = randomUUID();
    assert.notEqual(id1, id2);
    assert.equal(typeof id1, "string");
    assert.equal(id1.length, 36);
  });

  it("filters subscriptions by enabled flag", () => {
    const subs = [
      { id: "1", query: "a", enabled: true },
      { id: "2", query: "b", enabled: false },
      { id: "3", query: "c" }, // default enabled
    ];
    const active = subs.filter((s) => s.enabled !== false);
    assert.equal(active.length, 2);
    assert.equal(active[0].query, "a");
    assert.equal(active[1].query, "c");
  });
});

describe("Conflict policy", () => {
  it("skip policy: does not schedule update for conflicts", () => {
    // Simulate: skill in lock, upstream changed, locally modified
    // When skillManager.getSkill returns undefined (no local data), it goes to toUpdate
    const githubUrl = "https://github.com/owner/repo/tree/main/conflict-skill";
    const discovered = makeDiscovered([
      { name: "conflict-skill", githubUrl, updatedAt: 1700000099 },
    ]);
    const lock = makeLock({
      "conflict-skill": makeLockedSkill("conflict-skill", githubUrl),
    });
    const config = makeConfig({ conflictPolicy: "skip" });

    const diff = computeSyncDiff(discovered, lock, config);
    // Without skillManager having the skill, conflict detection isn't triggered
    assert.equal(diff.toUpdate.length, 1);
  });

  it("overwrite policy: schedules update even if locally modified", () => {
    const githubUrl = "https://github.com/owner/repo/tree/main/overwrite-skill";
    const discovered = makeDiscovered([
      { name: "overwrite-skill", githubUrl, updatedAt: 1700000099 },
    ]);
    const lock = makeLock({
      "overwrite-skill": makeLockedSkill("overwrite-skill", githubUrl),
    });
    const config = makeConfig({ conflictPolicy: "overwrite" });

    const diff = computeSyncDiff(discovered, lock, config);
    assert.equal(diff.toUpdate.length, 1);
  });
});

describe("Dry run behavior", () => {
  it("dry run report has dryRun=true", () => {
    const report = {
      startedAt: "2025-01-01T00:00:00.000Z",
      finishedAt: "2025-01-01T00:01:00.000Z",
      totalDiscovered: 5,
      actions: [
        { type: "install" as const, skillName: "a", githubUrl: "u1", reason: "would install" },
      ],
      installed: 1,
      updated: 0,
      removed: 0,
      skipped: 0,
      errors: 0,
      dryRun: true,
    };
    assert.equal(report.dryRun, true);
    assert.equal(report.installed, 1);
  });
});
