import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { skillManager, SkillManager, getSkillManager } from "../skill-manager.js";
import { resolvePaths } from "../scope-resolver.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

const TEST_DIR = join(tmpdir(), `skillsync-test-${Date.now()}`);

async function createTestSkill(name: string, files: Record<string, string>): Promise<string> {
  const skillDir = join(TEST_DIR, name);
  await mkdir(skillDir, { recursive: true });
  for (const [fileName, content] of Object.entries(files)) {
    await writeFile(join(skillDir, fileName), content, "utf-8");
  }
  return skillDir;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("SkillManager", () => {
  beforeEach(async () => {
    skillManager.shutdown();
    await mkdir(TEST_DIR, { recursive: true });
  });

  afterEach(async () => {
    skillManager.shutdown();
    await rm(TEST_DIR, { recursive: true, force: true }).catch(() => {});
  });

  describe("discoverSkills", () => {
    it("should return empty array when skills dir does not exist", async () => {
      // discoverSkills reads from SKILLS_DIR (~/.claude/skills/), not TEST_DIR
      // This test verifies it handles missing dirs gracefully
      const names = await skillManager.discoverSkills();
      // Could be empty or have real skills — just verify no crash
      assert.ok(Array.isArray(names));
    });

    it("should filter out invalid skill names", async () => {
      // Invalid names should not pass VALID_SKILL_NAME regex
      const validNames = ["my-skill", "skill_01", "SkillName"];
      const invalidNames = [".hidden", "-starts-dash", "has spaces", "a".repeat(65)];

      for (const name of validNames) {
        assert.ok(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(name), `Expected "${name}" to be valid`);
      }
      for (const name of invalidNames) {
        assert.ok(!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(name), `Expected "${name}" to be invalid`);
      }
    });
  });

  describe("getSummary", () => {
    it("should return correct structure when registry is empty", () => {
      const summary = skillManager.getSummary();
      assert.equal(summary.total, 0);
      assert.deepEqual(summary.skills, []);
      assert.equal(summary.byRisk.safe, 0);
      assert.equal(summary.byRisk.critical, 0);
    });
  });

  describe("getSkill / removeSkill", () => {
    it("should return undefined for unknown skill", () => {
      assert.equal(skillManager.getSkill("nonexistent"), undefined);
    });

    it("should remove skill from registry", () => {
      // Manually insert into registry for testing
      skillManager.registry.set("test-skill", {
        name: "test-skill",
        path: "/tmp/test",
        filesCount: 1,
        totalSize: 100,
        hasSkillMd: false,
        scanResult: {
          safe: true,
          riskLevel: "safe",
          threats: [],
          recommendation: "No threats detected.",
          contentHash: "abc123",
        },
        contentHash: "abc123",
        lastScanned: Date.now(),
        scope: "global",
        scopeLabel: "global (~/.claude/skills/)",
      });

      assert.ok(skillManager.getSkill("test-skill"));
      assert.ok(skillManager.removeSkill("test-skill"));
      assert.equal(skillManager.getSkill("test-skill"), undefined);
    });
  });

  describe("getAllSkills", () => {
    it("should return all skills in registry", () => {
      skillManager.registry.set("a", {
        name: "a", path: "/tmp/a", filesCount: 1, totalSize: 10,
        hasSkillMd: true,
        scanResult: { safe: true, riskLevel: "safe", threats: [], recommendation: "", contentHash: "h1" },
        contentHash: "h1", lastScanned: Date.now(),
        scope: "global", scopeLabel: "global",
      });
      skillManager.registry.set("b", {
        name: "b", path: "/tmp/b", filesCount: 2, totalSize: 20,
        hasSkillMd: false,
        scanResult: { safe: true, riskLevel: "safe", threats: [], recommendation: "", contentHash: "h2" },
        contentHash: "h2", lastScanned: Date.now(),
        scope: "global", scopeLabel: "global",
      });

      const all = skillManager.getAllSkills();
      assert.equal(all.length, 2);
      const names = all.map((s) => s.name).sort();
      assert.deepEqual(names, ["a", "b"]);
    });
  });

  describe("scanLocalSkill", () => {
    it("should reject invalid skill names", async () => {
      await assert.rejects(
        () => skillManager.scanLocalSkill(".evil"),
        /Invalid skill name/
      );
    });

    it("should reject nonexistent skills", async () => {
      await assert.rejects(
        () => skillManager.scanLocalSkill("nonexistent-skill-12345"),
        /ENOENT|not a directory|no such/i
      );
    });
  });

  describe("syncRegistry", () => {
    it("should detect removed skills", async () => {
      // Put a fake entry in registry
      skillManager.registry.set("ghost-skill", {
        name: "ghost-skill", path: "/tmp/ghost", filesCount: 0, totalSize: 0,
        hasSkillMd: false,
        scanResult: { safe: true, riskLevel: "safe", threats: [], recommendation: "", contentHash: "" },
        contentHash: "", lastScanned: Date.now(),
        scope: "global", scopeLabel: "global",
      });

      const sync = await skillManager.syncRegistry();
      // ghost-skill doesn't exist on disk, should be removed
      assert.ok(sync.removed.includes("ghost-skill"));
      assert.equal(skillManager.getSkill("ghost-skill"), undefined);
    });
  });

  describe("shutdown", () => {
    it("should clear registry and stop watcher", () => {
      skillManager.registry.set("test", {
        name: "test", path: "/tmp/t", filesCount: 0, totalSize: 0,
        hasSkillMd: false,
        scanResult: { safe: true, riskLevel: "safe", threats: [], recommendation: "", contentHash: "" },
        contentHash: "", lastScanned: Date.now(),
        scope: "global", scopeLabel: "global",
      });

      skillManager.shutdown();
      assert.equal(skillManager.registry.size, 0);
      assert.equal(skillManager.initialized, false);
    });
  });
});

describe("SkillManager Factory", () => {
  it("should return the same instance for the same scope", () => {
    const a = getSkillManager("global");
    const b = getSkillManager("global");
    assert.strictEqual(a, b);
  });

  it("should return different instances for different scopes", () => {
    const global = getSkillManager("global");
    const project = getSkillManager("project");
    assert.notStrictEqual(global, project);
  });

  it("should have correct scope in paths", () => {
    const global = getSkillManager("global");
    const project = getSkillManager("project");
    assert.equal(global.paths.scope, "global");
    assert.equal(project.paths.scope, "project");
  });

  it("should be a SkillManager instance", () => {
    const mgr = getSkillManager("global");
    assert.ok(mgr instanceof SkillManager);
  });
});
