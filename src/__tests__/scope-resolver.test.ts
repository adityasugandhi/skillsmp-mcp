import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";
import { join } from "node:path";
import { resolvePaths, validateSkillName, safeSkillPath } from "../scope-resolver.js";

describe("scope-resolver", () => {
  describe("resolvePaths", () => {
    it("should resolve global paths to ~/.claude/", () => {
      const paths = resolvePaths("global");
      const expectedBase = join(homedir(), ".claude");
      assert.equal(paths.scope, "global");
      assert.equal(paths.skillsDir, join(expectedBase, "skills"));
      assert.equal(paths.syncConfigPath, join(expectedBase, "skillsync.json"));
      assert.equal(paths.syncLockPath, join(expectedBase, "skillsync.lock"));
      assert.ok(paths.label.includes("global"));
    });

    it("should resolve project paths to cwd/.claude/", () => {
      const paths = resolvePaths("project");
      const expectedBase = join(process.cwd(), ".claude");
      assert.equal(paths.scope, "project");
      assert.equal(paths.skillsDir, join(expectedBase, "skills"));
      assert.equal(paths.syncConfigPath, join(expectedBase, "skillsync.json"));
      assert.equal(paths.syncLockPath, join(expectedBase, "skillsync.lock"));
      assert.ok(paths.label.includes("project"));
    });

    it("should return different paths for global vs project", () => {
      const global = resolvePaths("global");
      const project = resolvePaths("project");
      assert.notEqual(global.skillsDir, project.skillsDir);
      assert.notEqual(global.syncConfigPath, project.syncConfigPath);
      assert.notEqual(global.syncLockPath, project.syncLockPath);
    });
  });

  describe("validateSkillName", () => {
    it("should accept valid skill names", () => {
      assert.ok(validateSkillName("my-skill"));
      assert.ok(validateSkillName("skill_01"));
      assert.ok(validateSkillName("SkillName"));
      assert.ok(validateSkillName("a"));
      assert.ok(validateSkillName("abc123"));
    });

    it("should reject invalid skill names", () => {
      assert.ok(!validateSkillName(""));
      assert.ok(!validateSkillName(".hidden"));
      assert.ok(!validateSkillName("-starts-dash"));
      assert.ok(!validateSkillName("has spaces"));
      assert.ok(!validateSkillName("a".repeat(65)));
      assert.ok(!validateSkillName("../evil"));
    });
  });

  describe("safeSkillPath", () => {
    it("should resolve valid paths within skills dir", () => {
      const skillsDir = "/tmp/test-skills";
      const result = safeSkillPath(skillsDir, "my-skill");
      assert.ok(result.startsWith(skillsDir + "/"));
      assert.ok(result.endsWith("my-skill"));
    });

    it("should throw on path traversal attempts", () => {
      const skillsDir = "/tmp/test-skills";
      assert.throws(
        () => safeSkillPath(skillsDir, "../etc/passwd"),
        /Path traversal detected/
      );
    });

    it("should throw on absolute path injection", () => {
      const skillsDir = "/tmp/test-skills";
      // This won't actually traverse since resolve handles it, but let's verify
      assert.throws(
        () => safeSkillPath(skillsDir, "../../root"),
        /Path traversal detected/
      );
    });
  });
});
