# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SkillSync MCP Server (`@stranzwersweb2/skillsync-mcp`) — a Model Context Protocol server that provides security-gated skill management for Claude Code. Users can search the SkillsMP marketplace, scan GitHub skill repos for 60+ threat patterns, install/uninstall skills to `~/.claude/skills/`, and monitor installed skills with startup verification and live sync. Every installation is gated behind a security scan.

## Development Commands

```bash
npm install            # Install dependencies
npm run build          # Compile TypeScript → build/
npm run dev            # Watch mode (tsx watch src/index.ts)
npm run start          # Run compiled server (node build/index.js)
npm run test           # Run tests (requires prior build)
npm run test:build     # Build + run tests (recommended)
```

**Publishing**: `npm publish --access public` (scoped package, prepublishOnly runs build automatically)

## Architecture

**Transport**: MCP over stdio (`StdioServerTransport`). All logging goes to stderr.

**Startup Sequence**:
```
1. McpServer created
2. registerTools(server)          — registers all 8 tools
3. server.connect(transport)      — MCP is live, tools available
4. skillManager.initialize()      — BACKGROUND (fire-and-forget)
   4a. Discover skills in ~/.claude/skills/
   4b. Security scan each skill via scanSkillContent()
   4c. Start fs.watch for live additions/removals
5. Tools respond immediately; list_installed returns partial data if scan still running
```

**Data Flow**:
```
MCP Client (stdio) → tools.ts (8 tool handlers) → Business Logic → Response
                                                    ├── api-client.ts (SkillsMP REST API)
                                                    ├── security-scanner.ts (GitHub fetch + threat scan)
                                                    ├── skill-manager.ts (installed skill registry + fs.watch)
                                                    ├── installer.ts (filesystem + npm install)
                                                    └── sanitize.ts (output safety)
```

### Key Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Entry point — creates McpServer, registers tools, connects stdio transport, initializes skill manager |
| `src/tools.ts` | 8 MCP tool definitions with Zod schemas and handlers |
| `src/skill-manager.ts` | SkillManager class — discovery, local scanning, in-memory registry, fs.watch sync |
| `src/api-client.ts` | SkillsMP marketplace REST API client (search + AI search) |
| `src/security-scanner.ts` | Core threat engine — fetches GitHub repos via API, scans per-line + multiline patterns |
| `src/installer.ts` | Skill install/uninstall — path validation, file writing, `npm install --ignore-scripts` |
| `src/patterns.ts` | 60+ regex threat patterns in CRITICAL_PATTERNS and WARNING_PATTERNS |
| `src/constants.ts` | Config: skills dir, file limits (50 files / 2MB), binary/text extensions, watcher debounce |
| `src/sanitize.ts` | Strips zero-width Unicode, bidi overrides, truncates to prevent prompt injection |

### 8 MCP Tools

1. **skillsmp_search** — Keyword search on SkillsMP marketplace
2. **skillsmp_ai_search** — Semantic search via Cloudflare AI
3. **skillsmp_scan_skill** — Security scan a GitHub skill repo (up to 50 files, 2MB)
4. **skillsmp_search_safe** — Search + auto-scan top N results
5. **skillsmp_install_skill** — Scan → gate → fetch → write to ~/.claude/skills/ → npm install → update registry
6. **skillsmp_uninstall_skill** — Remove installed skill directory → remove from registry
7. **skillsmp_list_installed** — List all installed skills with risk levels (optional refresh/re-sync)
8. **skillsmp_audit_installed** — Deep security audit of a specific installed skill

### Security Model

**Risk levels**: safe → low → medium → high → critical

- **Critical threats** (prompt injection, RCE, reverse shells, credential theft, supply chain, privilege escalation): Installation BLOCKED, no override
- **Medium/High** (3-5+ warnings): Blocked unless `force=true`
- **Low/Safe**: Proceeds with warnings

**Defenses**: SSRF prevention (only github.com URLs), path traversal validation on skill names, ReDoS protection (skip lines >2000 chars), npm `--ignore-scripts`, output sanitization of all third-party text

### Skill Manager (`src/skill-manager.ts`)

Singleton `skillManager` with an in-memory `Map<string, InstalledSkill>` registry.

**Key methods**: `initialize()`, `shutdown()`, `discoverSkills()`, `scanLocalSkill(name)`, `getSkill(name)`, `getAllSkills()`, `removeSkill(name)`, `getSummary()`, `syncRegistry()`, `startWatching()`, `stopWatching()`

**InstalledSkill** type includes: name, path, filesCount, totalSize, hasSkillMd, scanResult (reused from security-scanner), contentHash (SHA-256), lastScanned timestamp.

### Test Suite

- `src/__tests__/security-scanner.test.ts` — 79 test cases covering all threat categories
- `src/__tests__/skill-manager.test.ts` — 10 test cases covering discovery, registry, sync, shutdown

Uses Node.js built-in test runner (`node --test`). No external test framework needed.

## Tech Stack

- TypeScript (strict mode, ES2022, Node16 modules)
- `@modelcontextprotocol/sdk` 1.12.1 — MCP protocol
- `zod` 3.24.2 — Tool input validation
- Node.js 20+ required
