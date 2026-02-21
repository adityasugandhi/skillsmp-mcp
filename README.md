# skillsmp-mcp

An MCP (Model Context Protocol) server for [SkillsMP](https://skillsmp.com) — the marketplace for Claude Code skills. Search, scan for security threats, install, and uninstall skills directly from your AI assistant.

**The only tool that gates skill installation behind a full security scan.**

## Features

- **Search** — Keyword and AI-powered semantic search across the SkillsMP marketplace
- **Security Scan** — 60+ threat patterns: prompt injection, reverse shells, credential theft, supply chain attacks, crypto mining, obfuscation
- **Install** — Download skills from GitHub to `~/.claude/skills/` with automatic security gate
- **Uninstall** — Clean removal of installed skills
- **Safe Search** — Combined search + auto-scan in one step

## Tools (6)

| Tool | Description |
|------|-------------|
| `skillsmp_search` | Keyword search across SkillsMP marketplace |
| `skillsmp_ai_search` | AI-powered semantic search (Cloudflare AI) |
| `skillsmp_scan_skill` | Security scan a GitHub skill repo (60+ patterns) |
| `skillsmp_search_safe` | Search + auto-scan top results |
| `skillsmp_install_skill` | Scan then install to `~/.claude/skills/` |
| `skillsmp_uninstall_skill` | Remove an installed skill |

## Install

### Claude Code (recommended)

Add to your Claude Code MCP settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "skillsmp": {
      "command": "npx",
      "args": ["-y", "skillsmp-mcp"]
    }
  }
}
```

### Global install

```bash
npm install -g skillsmp-mcp
```

Then add to your MCP config:

```json
{
  "mcpServers": {
    "skillsmp": {
      "command": "skillsmp-mcp"
    }
  }
}
```

## Security Model

Installation is gated by a multi-level security scan:

| Risk Level | Behavior |
|------------|----------|
| **Safe / Low** | Install proceeds, warnings shown |
| **Medium / High** | Install blocked — requires `force: true` to override |
| **Critical** | Install permanently blocked — no override |

### Additional Safety Guards

- Path traversal prevention on skill names and filenames
- SSRF prevention — only `github.com` URLs accepted
- `npm install --ignore-scripts` — blocks `postinstall` attacks
- Max 50 files, 2MB total size limit
- Binary files skipped, suspicious filenames flagged
- Content hash for TOCTOU verification

## How It Works

```
Search SkillsMP → Pick a skill → Security scan (60+ patterns)
                                        ↓
                              Critical? → BLOCKED
                              Medium/High? → Requires force=true
                              Safe/Low? → Download from GitHub
                                        ↓
                              Write to ~/.claude/skills/<name>/
                                        ↓
                              npm install --ignore-scripts (if needed)
                                        ↓
                              Restart Claude Code to load
```

## Examples

Ask your AI assistant:

```
Search for git-related skills on SkillsMP
```

```
Scan this skill for security issues: https://github.com/user/repo/tree/main/skills/my-skill
```

```
Install the commit skill from https://github.com/user/repo/tree/main/skills/commit
```

```
Uninstall the commit skill
```

## Development

```bash
git clone https://github.com/adityasugandhi/skillsmp-mcp.git
cd skillsmp-mcp
npm install
npm run build
npm run dev    # Watch mode with tsx
```

## Requirements

- Node.js >= 20
- Claude Code or any MCP-compatible client

## License

MIT - [Aditya Sugandhi](https://adityasugandhi.com)
