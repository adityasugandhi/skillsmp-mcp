# SkillSync MCP — Security-Gated Skill Manager

Search, scan, install, and manage Claude Code skills with built-in security scanning. Every installation is gated behind a 60+ pattern threat scan.

## Tools

- `skillsmp_search` — Search the SkillsMP marketplace by keyword
- `skillsmp_ai_search` — AI-powered semantic search for skills
- `skillsmp_scan_skill` — Security scan any GitHub skill repo
- `skillsmp_search_safe` — Search + auto-scan top results in one step
- `skillsmp_install_skill` — Scan, gate, and install a skill to `~/.claude/skills/`
- `skillsmp_uninstall_skill` — Remove an installed skill
- `skillsmp_list_installed` — List installed skills with risk levels
- `skillsmp_audit_installed` — Deep security audit of an installed skill

## Setup

Add to your MCP client config:

```json
{
  "mcpServers": {
    "skillsmp": {
      "command": "npx",
      "args": ["-y", "@stranzwersweb2/skillsync-mcp"]
    }
  }
}
```

## When to Use

- User asks to find, search, or browse skills
- User wants to install a skill from GitHub
- User wants to check if a skill is safe before installing
- User wants to see what skills are installed or audit them
- User mentions SkillsMP marketplace

## Security

Critical threats (prompt injection, RCE, credential theft) permanently block installation. Medium/high risk requires explicit `force: true`. All output is sanitized against prompt injection.
