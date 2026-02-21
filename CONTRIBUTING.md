# Contributing to SkillSync MCP

Thanks for your interest in making AI agent skill management safer. Here's how to contribute.

## Setup

```bash
git clone https://github.com/adityasugandhi/skillsync-mcp.git
cd skillsync-mcp
npm install
npm run build
npm run dev    # Watch mode
```

## Running Tests

```bash
npm run test:build   # Build + run all tests (recommended)
```

Tests use Node.js built-in test runner. No external framework needed.

## How to Contribute

### Add a New Threat Pattern

1. Open `src/patterns.ts`
2. Add your pattern to `CRITICAL_PATTERNS` (blocks install) or `WARNING_PATTERNS` (flags for review)
3. Follow the existing format:
   ```typescript
   { regex: /your-regex-here/, severity: "critical", description: "What this catches", category: "category-name" }
   ```
4. Add test cases in `src/__tests__/security-scanner.test.ts`
5. Document the pattern in `docs/THREAT_PATTERNS.md`

**Pattern guidelines:**
- Keep regexes simple and avoid catastrophic backtracking
- Lines over 2000 chars are skipped (ReDoS protection), so patterns only need to match within that limit
- Use `category` to group related patterns (e.g., `prompt-injection`, `reverse-shell`, `credential-theft`)
- Test both true positives and false positives

### Add a New MCP Tool

1. Define the tool schema and handler in `src/tools.ts`
2. Use Zod for input validation
3. Keep tool names prefixed with `skillsmp_`
4. Add the tool to the README tools table

### Add Client Support

1. Add configuration example to README under the "Install" section
2. Add the client to the "Client Compatibility" table
3. Test that the MCP connection works over stdio

### Fix a Bug

1. Check existing issues for duplicates
2. Write a test that reproduces the bug
3. Fix the bug
4. Verify `npm run test:build` passes

## Code Style

- TypeScript strict mode
- ES2022 target, Node16 module resolution
- All logging goes to `stderr` (stdout is reserved for MCP protocol)
- Use explicit types, avoid `any`

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `npm run test:build` and confirm all tests pass
4. Open a PR using the template
5. Respond to review feedback

## Reporting Security Issues

If you find a security vulnerability in SkillSync itself (not a threat pattern), please email adityasugandhi.dev.ai@gmail.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
