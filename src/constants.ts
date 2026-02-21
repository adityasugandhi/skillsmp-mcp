import { homedir } from "node:os";
import { join } from "node:path";

// ─── Skills Directory ───────────────────────────────────────────────────────

export const SKILLS_DIR = join(homedir(), ".claude", "skills");
export const VALID_SKILL_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

// ─── Scanner Limits ──────────────────────────────────────────────────────────

export const MAX_FILES = 50;
export const MAX_FILE_SIZE = 512 * 1024; // 512 KB per file
export const MAX_TOTAL_SIZE = 2 * 1024 * 1024; // 2 MB total
export const MAX_LINE_LENGTH = 2000; // Skip ReDoS-prone long lines
export const ALLOWED_GITHUB_HOSTS = ["github.com", "www.github.com"];

// ─── File Classification ────────────────────────────────────────────────────

export const BINARY_EXTENSIONS = new Set([
  ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
  ".wasm", ".node", ".pyc", ".pyo", ".class",
  ".tar", ".gz", ".tgz", ".zip", ".rar", ".7z", ".bz2",
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
  ".mp3", ".mp4", ".avi", ".mov", ".wav",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
]);

export const SUSPICIOUS_FILENAMES = new Set([
  "postinstall.sh", "preinstall.sh", "postinstall.js", "preinstall.js",
  ".npmrc", ".yarnrc", "makefile", ".env", ".env.local", ".env.production",
  ".gitconfig", ".netrc", ".curlrc",
]);

export const TEXT_EXTENSIONS = new Set([
  ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx",
  ".py", ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".c", ".cpp", ".h",
  ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
  ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
  ".md", ".txt", ".rst", ".adoc",
  ".html", ".htm", ".xml", ".svg",
  ".css", ".scss", ".less",
  ".sql", ".graphql", ".prisma",
  ".dockerfile", ".containerfile",
  ".tf", ".hcl",
  "", // extensionless files
]);

// ─── Sanitization ────────────────────────────────────────────────────────────

/** Characters/patterns that could be used for markdown injection in tool output */
// ─── Watcher ────────────────────────────────────────────────────────────────

export const WATCH_DEBOUNCE_MS = 500;

// ─── Sync Engine ────────────────────────────────────────────────────────────

export const SYNC_CONFIG_PATH = join(homedir(), ".claude", "skillsync.json");
export const SYNC_LOCK_PATH = join(homedir(), ".claude", "skillsync.lock");
export const SYNC_API_DELAY_MS = 200;
export const SYNC_DEFAULT_INTERVAL_HOURS = 0;
export const SYNC_DEFAULT_MAX_RISK = "low" as const;
export const SYNC_DEFAULT_CONFLICT_POLICY = "skip" as const;
export const RISK_LEVEL_ORDER: Record<string, number> = {
  safe: 0, low: 1, medium: 2, high: 3, critical: 4,
};

// ─── Sanitization ────────────────────────────────────────────────────────────

export const SANITIZE_PATTERNS: Array<[RegExp, string]> = [
  [/\u200B|\u200C|\u200D|\u2060|\uFEFF/g, ""], // zero-width chars
  [/\u202A|\u202B|\u202C|\u202D|\u202E|\u2066|\u2067|\u2068|\u2069/g, ""], // bidi overrides
];
