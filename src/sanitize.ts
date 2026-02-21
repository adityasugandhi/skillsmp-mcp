import { SANITIZE_PATTERNS } from "./constants.js";

/**
 * Strip dangerous Unicode and control characters from untrusted text
 * that will be rendered in tool output (prevents prompt injection via
 * invisible chars, bidi overrides, etc.).
 */
export function sanitizeText(input: string | undefined | null): string {
  if (!input) return "";
  let text = String(input);
  for (const [pattern, replacement] of SANITIZE_PATTERNS) {
    text = text.replace(pattern, replacement);
  }
  // Collapse excessive whitespace (>3 newlines → 2)
  text = text.replace(/\n{4,}/g, "\n\n\n");
  // Truncate excessively long fields
  if (text.length > 1000) {
    text = text.substring(0, 997) + "...";
  }
  return text;
}

/**
 * Sanitize a URL string — only allow http/https protocols, strip whitespace.
 */
export function sanitizeUrl(input: string | undefined | null): string {
  if (!input) return "";
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return "[invalid URL removed]";
}

/**
 * Truncate API error bodies to prevent leaking upstream internals.
 * Keeps only HTTP status and a safe prefix of the body.
 */
export function sanitizeApiError(status: number, body: string): string {
  const safeBody = body.substring(0, 100).replace(/[\n\r]/g, " ").trim();
  return `SkillsMP API error: HTTP ${status}${safeBody ? ` — ${safeBody}` : ""}`;
}
