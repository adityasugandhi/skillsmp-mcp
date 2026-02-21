import { sanitizeApiError } from "./sanitize.js";

const BASE_URL = "https://skillsmp.com/api/v1/skills";

export interface SkillResult {
  name: string;
  description: string;
  author: string;
  githubUrl: string;
  stars: number;
  updatedAt: number | string;
  tags?: string[];
  skillUrl?: string;
}

export interface AiSearchResult extends SkillResult {
  score?: number;
}

export interface SearchResponse {
  skills: SkillResult[];
  total: number;
  query: string;
}

export interface AiSearchResponse {
  skills: AiSearchResult[];
  total: number;
  query: string;
}

// Actual API response shape from skillsmp.com
interface ApiResponse {
  success: boolean;
  data: {
    skills: SkillResult[];
    pagination?: {
      total: number;
      page: number;
      limit: number;
      hasNext: boolean;
    };
  };
}

function getApiKey(): string | undefined {
  return process.env.SKILLSMP_API_KEY;
}

async function apiFetch<T>(url: string): Promise<T> {
  const apiKey = getApiKey();
  const headers: Record<string, string> = {
    Accept: "application/json",
    "User-Agent": "skillsmp-mcp-server/1.0",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
  }

  const response = await fetch(url, { headers });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    console.error(`[skillsmp] API error: HTTP ${response.status} — ${body}`);
    throw new Error(sanitizeApiError(response.status, body));
  }

  return response.json() as Promise<T>;
}

function extractSkills(raw: unknown): { skills: SkillResult[]; total: number } {
  if (!raw || typeof raw !== "object") return { skills: [], total: 0 };

  // Shape: { success, data: { skills: [...], pagination: { total } } }
  const resp = raw as Record<string, unknown>;
  if (resp.data && typeof resp.data === "object") {
    const data = resp.data as Record<string, unknown>;
    if (Array.isArray(data.skills)) {
      const pagination = data.pagination as { total?: number } | undefined;
      return { skills: data.skills as SkillResult[], total: pagination?.total ?? data.skills.length };
    }
    // Fallback: data is an array directly
    if (Array.isArray(data)) {
      return { skills: data as SkillResult[], total: data.length };
    }
  }

  // Fallback: response is array at top level
  if (Array.isArray(raw)) {
    return { skills: raw as SkillResult[], total: raw.length };
  }

  return { skills: [], total: 0 };
}

export async function searchSkills(
  query: string,
  limit: number = 20,
  sortBy: "stars" | "recent" = "recent"
): Promise<SearchResponse> {
  const params = new URLSearchParams({
    q: query,
    limit: String(Math.min(limit, 100)),
    sortBy,
  });

  const raw = await apiFetch<unknown>(`${BASE_URL}/search?${params}`);
  const { skills, total } = extractSkills(raw);
  return { skills, total, query };
}

export async function aiSearchSkills(
  query: string,
  limit: number = 10
): Promise<AiSearchResponse> {
  const params = new URLSearchParams({
    q: query,
    limit: String(Math.min(limit, 50)),
  });

  const raw = await apiFetch<unknown>(`${BASE_URL}/ai-search?${params}`);
  const { skills, total } = extractSkills(raw);
  return { skills: skills as AiSearchResult[], total, query };
}
