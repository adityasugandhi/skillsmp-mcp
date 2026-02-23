import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  SYNC_CONFIG_PATH,
  SYNC_DEFAULT_INTERVAL_HOURS,
  SYNC_DEFAULT_MAX_RISK,
  SYNC_DEFAULT_CONFLICT_POLICY,
} from "./constants.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SyncSubscription {
  id: string;
  query: string;
  authors?: string[];
  tags?: string[];
  limit?: number;
  sortBy?: "stars" | "recent";
  enabled?: boolean;
}

export interface SyncConfig {
  version: 1;
  subscriptions: SyncSubscription[];
  syncIntervalHours: number;
  maxRiskLevel: "safe" | "low" | "medium";
  conflictPolicy: "skip" | "overwrite" | "unmanage";
  autoRemove: boolean;
  enabled: boolean;
}

// ─── Validation ──────────────────────────────────────────────────────────────

const subscriptionSchema = z.object({
  id: z.string().min(1),
  query: z.string().min(1).max(200),
  authors: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  limit: z.number().min(1).max(100).optional(),
  sortBy: z.enum(["stars", "recent"]).optional(),
  enabled: z.boolean().optional(),
});

const configSchema = z.object({
  version: z.literal(1),
  subscriptions: z.array(subscriptionSchema),
  syncIntervalHours: z.number().min(0).max(168),
  maxRiskLevel: z.enum(["safe", "low", "medium"]),
  conflictPolicy: z.enum(["skip", "overwrite", "unmanage"]),
  autoRemove: z.boolean(),
  enabled: z.boolean(),
});

// ─── Defaults ────────────────────────────────────────────────────────────────

export function defaultConfig(): SyncConfig {
  return {
    version: 1,
    subscriptions: [],
    syncIntervalHours: SYNC_DEFAULT_INTERVAL_HOURS,
    maxRiskLevel: SYNC_DEFAULT_MAX_RISK,
    conflictPolicy: SYNC_DEFAULT_CONFLICT_POLICY,
    autoRemove: false,
    enabled: true,
  };
}

// ─── Read / Write ────────────────────────────────────────────────────────────

export async function readSyncConfig(configPath?: string): Promise<SyncConfig> {
  const path = configPath ?? SYNC_CONFIG_PATH;
  try {
    const raw = await readFile(path, "utf-8");
    const parsed = JSON.parse(raw);
    return configSchema.parse(parsed);
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
      return defaultConfig();
    }
    if (err instanceof z.ZodError) {
      console.error("[skillsync] Invalid config, using defaults:", err.issues);
      return defaultConfig();
    }
    throw err;
  }
}

export async function writeSyncConfig(config: SyncConfig, configPath?: string): Promise<void> {
  const path = configPath ?? SYNC_CONFIG_PATH;
  const validated = configSchema.parse(config);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(validated, null, 2) + "\n", "utf-8");
}

export async function mergeSyncConfig(partial: Partial<Omit<SyncConfig, "version" | "subscriptions">>, configPath?: string): Promise<SyncConfig> {
  const current = await readSyncConfig(configPath);
  const merged: SyncConfig = {
    ...current,
    ...partial,
    version: 1,
    subscriptions: current.subscriptions,
  };
  await writeSyncConfig(merged, configPath);
  return merged;
}

// ─── Subscription Management ─────────────────────────────────────────────────

export async function addSubscription(sub: Omit<SyncSubscription, "id">, configPath?: string): Promise<{ config: SyncConfig; subscription: SyncSubscription }> {
  const config = await readSyncConfig(configPath);
  const subscription: SyncSubscription = {
    ...sub,
    id: randomUUID(),
    enabled: sub.enabled ?? true,
  };
  config.subscriptions.push(subscription);
  await writeSyncConfig(config, configPath);
  return { config, subscription };
}

export async function removeSubscription(id: string, configPath?: string): Promise<{ config: SyncConfig; removed: boolean }> {
  const config = await readSyncConfig(configPath);
  const before = config.subscriptions.length;
  config.subscriptions = config.subscriptions.filter((s) => s.id !== id);
  const removed = config.subscriptions.length < before;
  if (removed) {
    await writeSyncConfig(config, configPath);
  }
  return { config, removed };
}
