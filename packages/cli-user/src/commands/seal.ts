/**
 * seal / reseal / unseal commands - SPEC v2 Mode 0 (Local Seal / TOFU).
 *
 * `contextlock seal <path...> [--note <text>]`
 * `contextlock seal --all [--root <dir>]`   (seals every protected-class file)
 * `contextlock reseal <path...>`            (deliberate re-approval)
 * `contextlock unseal <path...>`
 */

import { resolve, join } from "node:path";
import {
  SealStore,
  findProtectedFiles,
  DEFAULT_PATTERNS,
} from "@contextlock/core";

export type SealAction = "seal" | "reseal" | "unseal";

export interface SealOptions {
  paths?: string[];
  all?: boolean;
  root?: string;
  note?: string;
  action?: SealAction;
}

export interface SealedEntry {
  path: string;
  sha256: string;
  length: number;
  sealed_at: string;
}

export interface SealResult {
  action: SealAction;
  sealed: SealedEntry[];
  unsealed: string[];
  errors: Array<{ path: string; error: string }>;
  /** Set when the seal store is corrupt/tampered and nothing could be done. */
  storeUnavailable?: string;
}

/**
 * Resolves the set of target files. With --all, walks `root` (default cwd) for
 * protected-class files using the default detector patterns.
 */
async function resolveTargets(options: SealOptions): Promise<string[]> {
  if (options.all) {
    const root = resolve(options.root ?? process.cwd());
    const rel = await findProtectedFiles(root, DEFAULT_PATTERNS);
    return rel.map((r) => join(root, r));
  }
  return (options.paths ?? []).map((p) => resolve(p));
}

export async function sealCommand(options: SealOptions): Promise<SealResult> {
  const action: SealAction = options.action ?? "seal";
  const store = new SealStore();
  await store.load();

  if (!store.available) {
    return {
      action,
      sealed: [],
      unsealed: [],
      errors: [],
      storeUnavailable: store.unavailableReason,
    };
  }

  const targets = await resolveTargets(options);
  const result: SealResult = { action, sealed: [], unsealed: [], errors: [] };

  for (const target of targets) {
    try {
      if (action === "unseal") {
        const removed = await store.unsealFile(target);
        if (removed) {
          result.unsealed.push(target);
        } else {
          result.errors.push({ path: target, error: "no seal found for this path" });
        }
      } else {
        const entry =
          action === "reseal"
            ? await store.resealFile(target, options.note)
            : await store.sealFile(target, options.note);
        result.sealed.push({
          path: entry.path,
          sha256: entry.sha256,
          length: entry.length,
          sealed_at: entry.sealed_at,
        });
      }
    } catch (e) {
      result.errors.push({ path: target, error: (e as Error).message });
    }
  }

  return result;
}
