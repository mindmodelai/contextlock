/**
 * status command - SPEC v2 Mode 0.
 *
 * `contextlock status [--root <dir>] [--json]`
 * Shows the seal state (sealed | seal-modified | unsealed) and sealed_at for
 * every protected-class file under root (default cwd).
 */

import { resolve, join } from "node:path";
import {
  SealStore,
  findProtectedFiles,
  DEFAULT_PATTERNS,
} from "@contextlock/core";

export interface StatusOptions {
  root?: string;
}

export interface StatusRow {
  file: string;
  state: string;
  sealed_at?: string;
}

export interface StatusResult {
  root: string;
  rows: StatusRow[];
  storeUnavailable?: string;
}

export async function statusCommand(options: StatusOptions = {}): Promise<StatusResult> {
  const root = resolve(options.root ?? process.cwd());
  const store = new SealStore();
  await store.load();

  const rel = await findProtectedFiles(root, DEFAULT_PATTERNS);
  const rows: StatusRow[] = [];

  for (const r of rel) {
    const abs = join(root, r);
    const verdict = await store.verifySeal(abs);
    rows.push({
      file: r.replace(/\\/g, "/"),
      state: verdict.status,
      sealed_at: verdict.sealedAt,
    });
  }

  return {
    root,
    rows,
    storeUnavailable: store.available ? undefined : store.unavailableReason,
  };
}
