/**
 * Anti-rollback state (SPEC v2 6.3, threat T7).
 *
 * The verifier keeps per-(package, key) highest-version-seen state and rejects
 * any manifest whose `version` is STRICTLY LOWER than the highest seen (a
 * manifest equal to the highest seen re-verifies successfully - repeat
 * verification of the installed release must pass).
 *
 * State lives outside any workspace (`~/.contextlock/state.json`) and is
 * signed with the machine-local key, exactly like the seal and trust stores
 * (SPEC v2 8): a corrupt or hand-edited state file is LOUD (unavailable) and
 * verification fails closed rather than silently forgetting the baseline.
 *
 * Fast-forward recovery (SPEC v2 6.5, TUF 5.3.11): on key rotation, or via
 * `contextlock trust reset <publisher>`, the baseline for that publisher is
 * cleared so a legitimately restarted version counter is accepted.
 */

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  contextlockHome,
  ensureContextlockHome,
  signWithLocalKey,
  verifyWithLocalKey,
  canonicalJson,
} from "./localkey.js";

export const STATE_STORE_SPEC = "contextlock-state/1" as const;
const STATE_STORE_FILENAME = "state.json";

export interface RollbackEntry {
  package: string;
  /** Fingerprint (SHA-256 hex) of the verifying public key. */
  key_fingerprint: string;
  highest_version: number;
  /** Publisher display name, recorded so `trust reset <publisher>` can target entries. */
  publisher: string;
  updated_at: string;
}

interface StateStoreFile {
  spec_version: typeof STATE_STORE_SPEC;
  entries: RollbackEntry[];
  sig: { key_fingerprint: string; signature: string };
}

export type RollbackCheck =
  | { ok: true; highestSeen?: number }
  | { ok: false; highestSeen: number };

type LoadState = "empty" | "loaded" | "unavailable";

export class RollbackState {
  private entries: RollbackEntry[] = [];
  private state: LoadState = "empty";
  private error?: string;
  private readonly storePath: string;

  constructor(storePath?: string) {
    this.storePath = storePath ?? join(contextlockHome(), STATE_STORE_FILENAME);
  }

  get path(): string {
    return this.storePath;
  }

  /** False only when the store is corrupt or its signature failed (loud state). */
  get available(): boolean {
    return this.state !== "unavailable";
  }

  get unavailableReason(): string | undefined {
    return this.error;
  }

  /**
   * Loads and verifies the store. Never throws: a missing store is empty; a
   * corrupt/bad-signature store sets state=unavailable so callers fail closed.
   */
  async load(): Promise<void> {
    this.entries = [];
    this.state = "empty";
    this.error = undefined;

    if (!existsSync(this.storePath)) {
      return;
    }

    let raw: string;
    try {
      raw = await readFile(this.storePath, "utf-8");
    } catch (e) {
      this.state = "unavailable";
      this.error = `rollback state unavailable: cannot read ${this.storePath}: ${(e as Error).message}`;
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.state = "unavailable";
      this.error = `rollback state unavailable: invalid JSON in ${this.storePath} (possible tampering)`;
      return;
    }

    const file = parsed as Partial<StateStoreFile> | null;
    if (
      file == null ||
      typeof file !== "object" ||
      file.spec_version !== STATE_STORE_SPEC ||
      !Array.isArray(file.entries) ||
      file.sig == null ||
      typeof file.sig.signature !== "string"
    ) {
      this.state = "unavailable";
      this.error = `rollback state unavailable: malformed store at ${this.storePath} (possible tampering)`;
      return;
    }

    const payload = canonicalJson({
      spec_version: STATE_STORE_SPEC,
      entries: file.entries,
    });
    const { valid } = await verifyWithLocalKey(Buffer.from(payload, "utf-8"), file.sig.signature);
    if (!valid) {
      this.state = "unavailable";
      this.error = `rollback state unavailable: signature invalid for ${this.storePath} (possible tampering)`;
      return;
    }

    this.entries = file.entries;
    this.state = "loaded";
  }

  private async save(): Promise<void> {
    await ensureContextlockHome();
    const payload = canonicalJson({
      spec_version: STATE_STORE_SPEC,
      entries: this.entries,
    });
    const { signature, keyFingerprint } = await signWithLocalKey(Buffer.from(payload, "utf-8"));
    const file: StateStoreFile = {
      spec_version: STATE_STORE_SPEC,
      entries: this.entries,
      sig: { key_fingerprint: keyFingerprint, signature },
    };
    await writeFile(this.storePath, JSON.stringify(file, null, 2), "utf-8");
  }

  private find(pkg: string, keyFingerprint: string): RollbackEntry | undefined {
    return this.entries.find(
      (e) => e.package === pkg && e.key_fingerprint === keyFingerprint,
    );
  }

  /**
   * Rejects versions strictly below the highest seen for (package, key).
   * Equal versions pass (re-verifying the installed release).
   */
  check(pkg: string, keyFingerprint: string, version: number): RollbackCheck {
    const entry = this.find(pkg, keyFingerprint);
    if (!entry) return { ok: true };
    if (version < entry.highest_version) {
      return { ok: false, highestSeen: entry.highest_version };
    }
    return { ok: true, highestSeen: entry.highest_version };
  }

  /**
   * Records a successfully verified version, raising the baseline when it is
   * higher than anything previously seen. Persists (signed) on change.
   */
  async record(
    pkg: string,
    keyFingerprint: string,
    version: number,
    publisher: string,
  ): Promise<void> {
    if (!this.available) {
      throw new Error(this.error ?? "rollback state unavailable");
    }
    const entry = this.find(pkg, keyFingerprint);
    if (entry) {
      if (version <= entry.highest_version) return;
      entry.highest_version = version;
      entry.publisher = publisher;
      entry.updated_at = new Date().toISOString();
    } else {
      this.entries.push({
        package: pkg,
        key_fingerprint: keyFingerprint,
        highest_version: version,
        publisher,
        updated_at: new Date().toISOString(),
      });
    }
    await this.save();
  }

  /**
   * Fast-forward recovery: clears all baselines recorded for a publisher.
   * Returns the number of entries removed.
   */
  async resetPublisher(publisher: string): Promise<number> {
    if (!this.available) {
      throw new Error(this.error ?? "rollback state unavailable");
    }
    const before = this.entries.length;
    this.entries = this.entries.filter((e) => e.publisher !== publisher);
    const removed = before - this.entries.length;
    if (removed > 0) {
      await this.save();
    }
    return removed;
  }

  listEntries(): RollbackEntry[] {
    return [...this.entries];
  }
}
