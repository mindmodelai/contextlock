/**
 * Seal store - SPEC v2 section 5 (Mode 0: Local Seal / TOFU).
 *
 * Trust-on-first-use pinning. `sealFile` records (path, sha256, length,
 * sealed_at, note) for a file the user has reviewed. The whole store is signed
 * by the machine-local Ed25519 key so a hand-edited `seals.json` fails closed.
 *
 * Store shape (`~/.contextlock/seals.json`):
 * {
 *   "spec_version": "contextlock-seals/1",
 *   "entries": [ { path, sha256, length, sealed_at, note? } ],
 *   "sig": { key_fingerprint, signature }
 * }
 * The signature is Ed25519 over canonicalJson({spec_version, entries}).
 *
 * Load MUST verify the signature: a missing store is fine (empty), but a corrupt
 * or signature-invalid store is LOUD (state "unavailable"), and every protected
 * file must then be treated as unverifiable rather than silently unsealed.
 */

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalize } from "./canonicalize.js";
import { normalizeFileOnDisk } from "./canonicalize.js";
import { sha256 } from "./hash.js";
import {
  contextlockHome,
  ensureContextlockHome,
  signWithLocalKey,
  verifyWithLocalKey,
  canonicalJson,
} from "./localkey.js";

export const SEAL_STORE_SPEC = "contextlock-seals/1" as const;
const SEAL_STORE_FILENAME = "seals.json";

export interface SealEntry {
  /** Absolute path; on win32 the lowercased resolved path. */
  path: string;
  /** SHA-256 (lowercase hex) of the normalized bytes written at seal time. */
  sha256: string;
  /** Byte length of the sealed (normalized) content. */
  length: number;
  /** ISO 8601 timestamp of when the file was sealed. */
  sealed_at: string;
  /** Optional human note. */
  note?: string;
}

interface SealStoreFile {
  spec_version: typeof SEAL_STORE_SPEC;
  entries: SealEntry[];
  sig: { key_fingerprint: string; signature: string };
}

export type SealStatus = "sealed" | "seal-modified" | "unsealed" | "store-unavailable";

export interface SealVerdict {
  status: SealStatus;
  expectedHash?: string;
  actualHash?: string;
  /** Diagnostic: the only difference vs. expected is line endings (CRLF vs LF). */
  lineEndingsOnly?: boolean;
  sealedAt?: string;
  note?: string;
  reason?: string;
}

type LoadState = "empty" | "loaded" | "unavailable";

export class SealStore {
  private entries: SealEntry[] = [];
  private state: LoadState = "empty";
  private error?: string;
  private readonly storePath: string;

  constructor(storePath?: string) {
    this.storePath = storePath ?? join(contextlockHome(), SEAL_STORE_FILENAME);
  }

  /** Path to the backing seals.json file. */
  get path(): string {
    return this.storePath;
  }

  /** False only when the store is corrupt or its signature failed (loud state). */
  get available(): boolean {
    return this.state !== "unavailable";
  }

  /** Human-readable reason the store is unavailable, if any. */
  get unavailableReason(): string | undefined {
    return this.error;
  }

  /**
   * Loads and verifies the store. Never throws: a missing store is empty; a
   * corrupt/bad-signature store sets state=unavailable so callers can render
   * "seal store unavailable: possible tampering" and fail closed.
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
      this.error = `seal store unavailable: cannot read ${this.storePath}: ${(e as Error).message}`;
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.state = "unavailable";
      this.error = "seal store unavailable: corrupt (invalid JSON) - possible tampering";
      return;
    }

    const data = parsed as Partial<SealStoreFile> | null;
    if (
      data == null ||
      typeof data !== "object" ||
      data.spec_version !== SEAL_STORE_SPEC ||
      !Array.isArray(data.entries) ||
      data.sig == null ||
      typeof data.sig.signature !== "string"
    ) {
      this.state = "unavailable";
      this.error = "seal store unavailable: bad schema - possible tampering";
      return;
    }

    const payload = canonicalJson({ spec_version: data.spec_version, entries: data.entries });
    const { valid } = await verifyWithLocalKey(Buffer.from(payload, "utf-8"), data.sig.signature);
    if (!valid) {
      this.state = "unavailable";
      this.error = "seal store unavailable: signature invalid - possible tampering";
      return;
    }

    this.entries = data.entries;
    this.state = "loaded";
  }

  /** Signs and writes the store with the machine-local key. */
  async save(): Promise<void> {
    await ensureContextlockHome();
    const payload = { spec_version: SEAL_STORE_SPEC, entries: this.entries };
    const canonical = canonicalJson(payload);
    const { signature, keyFingerprint } = await signWithLocalKey(Buffer.from(canonical, "utf-8"));
    const data: SealStoreFile = {
      ...payload,
      sig: { key_fingerprint: keyFingerprint, signature },
    };
    await writeFile(this.storePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
    this.state = this.entries.length > 0 ? "loaded" : "empty";
  }

  /** Canonical store key for a path (absolute; win32 lowercased resolved). */
  static sealKey(filePath: string): string {
    const abs = resolve(filePath);
    return process.platform === "win32" ? abs.toLowerCase() : abs;
  }

  /**
   * Seals a file: normalize it on disk (UTF-8, LF, no BOM), hash the resulting
   * raw bytes, and upsert the entry. Persists the store. Prints a warning
   * naming the file when normalization actually rewrote it (SPEC v2 6.1).
   */
  async sealFile(filePath: string, note?: string): Promise<SealEntry> {
    if (!this.available) {
      throw new Error(this.error ?? "seal store unavailable");
    }
    if (await normalizeFileOnDisk(filePath)) {
      console.warn(
        `[ContextLock] Normalized ${filePath} to UTF-8/LF/no-BOM before sealing.`,
      );
    }
    const key = SealStore.sealKey(filePath);
    const raw = await readFile(filePath);
    const entry: SealEntry = {
      path: key,
      sha256: sha256(raw),
      length: raw.length,
      sealed_at: new Date().toISOString(),
    };
    if (note !== undefined && note !== "") {
      entry.note = note;
    }
    const idx = this.entries.findIndex((e) => e.path === key);
    if (idx >= 0) {
      this.entries[idx] = entry;
    } else {
      this.entries.push(entry);
    }
    await this.save();
    return entry;
  }

  /** Deliberate re-approval after an intended edit. Identical to sealFile. */
  async resealFile(filePath: string, note?: string): Promise<SealEntry> {
    return this.sealFile(filePath, note);
  }

  /** Removes a file's seal. Returns whether an entry was removed. */
  async unsealFile(filePath: string): Promise<boolean> {
    if (!this.available) {
      throw new Error(this.error ?? "seal store unavailable");
    }
    const key = SealStore.sealKey(filePath);
    const before = this.entries.length;
    this.entries = this.entries.filter((e) => e.path !== key);
    const removed = this.entries.length < before;
    if (removed) {
      await this.save();
    }
    return removed;
  }

  /**
   * Verifies a file against its seal (if any). Hashes exact bytes on disk. On a
   * mismatch, additionally computes the LF-normalized hash as a diagnostic to
   * flag a line-endings-only difference (verdict stays seal-modified).
   */
  async verifySeal(filePath: string): Promise<SealVerdict> {
    if (!this.available) {
      return { status: "store-unavailable", reason: this.error };
    }
    const key = SealStore.sealKey(filePath);
    const entry = this.entries.find((e) => e.path === key);
    if (!entry) {
      return { status: "unsealed" };
    }

    let raw: Buffer;
    try {
      raw = await readFile(filePath);
    } catch {
      return {
        status: "seal-modified",
        expectedHash: entry.sha256,
        reason: "sealed file cannot be read",
        sealedAt: entry.sealed_at,
        note: entry.note,
      };
    }

    const actualHash = sha256(raw);
    if (actualHash === entry.sha256) {
      return {
        status: "sealed",
        expectedHash: entry.sha256,
        actualHash,
        sealedAt: entry.sealed_at,
        note: entry.note,
      };
    }

    const normalizedHash = sha256(canonicalize(raw));
    return {
      status: "seal-modified",
      expectedHash: entry.sha256,
      actualHash,
      lineEndingsOnly: normalizedHash === entry.sha256,
      sealedAt: entry.sealed_at,
      note: entry.note,
    };
  }

  /** Returns a copy of all seal entries. */
  listSeals(): SealEntry[] {
    return this.entries.map((e) => ({ ...e }));
  }
}
