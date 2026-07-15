/**
 * protect command — Unified publisher action to make files verifiable.
 *
 * Supports two modes:
 *   1. "hash" — Filename change hints (Mode 1: a development convenience for
 *      visible change detection, NOT a security mode - SPEC v2 5)
 *   2. "sign" — Signed contextlock/2 manifest in a DSSE envelope (Mode 2)
 *
 * Sign mode is a one-shot flow: init-key (if needed) -> build manifest
 * (normalize + lint + hash) -> DSSE envelope. The only shipped artifact is
 * `contextlock.dsse.json`.
 */

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { initKey, defaultKeyId, PRIVATE_KEY_FILENAME } from "./init-key.js";
import { buildManifest } from "./build-manifest.js";
import { signManifest } from "./sign-manifest.js";
import { hashFilename } from "./hash-filename.js";
import {
  findProtectedFiles,
  computeFingerprint,
  base64urlDecode,
  DEFAULT_PATTERNS,
  ENVELOPE_FILENAME,
} from "@contextlock/core";
import type { LintRule } from "@contextlock/core";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import type { HashFilenameResult } from "./hash-filename.js";
import type { BuildManifestResult } from "./build-manifest.js";
import type { SignManifestResult } from "./sign-manifest.js";
import type { InitKeyResult } from "./init-key.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export type ProtectMode = "hash" | "sign";

export interface ProtectOptions {
  /** Directory containing files to protect. */
  directory: string;
  /** Protection mode: "hash" for filename change hints, "sign" for signed manifest. */
  mode: ProtectMode;
  /** Package name (required for "sign" mode). */
  packageName?: string;
  /** Monotonic integer version (anti-rollback counter). Defaults to 1. */
  version?: number;
  /** Human-facing version string (informational). */
  displayVersion?: string;
  /** Publisher display name (required for "sign" mode). */
  publisherName?: string;
  /** Short key label recorded as publisher.key_id and the DSSE keyid hint. */
  keyId?: string;
  /** ISO 8601 manifest expiry (default now + expiresDays). */
  expiresAt?: string;
  /** Validity window in days (default 365). */
  expiresDays?: number;
  /** Lint rules explicitly allowed despite hits. */
  allowLints?: LintRule[];
  /** Path to existing private key file. If omitted in "sign" mode, a new keypair is generated. */
  privateKeyPath?: string;
  /** Directory to store generated keys (defaults to the package directory). */
  keyOutputDir?: string;
  /** Glob patterns for protected files (defaults to DEFAULT_PATTERNS). */
  patterns?: string[];
  /** Number of hex chars to embed in filename (for "hash" mode, default 16). */
  hashLength?: number;
}

export interface ProtectResult {
  mode: ProtectMode;
  directory: string;
  filesProtected: number;
  /** Present in "hash" mode — one result per file. */
  hashResults?: HashFilenameResult[];
  /** Present in "sign" mode. */
  keyResult?: InitKeyResult;
  /** Present in "sign" mode. */
  buildResult?: BuildManifestResult;
  /** Present in "sign" mode. */
  signResult?: SignManifestResult;
  /** True if a new keypair was generated (sign mode only). */
  keyGenerated?: boolean;
}

/**
 * Protect files in a directory using the chosen mode.
 */
export async function protect(options: ProtectOptions): Promise<ProtectResult> {
  const {
    directory,
    mode,
    patterns = DEFAULT_PATTERNS,
    hashLength = 16,
  } = options;

  // Find protected files in the directory
  const protectedFiles = await findProtectedFiles(directory, patterns);

  if (protectedFiles.length === 0) {
    return { mode, directory, filesProtected: 0 };
  }

  if (mode === "hash") {
    // ---- Filename change-hint mode ----
    const hashResults: HashFilenameResult[] = [];
    for (const relPath of protectedFiles) {
      const fullPath = join(directory, relPath);
      const result = await hashFilename({ filePath: fullPath, hashLength });
      hashResults.push(result);
    }
    return {
      mode,
      directory,
      filesProtected: hashResults.length,
      hashResults,
    };
  }

  // ---- Signed-manifest mode (contextlock/2 + DSSE) ----
  const packageName = options.packageName ?? "unnamed-package";
  const version = options.version ?? 1;
  const publisherName = options.publisherName ?? "unknown";
  const keyDir = options.keyOutputDir ?? directory;

  // Generate or locate keypair
  let keyResult: InitKeyResult | undefined;
  let keyGenerated = false;
  let privateKeyPath = options.privateKeyPath;

  if (!privateKeyPath) {
    // Check if keys already exist in the directory (current or legacy name)
    const existing = [PRIVATE_KEY_FILENAME, "tcv-private.key"]
      .map((name) => join(keyDir, name))
      .find((p) => existsSync(p));
    if (existing) {
      privateKeyPath = existing;
    } else {
      keyResult = await initKey({ output: keyDir, keyId: options.keyId });
      privateKeyPath = keyResult.privateKeyPath;
      keyGenerated = true;
    }
  }

  // Derive the fingerprint from the private key itself (no reliance on a
  // matching public-key file being present).
  let fingerprint: string;
  if (keyResult) {
    fingerprint = keyResult.fingerprint;
  } else {
    const raw = (await readFile(privateKeyPath!, "utf-8")).trim();
    const seed = base64urlDecode(raw);
    if (seed.length !== 32) {
      throw new Error(`private key at ${privateKeyPath} is malformed (expected raw 32 bytes)`);
    }
    const publicKey = await ed.getPublicKeyAsync(seed);
    fingerprint = computeFingerprint(Buffer.from(publicKey));
  }

  const keyId = options.keyId ?? keyResult?.keyId ?? defaultKeyId(fingerprint);

  // Build manifest in memory (no unsigned intermediate on disk in protect flow)
  const buildResult = await buildManifest({
    directory,
    packageName,
    version,
    displayVersion: options.displayVersion,
    publisherName,
    keyId,
    expiresAt: options.expiresAt,
    expiresDays: options.expiresDays,
    allowLints: options.allowLints,
    patterns,
    write: false,
  });

  // Sign the exact manifest bytes into the DSSE envelope
  const signResult = await signManifest({
    manifestBytes: buildResult.manifestJson,
    privateKeyPath: privateKeyPath!,
    keyId,
    outputPath: join(directory, ENVELOPE_FILENAME),
  });

  return {
    mode,
    directory,
    filesProtected: buildResult.fileCount,
    keyResult,
    buildResult,
    signResult,
    keyGenerated,
  };
}
