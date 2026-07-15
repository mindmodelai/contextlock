/**
 * protect command — Unified publisher action to make files verifiable.
 *
 * Supports two modes:
 *   1. "hash" — Lightweight filename-hash protection (no keys needed)
 *   2. "sign" — Full signed-manifest protection (Ed25519 keypair required)
 *
 * This is the primary publisher-facing command. It wraps init-key,
 * build-manifest, sign-manifest, and hash-filename into a single flow.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { initKey } from "./init-key.js";
import { buildManifest } from "./build-manifest.js";
import { signManifest } from "./sign-manifest.js";
import { hashFilename } from "./hash-filename.js";
import { findProtectedFiles, DEFAULT_PATTERNS } from "@contextlock/core";
import type { HashFilenameResult } from "./hash-filename.js";
import type { BuildManifestResult } from "./build-manifest.js";
import type { SignManifestResult } from "./sign-manifest.js";
import type { InitKeyResult } from "./init-key.js";

export type ProtectMode = "hash" | "sign";

export interface ProtectOptions {
  /** Directory containing files to protect. */
  directory: string;
  /** Protection mode: "hash" for filename-hash, "sign" for signed manifest. */
  mode: ProtectMode;
  /** Package name (required for "sign" mode). */
  packageName?: string;
  /** Package version (required for "sign" mode). */
  version?: string;
  /** Publisher display name (required for "sign" mode). */
  publisherName?: string;
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
 *
 * Hash mode:  Produces hash-embedded filename copies for each protected file.
 * Sign mode:  Generates keypair (if needed), builds manifest, signs it.
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
    // ---- Filename-hash mode ----
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

  // ---- Signed-manifest mode ----
  const packageName = options.packageName ?? "unnamed-package";
  const version = options.version ?? "0.0.0";
  const publisherName = options.publisherName ?? "unknown";
  const keyDir = options.keyOutputDir ?? directory;

  // Generate or locate keypair
  let keyResult: InitKeyResult | undefined;
  let keyGenerated = false;
  let privateKeyPath = options.privateKeyPath;

  if (!privateKeyPath) {
    // Check if keys already exist in the directory
    const existingPriv = join(keyDir, "tcv-private.key");
    if (existsSync(existingPriv)) {
      privateKeyPath = existingPriv;
    } else {
      keyResult = await initKey({ output: keyDir });
      privateKeyPath = keyResult.privateKeyPath;
      keyGenerated = true;
    }
  }

  // Derive fingerprint from the private key's corresponding public key
  let fingerprint: string;
  if (keyResult) {
    fingerprint = keyResult.fingerprint;
  } else {
    // Read existing public key to get fingerprint
    const { readFile } = await import("node:fs/promises");
    const { computeFingerprint } = await import("@contextlock/core");
    const pubKeyPath = privateKeyPath!.replace("private", "public");
    const pubB64 = (await readFile(pubKeyPath, "utf-8")).trim();
    fingerprint = computeFingerprint(Buffer.from(pubB64, "base64"));
  }

  // Build manifest
  const buildResult = await buildManifest({
    directory,
    packageName,
    version,
    publisherName,
    keyId: fingerprint,
    fingerprint,
    patterns,
  });

  // Sign manifest
  const signResult = await signManifest({
    manifestPath: buildResult.manifestPath,
    privateKeyPath: privateKeyPath!,
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
