/**
 * Verification Engine - orchestrates the full ContextLock verification flow.
 *
 * SPEC v2: consults TWO evidence sources for every file:
 *   - the machine-local SEAL store (Mode 0, trust-on-first-use), and
 *   - the signed MANIFEST chain (Mode 2, publisher trust, existing v1 logic).
 *
 * Hashing is over the EXACT bytes on disk (SPEC v2 6.1); canonicalization is
 * used only as a line-endings-only diagnostic on a mismatch.
 */

import { readFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import {
  parseManifest,
  parseSignature,
  validateManifest,
  validateSignature,
} from "./manifest.js";
import type { Manifest, DetachedSignature } from "./manifest.js";
import { verifySignature } from "./signature.js";
import { TrustStore } from "./trust-store.js";
import { sha256 } from "./hash.js";
import { canonicalize } from "./canonicalize.js";
import { SealStore } from "./seal.js";
import { isProtectedFile } from "./detector.js";
import type { PolicyLevel } from "./policy.js";

// ---- Types ----

export type VerificationStatus =
  | "trusted"
  | "sealed"
  | "sealed+trusted"
  | "modified"
  | "untrusted"
  | "revoked"
  | "expired"
  | "error"
  | "seal-store-unavailable";

export interface VerificationResult {
  status: VerificationStatus;
  publisher?: string;
  keyId?: string;
  manifestSource?: string;
  fileHash?: string;
  expectedHash?: string;
  reason?: string;
  expiresAt?: string;
  warning?: string;
  /** Seal timestamp when the verdict rests on a local seal. */
  sealedAt?: string;
}

export interface VerificationEngineConfig {
  trustStorePath: string;
  cachePath: string;
  protectedPatterns: string[];
  policyLevel: PolicyLevel;
  /** Optional override for the seal store path. Defaults to CONTEXTLOCK_HOME/seals.json. */
  sealStorePath?: string;
}

// ---- Helpers ----

const MANIFEST_FILENAME = "manifest.json";
const SIGNATURE_FILENAME = "manifest.sig.json";

const LINE_ENDINGS_HINT =
  "difference is line endings only (CRLF vs LF); re-seal or restore LF endings";

/**
 * Walk up from `startDir` looking for manifest.json + manifest.sig.json.
 * Returns the directory containing both, or undefined if not found.
 */
async function locateManifestDir(startDir: string): Promise<string | undefined> {
  let current = resolve(startDir);
  const root = resolve("/");

  while (true) {
    const manifestPath = join(current, MANIFEST_FILENAME);
    const sigPath = join(current, SIGNATURE_FILENAME);
    try {
      await readFile(manifestPath);
      await readFile(sigPath);
      return current;
    } catch {
      // files not found in this directory - walk up
    }
    const parent = dirname(current);
    if (parent === current || parent === root) {
      break;
    }
    current = parent;
  }
  return undefined;
}

// ---- VerificationEngine ----

export class VerificationEngine {
  private config: VerificationEngineConfig;

  constructor(config: VerificationEngineConfig) {
    this.config = config;
  }

  /**
   * Returns true if the file path matches any of the configured protected patterns.
   */
  isProtected(filePath: string): boolean {
    return isProtectedFile(filePath, this.config.protectedPatterns);
  }

  /**
   * Verify a manifest + signature pair without checking individual files.
   * Returns a VerificationResult reflecting the manifest-level verification status.
   */
  async verifyManifest(
    manifestPath: string,
    signaturePath: string,
  ): Promise<VerificationResult> {
    // 1. Read manifest
    let manifestContent: Buffer;
    try {
      manifestContent = await readFile(manifestPath);
    } catch {
      return { status: "error", reason: `cannot read manifest: ${manifestPath}` };
    }

    // 2. Parse & validate manifest
    let manifest: Manifest;
    try {
      manifest = parseManifest(manifestContent.toString("utf-8"));
    } catch (e) {
      return { status: "error", reason: `invalid manifest: ${(e as Error).message}` };
    }

    const manifestErrors = validateManifest(manifest);
    if (manifestErrors.length > 0) {
      return {
        status: "error",
        reason: `manifest validation failed: ${manifestErrors.map((e) => e.message).join("; ")}`,
      };
    }

    // 3. Read signature
    let sigContent: Buffer;
    try {
      sigContent = await readFile(signaturePath);
    } catch {
      return { status: "error", reason: `cannot read signature: ${signaturePath}` };
    }

    // 4. Parse & validate signature
    let signature: DetachedSignature;
    try {
      signature = parseSignature(sigContent.toString("utf-8"));
    } catch (e) {
      return { status: "error", reason: `invalid signature: ${(e as Error).message}` };
    }

    const sigErrors = validateSignature(signature);
    if (sigErrors.length > 0) {
      return {
        status: "error",
        reason: `signature validation failed: ${sigErrors.map((e) => e.message).join("; ")}`,
      };
    }

    // 5. Load trust store
    const trustStore = new TrustStore();
    try {
      await trustStore.load(this.config.trustStorePath);
    } catch (e) {
      return { status: "error", reason: `cannot load trust store: ${(e as Error).message}` };
    }

    // 6. Verify signature
    const sigResult = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    if (!sigResult.valid) {
      if (sigResult.reason === "key revoked") {
        return {
          status: "revoked",
          keyId: sigResult.keyId,
          publisher: sigResult.publisher,
          reason: sigResult.reason,
        };
      }
      if (sigResult.reason === "unknown signing key") {
        return {
          status: "untrusted",
          keyId: sigResult.keyId,
          reason: sigResult.reason,
        };
      }
      if (sigResult.reason === "manifest hash mismatch") {
        return {
          status: "error",
          reason: sigResult.reason,
        };
      }
      return {
        status: "untrusted",
        keyId: sigResult.keyId,
        publisher: sigResult.publisher,
        reason: sigResult.reason ?? "signature verification failed",
      };
    }

    // 7. Check manifest revocation status
    if (manifest.revocation && manifest.revocation.status !== "active") {
      return {
        status: "revoked",
        keyId: sigResult.keyId,
        publisher: sigResult.publisher,
        reason: "manifest revoked",
      };
    }

    // 8. Check manifest expiry
    if (manifest.expires_at) {
      const expiresAt = new Date(manifest.expires_at);
      if (expiresAt.getTime() < Date.now()) {
        const publisherEntry = trustStore.getPublisher(signature.key_id);
        const allowExpired = publisherEntry?.policy?.allow_expired_manifest ?? false;

        if (!allowExpired) {
          return {
            status: "expired",
            expiresAt: manifest.expires_at,
            keyId: sigResult.keyId,
            publisher: sigResult.publisher,
          };
        }
        return {
          status: "trusted",
          publisher: sigResult.publisher,
          keyId: sigResult.keyId,
          expiresAt: manifest.expires_at,
          warning: "manifest is expired but allowed by publisher policy",
        };
      }
    }

    return {
      status: "trusted",
      publisher: sigResult.publisher,
      keyId: sigResult.keyId,
      manifestSource: manifestPath,
    };
  }

  /**
   * Full verification flow for a single file, combining seal + manifest evidence.
   *
   * Combination rules (SPEC v2 5):
   *   seal ok + no manifest     -> sealed
   *   seal ok + manifest trusted-> sealed+trusted
   *   seal mismatch             -> modified  (seal wins: the user pinned it)
   *   no seal + manifest trusted-> trusted
   *   seal store unavailable    -> seal-store-unavailable (fail closed)
   *   otherwise                 -> the manifest verdict (untrusted/modified/...)
   */
  async verify(filePath: string): Promise<VerificationResult> {
    const absPath = resolve(filePath);

    // 1. Seal evidence (Mode 0). A corrupt/tampered store fails closed for
    //    every file rather than silently reporting "unsealed".
    const sealStore = new SealStore(this.config.sealStorePath);
    await sealStore.load();
    const sealVerdict = await sealStore.verifySeal(absPath);

    if (sealVerdict.status === "store-unavailable") {
      return {
        status: "seal-store-unavailable",
        reason:
          sealVerdict.reason ??
          "seal store unavailable: possible tampering (treat as unverifiable)",
      };
    }

    // Seal mismatch wins over any manifest verdict: the user explicitly pinned
    // these bytes, so a change is a violation regardless of publisher status.
    if (sealVerdict.status === "seal-modified") {
      const reason = sealVerdict.lineEndingsOnly
        ? `sealed content modified; ${LINE_ENDINGS_HINT}`
        : "sealed content modified since it was sealed";
      return {
        status: "modified",
        expectedHash: sealVerdict.expectedHash,
        fileHash: sealVerdict.actualHash,
        reason,
        sealedAt: sealVerdict.sealedAt,
      };
    }

    // 2. Manifest evidence (Mode 2).
    const manifestResult = await this.verifyViaManifest(absPath);

    // 3. Combine.
    if (sealVerdict.status === "sealed") {
      if (manifestResult.status === "trusted") {
        return { ...manifestResult, status: "sealed+trusted", sealedAt: sealVerdict.sealedAt };
      }
      return {
        status: "sealed",
        fileHash: sealVerdict.actualHash,
        expectedHash: sealVerdict.expectedHash,
        sealedAt: sealVerdict.sealedAt,
        reason: sealVerdict.note
          ? `sealed via local trust-on-first-use (${sealVerdict.note})`
          : "sealed via local trust-on-first-use",
      };
    }

    // Unsealed: the manifest verdict stands.
    return manifestResult;
  }

  /**
   * Manifest-chain verification for a single file. Hashes exact bytes on disk.
   * On a hash mismatch, computes the LF-normalized hash purely to append a
   * line-endings-only diagnostic (verdict stays `modified`).
   */
  private async verifyViaManifest(absPath: string): Promise<VerificationResult> {
    const fileDir = dirname(absPath);

    // 1. Locate manifest directory
    const manifestDir = await locateManifestDir(fileDir);
    if (!manifestDir) {
      return { status: "untrusted", reason: "no manifest found" };
    }

    const manifestPath = join(manifestDir, MANIFEST_FILENAME);
    const signaturePath = join(manifestDir, SIGNATURE_FILENAME);

    // 2. Read manifest
    let manifestContent: Buffer;
    try {
      manifestContent = await readFile(manifestPath);
    } catch {
      return { status: "untrusted", reason: "no manifest found" };
    }

    // 3. Parse & validate manifest
    let manifest: Manifest;
    try {
      manifest = parseManifest(manifestContent.toString("utf-8"));
    } catch (e) {
      return { status: "error", reason: `invalid manifest: ${(e as Error).message}` };
    }

    const manifestErrors = validateManifest(manifest);
    if (manifestErrors.length > 0) {
      return {
        status: "error",
        reason: `manifest validation failed: ${manifestErrors.map((e) => e.message).join("; ")}`,
      };
    }

    // 4. Read & parse signature
    let sigContent: Buffer;
    try {
      sigContent = await readFile(signaturePath);
    } catch {
      return { status: "error", reason: `cannot read signature: ${signaturePath}` };
    }

    let signature: DetachedSignature;
    try {
      signature = parseSignature(sigContent.toString("utf-8"));
    } catch (e) {
      return { status: "error", reason: `invalid signature: ${(e as Error).message}` };
    }

    const sigErrors = validateSignature(signature);
    if (sigErrors.length > 0) {
      return {
        status: "error",
        reason: `signature validation failed: ${sigErrors.map((e) => e.message).join("; ")}`,
      };
    }

    // 5. Load trust store
    const trustStore = new TrustStore();
    try {
      await trustStore.load(this.config.trustStorePath);
    } catch (e) {
      return { status: "error", reason: `cannot load trust store: ${(e as Error).message}` };
    }

    // 6. Verify signature
    const sigResult = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    if (!sigResult.valid) {
      if (sigResult.reason === "key revoked") {
        return {
          status: "revoked",
          keyId: sigResult.keyId,
          publisher: sigResult.publisher,
          reason: sigResult.reason,
        };
      }
      if (sigResult.reason === "unknown signing key") {
        return {
          status: "untrusted",
          keyId: sigResult.keyId,
          reason: sigResult.reason,
        };
      }
      if (sigResult.reason === "manifest hash mismatch") {
        return { status: "error", reason: sigResult.reason };
      }
      return {
        status: "untrusted",
        keyId: sigResult.keyId,
        publisher: sigResult.publisher,
        reason: sigResult.reason ?? "signature verification failed",
      };
    }

    // 7. Check manifest revocation status
    if (manifest.revocation && manifest.revocation.status !== "active") {
      return {
        status: "revoked",
        keyId: sigResult.keyId,
        publisher: sigResult.publisher,
        reason: "manifest revoked",
      };
    }

    // 8. Check manifest expiry
    let expiryWarning: string | undefined;
    if (manifest.expires_at) {
      const expiresAt = new Date(manifest.expires_at);
      if (expiresAt.getTime() < Date.now()) {
        const publisherEntry = trustStore.getPublisher(signature.key_id);
        const allowExpired = publisherEntry?.policy?.allow_expired_manifest ?? false;

        if (!allowExpired) {
          return {
            status: "expired",
            expiresAt: manifest.expires_at,
            keyId: sigResult.keyId,
            publisher: sigResult.publisher,
          };
        }
        expiryWarning = "manifest is expired but allowed by publisher policy";
      }
    }

    // 9. Read file and hash EXACT bytes on disk (SPEC v2 6.1)
    let fileContent: Buffer;
    try {
      fileContent = await readFile(absPath);
    } catch (e) {
      return { status: "error", reason: `cannot read file: ${(e as Error).message}` };
    }

    const fileHash = sha256(fileContent);

    // 10. Find file entry in manifest by relative path
    const relPath = relative(manifestDir, absPath).replace(/\\/g, "/");
    const entry = manifest.files.find((f) => f.path === relPath);

    if (!entry) {
      return { status: "untrusted", reason: "file not listed in manifest" };
    }

    // 11. Compare hashes
    if (fileHash === entry.sha256) {
      const result: VerificationResult = {
        status: "trusted",
        publisher: sigResult.publisher,
        keyId: sigResult.keyId,
        manifestSource: manifestPath,
        fileHash,
        expectedHash: entry.sha256,
      };
      if (expiryWarning) {
        result.warning = expiryWarning;
        result.expiresAt = manifest.expires_at;
      }
      return result;
    }

    // Hash mismatch. Compute the LF-normalized hash purely for diagnostics.
    const normalizedHash = sha256(canonicalize(fileContent));
    const reason =
      normalizedHash === entry.sha256
        ? `file modified since signing; ${LINE_ENDINGS_HINT}`
        : "file modified since signing";

    return {
      status: "modified",
      fileHash,
      expectedHash: entry.sha256,
      publisher: sigResult.publisher,
      keyId: sigResult.keyId,
      reason,
    };
  }
}
