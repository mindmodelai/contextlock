/**
 * verify command — Pre-publish verification of a package directory (v2).
 *
 * Checks that contextlock.dsse.json exists, verifies the envelope signature
 * when a public key is available (option, or contextlock-public.key /
 * tcv-public.key in the directory), then verifies every listed file's length
 * and hash against the VERIFIED payload (verify-then-parse). Also re-runs the
 * content lints and cross-checks the manifest's lint attestation.
 */

import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  parseEnvelope,
  parseManifest,
  envelopeVerifiesWithKey,
  b64Decode,
  base64urlDecode,
  computeFileHash,
  lintContent,
  ENVELOPE_FILENAME,
  MANIFEST_PAYLOAD_TYPE,
} from "@contextlock/core";
import type { Manifest } from "@contextlock/core";
import { PUBLIC_KEY_FILENAME } from "./init-key.js";

export interface VerifyOptions {
  directory: string;
  /** Path to the publisher public key. Auto-detected in the directory if omitted. */
  publicKeyPath?: string;
}

export interface FileVerificationResult {
  path: string;
  status: "ok" | "modified" | "missing" | "length-mismatch" | "lint-mismatch";
  expectedHash?: string;
  computedHash?: string;
}

export interface VerifyResult {
  success: boolean;
  envelopeFound: boolean;
  /** true = verified; false = failed; undefined = no public key available. */
  signatureValid?: boolean;
  fileResults: FileVerificationResult[];
  manifest?: Manifest;
  error?: string;
}

function findPublicKey(directory: string, explicit?: string): string | undefined {
  if (explicit) return explicit;
  for (const name of [PUBLIC_KEY_FILENAME, "tcv-public.key"]) {
    const candidate = join(directory, name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Performs full pre-publish verification on a package directory.
 */
export async function verify(options: VerifyOptions): Promise<VerifyResult> {
  const { directory } = options;
  const envelopePath = join(directory, ENVELOPE_FILENAME);

  let envelopeContent: Buffer;
  try {
    envelopeContent = await readFile(envelopePath);
  } catch {
    return {
      success: false,
      envelopeFound: false,
      fileResults: [],
      error: `${ENVELOPE_FILENAME} not found in package directory`,
    };
  }

  let payload: Buffer;
  let signatureValid: boolean | undefined;
  let manifest: Manifest;
  try {
    const envelope = parseEnvelope(envelopeContent);
    if (envelope.payloadType !== MANIFEST_PAYLOAD_TYPE) {
      return {
        success: false,
        envelopeFound: true,
        fileResults: [],
        error: `unexpected payloadType "${envelope.payloadType}"`,
      };
    }

    const pubKeyPath = findPublicKey(directory, options.publicKeyPath);
    if (pubKeyPath) {
      const pub = base64urlDecode((await readFile(pubKeyPath, "utf-8")).trim());
      signatureValid = await envelopeVerifiesWithKey(envelope, pub);
      if (!signatureValid) {
        return {
          success: false,
          envelopeFound: true,
          signatureValid,
          fileResults: [],
          error: "envelope signature does not verify with the publisher public key",
        };
      }
    }

    payload = b64Decode(envelope.payload);
    manifest = parseManifest(payload);
  } catch (e) {
    return {
      success: false,
      envelopeFound: true,
      signatureValid,
      fileResults: [],
      error: `Invalid envelope or manifest: ${(e as Error).message}`,
    };
  }

  // Verify each file: length before hash, then lint cross-check.
  const fileResults: FileVerificationResult[] = [];
  let allOk = true;
  const allowedRules = new Set(
    Object.entries(manifest.lints ?? {})
      .filter(([, v]) => v === "allowed")
      .map(([rule]) => rule),
  );

  for (const entry of manifest.files) {
    const filePath = join(directory, entry.path);
    let fileStat;
    try {
      fileStat = await stat(filePath);
    } catch {
      allOk = false;
      fileResults.push({ path: entry.path, status: "missing", expectedHash: entry.sha256 });
      continue;
    }
    if (fileStat.size !== entry.length) {
      allOk = false;
      fileResults.push({ path: entry.path, status: "length-mismatch", expectedHash: entry.sha256 });
      continue;
    }
    const computedHash = await computeFileHash(filePath);
    if (computedHash !== entry.sha256) {
      allOk = false;
      fileResults.push({
        path: entry.path,
        status: "modified",
        expectedHash: entry.sha256,
        computedHash,
      });
      continue;
    }
    // Lint cross-check: hits for a rule the manifest does not attest as
    // "allowed" mean the attestation is wrong (or content was crafted after
    // attestation) - refuse to publish.
    const hits = lintContent(await readFile(filePath));
    const unattested = hits.filter((h) => !allowedRules.has(h.rule));
    if (unattested.length > 0) {
      allOk = false;
      fileResults.push({
        path: entry.path,
        status: "lint-mismatch",
        expectedHash: entry.sha256,
        computedHash,
      });
      continue;
    }
    fileResults.push({
      path: entry.path,
      status: "ok",
      expectedHash: entry.sha256,
      computedHash,
    });
  }

  return {
    success: allOk,
    envelopeFound: true,
    signatureValid,
    fileResults,
    manifest,
  };
}
