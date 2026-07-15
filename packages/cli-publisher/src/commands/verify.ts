/**
 * verify command — Pre-publish verification of a package directory.
 * Requirements: 19.1, 19.2, 19.3, 19.4
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  parseManifest,
  computeFileHash,
} from "@contextlock/core";
import type { Manifest } from "@contextlock/core";

export interface VerifyOptions {
  directory: string;
}

export interface FileVerificationResult {
  path: string;
  status: "ok" | "modified" | "missing";
  expectedHash?: string;
  computedHash?: string;
}

export interface VerifyResult {
  success: boolean;
  manifestFound: boolean;
  signatureFound: boolean;
  fileResults: FileVerificationResult[];
  error?: string;
}

/**
 * Performs full verification flow on a package directory.
 * Checks that manifest.json and manifest.sig.json exist,
 * then verifies each file's hash against the manifest.
 */
export async function verify(options: VerifyOptions): Promise<VerifyResult> {
  const { directory } = options;
  const manifestPath = join(directory, "manifest.json");
  const signaturePath = join(directory, "manifest.sig.json");

  // Check manifest exists
  let manifestContent: string;
  try {
    manifestContent = await readFile(manifestPath, "utf-8");
  } catch {
    return {
      success: false,
      manifestFound: false,
      signatureFound: false,
      fileResults: [],
      error: "manifest.json not found in package directory",
    };
  }

  // Check signature exists
  let signatureFound = true;
  try {
    await readFile(signaturePath);
  } catch {
    signatureFound = false;
  }

  // Parse manifest
  let manifest: Manifest;
  try {
    manifest = parseManifest(manifestContent);
  } catch (e) {
    return {
      success: false,
      manifestFound: true,
      signatureFound,
      fileResults: [],
      error: `Invalid manifest: ${(e as Error).message}`,
    };
  }

  // Verify each file
  const fileResults: FileVerificationResult[] = [];
  let allOk = true;

  for (const entry of manifest.files) {
    const filePath = join(directory, entry.path);
    try {
      const computedHash = await computeFileHash(filePath);
      if (computedHash === entry.sha256) {
        fileResults.push({
          path: entry.path,
          status: "ok",
          expectedHash: entry.sha256,
          computedHash,
        });
      } else {
        allOk = false;
        fileResults.push({
          path: entry.path,
          status: "modified",
          expectedHash: entry.sha256,
          computedHash,
        });
      }
    } catch {
      allOk = false;
      fileResults.push({
        path: entry.path,
        status: "missing",
        expectedHash: entry.sha256,
      });
    }
  }

  return {
    success: allOk && signatureFound,
    manifestFound: true,
    signatureFound,
    fileResults,
    error: !signatureFound ? "manifest.sig.json not found in package directory" : undefined,
  };
}
