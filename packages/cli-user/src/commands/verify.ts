/**
 * verify command — Verify a protected file through the full verification flow.
 * Falls back to filename-hash check when no manifest is found.
 * Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 16.1, 16.2, 16.3, 16.4
 */

import { resolve } from "node:path";
import { VerificationEngine, DEFAULT_PATTERNS, verifyFilenameHash } from "@contextlock/core";
import type { VerificationResult, VerificationEngineConfig, FilenameHashResult } from "@contextlock/core";

export interface UserVerifyOptions {
  filePath: string;
  trustStorePath: string;
  cachePath?: string;
  policyLevel?: "strict" | "balanced" | "audit";
}

export interface UserVerifyResult {
  filePath: string;
  result: VerificationResult;
  displayMessage: string;
  /** Present when filename-hash extraction was attempted. */
  filenameHash?: FilenameHashResult;
}

/**
 * Formats a verification result into a human-readable display message.
 */
function formatResult(
  filePath: string,
  result: VerificationResult,
  filenameHash?: FilenameHashResult,
): string {
  const name = filePath;

  // If we have a manifest-based result, show that first
  let line: string;
  switch (result.status) {
    case "trusted":
      line = `✓ ${name} — trusted (publisher: ${result.publisher}, key: ${result.keyId})`;
      if (result.warning) line += ` [warning: ${result.warning}]`;
      break;
    case "modified":
      line = `✗ ${name} — modified (expected: ${result.expectedHash}, computed: ${result.fileHash})`;
      break;
    case "untrusted":
      line = `✗ ${name} — untrusted (${result.reason})`;
      break;
    case "revoked":
      line = `✗ ${name} — revoked (key: ${result.keyId})`;
      break;
    case "expired":
      line = `✗ ${name} — expired (expires_at: ${result.expiresAt})`;
      break;
    case "error":
      line = `✗ ${name} — error (${result.reason})`;
      break;
  }

  // Append filename-hash info when relevant
  if (filenameHash?.hasEmbeddedHash) {
    if (filenameHash.matches) {
      line += `\n  ℹ filename hash matches (advisory — does not prove publisher identity)`;
    } else {
      line += `\n  ⚠ filename hash MISMATCH (embedded: ${filenameHash.embeddedHash}, computed: ${filenameHash.computedHashPrefix})`;
    }
  }

  return line;
}

/**
 * Verifies a single protected file.
 *
 * Flow:
 * 1. Run full manifest+signature verification via the engine.
 * 2. Always attempt filename-hash extraction (advisory info).
 * 3. If no manifest was found AND the filename has an embedded hash,
 *    report the filename-hash result as supplementary info.
 */
export async function userVerify(options: UserVerifyOptions): Promise<UserVerifyResult> {
  const { filePath, trustStorePath, cachePath = "", policyLevel = "balanced" } = options;

  const config: VerificationEngineConfig = {
    trustStorePath,
    cachePath,
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel,
  };

  const engine = new VerificationEngine(config);
  const absPath = resolve(filePath);

  // 1. Full manifest-based verification
  const result = await engine.verify(absPath);

  // 2. Filename-hash extraction (always attempted, advisory only)
  let filenameHash: FilenameHashResult | undefined;
  try {
    filenameHash = await verifyFilenameHash(absPath);
  } catch {
    // File might not exist or be unreadable — skip
  }

  const displayMessage = formatResult(filePath, result, filenameHash);

  return { filePath, result, displayMessage, filenameHash };
}
