/**
 * Filename Hash Extractor - extracts and verifies embedded filename hashes.
 * Requirements: 16.1, 16.2, 16.3, 16.4
 *
 * Pattern: <name>.<hex-hash>.<ext>
 * Filename hash is advisory only - never produces `trusted` status.
 */

import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { sha256 } from "./hash.js";

export interface FilenameHashResult {
  hasEmbeddedHash: boolean;
  embeddedHash?: string;
  computedHashPrefix?: string;
  matches?: boolean;
}

/**
 * Regex: <name>.<hex-hash>.<ext>
 * Requires at least 4 hex chars for the hash portion to avoid false positives.
 * The name and ext must each be at least 1 char and not purely hex.
 */
const FILENAME_HASH_RE = /^(.+)\.([0-9a-fA-F]{4,64})\.([^.]+)$/;

/**
 * Extracts the hex hash portion from a filename matching `<name>.<hex-hash>.<ext>`.
 * Returns null if the filename does not match the pattern.
 */
export function extractFilenameHash(filename: string): string | null {
  // Use only the basename (strip directory components)
  const base = basename(filename);
  const match = FILENAME_HASH_RE.exec(base);
  if (!match) return null;
  return match[2].toLowerCase();
}

/**
 * Verifies the embedded filename hash against the SHA-256 of the EXACT file
 * bytes on disk (SPEC v2 6.1: no canonicalization at verify time). Filename
 * hash is a "change hint" only (SPEC v2 Mode 1) and never produces `trusted`.
 */
export async function verifyFilenameHash(filePath: string): Promise<FilenameHashResult> {
  const embeddedHash = extractFilenameHash(filePath);
  if (embeddedHash === null) {
    return { hasEmbeddedHash: false };
  }

  const raw = await readFile(filePath);
  const fullHash = sha256(raw);
  const prefix = fullHash.substring(0, embeddedHash.length);

  return {
    hasEmbeddedHash: true,
    embeddedHash,
    computedHashPrefix: prefix,
    matches: prefix === embeddedHash,
  };
}
