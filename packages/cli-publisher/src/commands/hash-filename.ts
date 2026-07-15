/**
 * hash-filename command — Produce a hash-protected copy of a file.
 *
 * Renames (or copies) a file to embed a truncated SHA-256 hash in the filename:
 *   SKILL.md → SKILL.a3f5c9e8d1f24a6c.md
 *
 * This is the "easy mode" / Option 1 from the project spec.
 * It provides basic integrity checking but NOT publisher identity verification.
 * Requirements: 16.1, 16.2, 16.3, 16.4
 */

import { readFile, writeFile, copyFile } from "node:fs/promises";
import { join, dirname, basename, extname } from "node:path";
import { canonicalize, sha256 } from "@contextlock/core";

export interface HashFilenameOptions {
  filePath: string;
  /** Number of hex characters to embed (default: 16). Min 4, max 64. */
  hashLength?: number;
  /** If true, copy instead of rename — keeps the original file. */
  copy?: boolean;
  /** Output directory. Defaults to same directory as the source file. */
  outputDir?: string;
}

export interface HashFilenameResult {
  originalPath: string;
  hashedPath: string;
  hash: string;
  embeddedHash: string;
}

/**
 * Reads a file, computes its canonicalized SHA-256, and writes a copy
 * with the hash embedded in the filename.
 */
export async function hashFilename(options: HashFilenameOptions): Promise<HashFilenameResult> {
  const { filePath, hashLength = 16, copy: keepOriginal = true, outputDir } = options;

  const len = Math.max(4, Math.min(64, hashLength));

  // Read and hash
  const raw = await readFile(filePath);
  const canonical = canonicalize(raw);
  const fullHash = sha256(canonical);
  const embeddedHash = fullHash.substring(0, len);

  // Build new filename: name.hash.ext
  const dir = outputDir ?? dirname(filePath);
  const ext = extname(filePath);                       // ".md"
  const nameWithoutExt = basename(filePath, ext);      // "SKILL"
  const newName = `${nameWithoutExt}.${embeddedHash}${ext}`;
  const hashedPath = join(dir, newName);

  if (keepOriginal) {
    // Copy the original content (not canonicalized — preserve original bytes)
    await copyFile(filePath, hashedPath);
  } else {
    // Write canonicalized content to new path
    await writeFile(hashedPath, raw);
  }

  return {
    originalPath: filePath,
    hashedPath,
    hash: fullHash,
    embeddedHash,
  };
}
