import { readFile, writeFile } from "node:fs/promises";

/**
 * Canonicalizes file content for consistent hashing across platforms.
 *
 * SPEC v2 6.1: canonicalization is a WRITE-PATH operation only. Verification
 * hashes the exact bytes on disk; publishers and the `seal` command normalize
 * the file once at sign time (see normalizeFileOnDisk), then hash what was
 * written. This function is retained as the normalization primitive plus a
 * verify-time line-endings-only DIAGNOSTIC (never a verdict input).
 *
 * - Strips UTF-8 BOM (0xEF 0xBB 0xBF) if present
 * - Converts CRLF (\r\n) and lone CR (\r) to LF (\n)
 *
 * @param content - Raw file content as a Buffer
 * @returns Canonicalized content as a Buffer
 */
export function canonicalize(content: Buffer): Buffer {
  let start = 0;

  // Strip UTF-8 BOM
  if (
    content.length >= 3 &&
    content[0] === 0xef &&
    content[1] === 0xbb &&
    content[2] === 0xbf
  ) {
    start = 3;
  }

  // Fast path: scan for CR bytes. If none exist and no BOM, return as-is.
  let hasCR = false;
  for (let i = start; i < content.length; i++) {
    if (content[i] === 0x0d) {
      hasCR = true;
      break;
    }
  }

  if (!hasCR && start === 0) {
    return content;
  }

  if (!hasCR) {
    // BOM only - return slice after BOM
    return content.subarray(start);
  }

  // Normalize line endings: CRLF -> LF, lone CR -> LF
  const out: number[] = [];
  for (let i = start; i < content.length; i++) {
    if (content[i] === 0x0d) {
      out.push(0x0a); // LF
      // Skip the LF in a CRLF pair
      if (i + 1 < content.length && content[i + 1] === 0x0a) {
        i++;
      }
    } else {
      out.push(content[i]);
    }
  }

  return Buffer.from(out);
}

/**
 * Pure write-path helper: returns the normalized bytes (UTF-8, LF, no BOM)
 * and whether normalization changed anything.
 */
export function normalizeContent(content: Buffer): { content: Buffer; changed: boolean } {
  const normalized = canonicalize(content);
  return { content: normalized, changed: !normalized.equals(content) };
}

/**
 * Normalizes a file on disk to UTF-8, LF, no BOM (SPEC v2 6.1 write path).
 * Rewrites the file only when normalization actually changes the bytes.
 *
 * @returns true if the file was rewritten, false if it was already normalized.
 */
export async function normalizeFileOnDisk(filePath: string): Promise<boolean> {
  const raw = await readFile(filePath);
  const { content, changed } = normalizeContent(raw);
  if (changed) {
    await writeFile(filePath, content);
  }
  return changed;
}
