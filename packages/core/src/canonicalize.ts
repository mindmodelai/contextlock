/**
 * Canonicalizes file content for consistent hashing across platforms.
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
    // BOM only — return slice after BOM
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
