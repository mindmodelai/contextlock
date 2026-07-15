// Feature: contextlock, Property 2: Cross-platform hash equivalence at the WRITE path
// Validates: Requirements 1.4 (moved to the write path per SPEC v2 6.1)
//
// SPEC v2: a publisher/sealer normalizes the artifact once (UTF-8, LF, no BOM)
// and then hashes the exact bytes written. Cross-platform equivalence is now a
// property of the write-path normalization, not the verifier: normalizing any
// line-ending variant of the same logical content yields the same bytes and
// therefore the same hash. The verifier itself hashes raw bytes, where a single
// byte flip must always be detected (new sibling property below).

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { normalizeContent } from "./canonicalize.js";
import { sha256 } from "./hash.js";

/**
 * Arbitrary that generates random base strings with no CR or LF characters.
 * These serve as the "content lines" that will be joined with different
 * line-ending styles to produce platform variants.
 */
const baseStringNoCrLf = fc
  .array(
    fc.string({ minLength: 0, maxLength: 30 }).map((s) =>
      s.replace(/[\r\n]/g, "x")
    ),
    { minLength: 1, maxLength: 10 }
  )
  .map((parts) => parts);

describe("Property 2: Cross-platform hash equivalence (write path)", () => {
  it("SHA-256 of write-path-normalized content is identical across LF, CRLF, CR, and BOM variants", () => {
    fc.assert(
      fc.property(baseStringNoCrLf, (lines) => {
        // Create 4 variants from the same base lines
        const lfContent = lines.join("\n");
        const crlfContent = lines.join("\r\n");
        const crContent = lines.join("\r");
        const bomContent = "﻿" + lfContent;

        // Normalize each variant at the write path, then hash the raw result
        const hashLf = sha256(normalizeContent(Buffer.from(lfContent, "utf-8")).content);
        const hashCrlf = sha256(normalizeContent(Buffer.from(crlfContent, "utf-8")).content);
        const hashCr = sha256(normalizeContent(Buffer.from(crContent, "utf-8")).content);
        const hashBom = sha256(normalizeContent(Buffer.from(bomContent, "utf-8")).content);

        // All 4 hashes must be identical
        expect(hashCrlf).toBe(hashLf);
        expect(hashCr).toBe(hashLf);
        expect(hashBom).toBe(hashLf);
      }),
      { numRuns: 200 }
    );
  });
});

describe("Property 2b: Single byte flip in raw content is always detected", () => {
  // SPEC v2 6.1: the verifier hashes exact bytes, so ANY single-byte change to
  // the raw content must change the SHA-256 (no normalization can mask it).
  it("flipping any single byte changes the exact-byte SHA-256", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        (bytes, idxSeed, xorMask) => {
          const original = Buffer.from(bytes);
          const idx = idxSeed % original.length;

          const flipped = Buffer.from(original);
          flipped[idx] = flipped[idx] ^ xorMask; // guaranteed different byte

          const originalHash = sha256(original);
          const flippedHash = sha256(flipped);
          expect(flippedHash).not.toBe(originalHash);
        },
      ),
      { numRuns: 300 }
    );
  });
});
