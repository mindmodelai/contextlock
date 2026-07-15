// Feature: contextlock, Property 2: Cross-platform hash equivalence
// Validates: Requirements 1.4

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { canonicalize } from "./canonicalize.js";
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

describe("Property 2: Cross-platform hash equivalence", () => {
  it("SHA-256 of canonicalized content is identical across LF, CRLF, CR, and BOM variants", () => {
    fc.assert(
      fc.property(baseStringNoCrLf, (lines) => {
        // Create 4 variants from the same base lines
        const lfContent = lines.join("\n");
        const crlfContent = lines.join("\r\n");
        const crContent = lines.join("\r");
        const bomContent = "\uFEFF" + lfContent;

        // Canonicalize each variant and compute SHA-256
        const hashLf = sha256(canonicalize(Buffer.from(lfContent, "utf-8")));
        const hashCrlf = sha256(canonicalize(Buffer.from(crlfContent, "utf-8")));
        const hashCr = sha256(canonicalize(Buffer.from(crContent, "utf-8")));
        const hashBom = sha256(canonicalize(Buffer.from(bomContent, "utf-8")));

        // All 4 hashes must be identical
        expect(hashCrlf).toBe(hashLf);
        expect(hashCr).toBe(hashLf);
        expect(hashBom).toBe(hashLf);
      }),
      { numRuns: 200 }
    );
  });
});
