// Feature: contextlock, Property 1: Canonicalization idempotence
// Validates: Requirements 1.1, 1.2, 1.3

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { canonicalize } from "./canonicalize.js";

/**
 * Arbitrary that generates random strings with mixed line endings
 * (LF, CRLF, CR) and an optional UTF-8 BOM prefix.
 */
const mixedLineEndingContent = fc
  .array(
    fc.oneof(
      // Regular text segments (no CR/LF)
      fc.string({ minLength: 0, maxLength: 20 }).map((s) =>
        s.replace(/[\r\n]/g, "a")
      ),
      // Line ending variants
      fc.constantFrom("\n", "\r\n", "\r")
    ),
    { minLength: 0, maxLength: 30 }
  )
  .chain((parts) =>
    fc.boolean().map((addBom) => {
      const body = parts.join("");
      return addBom ? "\uFEFF" + body : body;
    })
  );

describe("Property 1: Canonicalization idempotence", () => {
  it("canonicalize(canonicalize(x)) === canonicalize(x) for arbitrary content with mixed line endings and optional BOM", () => {
    fc.assert(
      fc.property(mixedLineEndingContent, (content) => {
        const buf = Buffer.from(content, "utf-8");
        const once = canonicalize(buf);
        const twice = canonicalize(once);
        expect(twice).toEqual(once);
      }),
      { numRuns: 200 }
    );
  });
});
