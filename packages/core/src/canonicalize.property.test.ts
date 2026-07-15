// Feature: contextlock, Property 1: Write-path normalization idempotence
// Validates: Requirements 1.1, 1.2, 1.3 (moved to the WRITE path per SPEC v2 6.1)
//
// SPEC v2: canonicalization happens once, at sign/seal time, on the artifact
// itself. Verification hashes exact bytes. The idempotence property therefore
// now guards the write path: normalizing an already-normalized file must be a
// no-op, so repeated seal/build-manifest runs never rewrite or hash-drift.

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { canonicalize, normalizeContent } from "./canonicalize.js";

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
      return addBom ? "﻿" + body : body;
    })
  );

describe("Property 1: Write-path normalization idempotence", () => {
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

  it("normalizeContent reports changed=false on already-normalized content (stable write path)", () => {
    fc.assert(
      fc.property(mixedLineEndingContent, (content) => {
        const buf = Buffer.from(content, "utf-8");
        const first = normalizeContent(buf);
        const second = normalizeContent(first.content);
        // Second pass must be a no-op: nothing to rewrite, bytes identical.
        expect(second.changed).toBe(false);
        expect(second.content).toEqual(first.content);
      }),
      { numRuns: 200 }
    );
  });
});
