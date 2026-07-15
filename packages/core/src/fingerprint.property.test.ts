// Feature: contextlock, Property 8: Key fingerprint is SHA-256 of public key
// Validates: Requirements 5.2, 20.1, 20.2

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { sha256, computeFingerprint } from "./hash.js";

describe("Property 8: Key fingerprint is SHA-256 of public key", () => {
  it("computeFingerprint(key) equals sha256(key) for any 32-byte public key", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (rawKey) => {
          const key = Buffer.from(rawKey);
          const fingerprint = computeFingerprint(key);
          const expected = sha256(key);

          // Fingerprint must equal SHA-256 hex of the public key bytes
          expect(fingerprint).toBe(expected);

          // Must be lowercase hex, 64 characters (256 bits)
          expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
        }
      ),
      { numRuns: 200 }
    );
  });
});
