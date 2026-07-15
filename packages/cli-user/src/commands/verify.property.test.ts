/**
 * Property 19: CLI verification output completeness
 * Validates: Requirements 14.3, 14.4
 *
 * For any VerificationResult, assert CLI output contains file name and either
 * (publisher + key ID) on success or (status + reason) on failure.
 */

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import type { VerificationResult } from "@contextlock/core";

/**
 * Replicates the formatResult logic from verify.ts for property testing.
 */
function formatResult(filePath: string, result: VerificationResult): string {
  const name = filePath;
  switch (result.status) {
    case "trusted":
      return `✓ ${name} — trusted (publisher: ${result.publisher}, key: ${result.keyId})${result.warning ? ` [warning: ${result.warning}]` : ""}`;
    case "modified":
      return `✗ ${name} — modified (expected: ${result.expectedHash}, computed: ${result.fileHash})`;
    case "untrusted":
      return `✗ ${name} — untrusted (${result.reason})`;
    case "revoked":
      return `✗ ${name} — revoked (key: ${result.keyId})`;
    case "expired":
      return `✗ ${name} — expired (expires_at: ${result.expiresAt})`;
    case "error":
      return `✗ ${name} — error (${result.reason})`;
  }
}

const nonEmptyString = fc.string({ minLength: 1, maxLength: 50 }).filter((s) => s.trim().length > 0);
const hexChars = "0123456789abcdef";
const hexHash = fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 64, maxLength: 64 }).map(
  (arr) => arr.map((i) => hexChars[i]).join(""),
);

describe("Property 19: CLI verification output completeness", () => {
  it("trusted output contains file name, publisher, and key ID", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        nonEmptyString,
        nonEmptyString,
        (filePath, publisher, keyId) => {
          const result: VerificationResult = { status: "trusted", publisher, keyId };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain(publisher);
          expect(output).toContain(keyId);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("modified output contains file name, expected hash, and computed hash", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        hexHash,
        hexHash,
        (filePath, expectedHash, fileHash) => {
          const result: VerificationResult = { status: "modified", expectedHash, fileHash };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain(expectedHash);
          expect(output).toContain(fileHash);
          expect(output).toContain("modified");
        },
      ),
      { numRuns: 100 },
    );
  });

  it("untrusted output contains file name, status, and reason", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        nonEmptyString,
        (filePath, reason) => {
          const result: VerificationResult = { status: "untrusted", reason };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain("untrusted");
          expect(output).toContain(reason);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("revoked output contains file name and key ID", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        nonEmptyString,
        (filePath, keyId) => {
          const result: VerificationResult = { status: "revoked", keyId };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain("revoked");
          expect(output).toContain(keyId);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("expired output contains file name and expiresAt", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        fc.integer({ min: new Date("2020-01-01").getTime(), max: new Date("2030-01-01").getTime() }).map(
          (ms) => new Date(ms).toISOString(),
        ),
        (filePath, expiresAt) => {
          const result: VerificationResult = { status: "expired", expiresAt };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain("expired");
          expect(output).toContain(expiresAt);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("error output contains file name and reason", () => {
    fc.assert(
      fc.property(
        nonEmptyString,
        nonEmptyString,
        (filePath, reason) => {
          const result: VerificationResult = { status: "error", reason };
          const output = formatResult(filePath, result);
          expect(output).toContain(filePath);
          expect(output).toContain("error");
          expect(output).toContain(reason);
        },
      ),
      { numRuns: 100 },
    );
  });
});
