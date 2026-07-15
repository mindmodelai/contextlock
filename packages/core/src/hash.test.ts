// Unit tests for Hasher
// Validates: Requirements 1.4, 5.2, 20.1, 20.2

import { describe, it, expect } from "vitest";
import { sha256, sha256Bytes, computeFingerprint } from "./hash.js";

describe("sha256", () => {
  it("returns correct hash for empty string", () => {
    const result = sha256(Buffer.alloc(0));
    expect(result).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it('returns correct hash for "hello"', () => {
    const result = sha256(Buffer.from("hello", "utf-8"));
    expect(result).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });
});

describe("sha256Bytes", () => {
  it("returns a 32-byte Buffer", () => {
    const result = sha256Bytes(Buffer.from("test data", "utf-8"));
    expect(Buffer.isBuffer(result)).toBe(true);
    expect(result.length).toBe(32);
  });
});

describe("computeFingerprint", () => {
  it("returns lowercase hex string of 64 characters", () => {
    const key = Buffer.alloc(32, 0xab);
    const result = computeFingerprint(key);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });
});
