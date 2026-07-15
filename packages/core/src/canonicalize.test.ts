// Unit tests for Canonicalizer
// Validates: Requirements 1.1, 1.2, 1.3

import { describe, it, expect } from "vitest";
import { canonicalize } from "./canonicalize.js";

describe("canonicalize", () => {
  it("returns empty buffer for empty input", () => {
    const result = canonicalize(Buffer.alloc(0));
    expect(result.length).toBe(0);
  });

  it("returns empty buffer for BOM-only content", () => {
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const result = canonicalize(bom);
    expect(result.length).toBe(0);
  });

  it("returns same content when already canonical (LF only, no BOM)", () => {
    const input = Buffer.from("hello\nworld\n", "utf-8");
    const result = canonicalize(input);
    expect(result).toEqual(input);
    // Should be the exact same buffer reference (fast path)
    expect(result).toBe(input);
  });

  it("converts CRLF to LF", () => {
    const input = Buffer.from("line1\r\nline2\r\nline3", "utf-8");
    const expected = Buffer.from("line1\nline2\nline3", "utf-8");
    const result = canonicalize(input);
    expect(result).toEqual(expected);
  });

  it("converts lone CR to LF", () => {
    const input = Buffer.from("line1\rline2\rline3", "utf-8");
    const expected = Buffer.from("line1\nline2\nline3", "utf-8");
    const result = canonicalize(input);
    expect(result).toEqual(expected);
  });

  it("handles mixed CRLF and CR in same content", () => {
    const input = Buffer.from("a\r\nb\rc\r\nd\r", "utf-8");
    const expected = Buffer.from("a\nb\nc\nd\n", "utf-8");
    const result = canonicalize(input);
    expect(result).toEqual(expected);
  });

  it("strips BOM and converts CRLF", () => {
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    const body = Buffer.from("hello\r\nworld", "utf-8");
    const input = Buffer.concat([bom, body]);
    const expected = Buffer.from("hello\nworld", "utf-8");
    const result = canonicalize(input);
    expect(result).toEqual(expected);
  });
});
