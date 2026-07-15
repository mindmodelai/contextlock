// Feature: contextlock, Properties 3, 4, 5 — Manifest module property tests
// Property 3: Manifest round-trip — Validates: Requirements 2.5, 13.3
// Property 4: Detached signature round-trip — Validates: Requirements 13.4
// Property 5: Invalid manifest rejection — Validates: Requirements 2.2

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  parseManifest,
  serializeManifest,
  parseSignature,
  serializeSignature,
  type Manifest,
  type DetachedSignature,
} from "./manifest.js";

// ---- Arbitraries ----

/** Lowercase hex string of exact length */
const hexString = (len: number) =>
  fc
    .array(fc.integer({ min: 0, max: 15 }), { minLength: len, maxLength: len })
    .map((nums) => nums.map((n) => n.toString(16)).join(""));

/** Non-empty alphanumeric string */
const alphaNum = fc
  .array(
    fc.constantFrom(..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("")),
    { minLength: 1, maxLength: 20 },
  )
  .map((chars) => chars.join(""));

/** Semver-like version string e.g. "1.0.0" */
const semver = fc
  .tuple(
    fc.integer({ min: 0, max: 99 }),
    fc.integer({ min: 0, max: 99 }),
    fc.integer({ min: 0, max: 99 }),
  )
  .map(([ma, mi, pa]) => `${ma}.${mi}.${pa}`);

/** Valid ISO 8601 date string — built from integer components to avoid invalid Date edge cases */
const iso8601 = fc
  .tuple(
    fc.integer({ min: 2000, max: 2099 }),
    fc.integer({ min: 1, max: 12 }),
    fc.integer({ min: 1, max: 28 }), // cap at 28 to avoid month-length issues
    fc.integer({ min: 0, max: 23 }),
    fc.integer({ min: 0, max: 59 }),
    fc.integer({ min: 0, max: 59 }),
  )
  .map(
    ([y, mo, d, h, mi, s]) =>
      `${y}-${String(mo).padStart(2, "0")}-${String(d).padStart(2, "0")}T${String(h).padStart(2, "0")}:${String(mi).padStart(2, "0")}:${String(s).padStart(2, "0")}Z`,
  );

/** Base64url-safe string (non-empty) */
const base64url = fc
  .array(fc.integer({ min: 0, max: 255 }), { minLength: 8, maxLength: 64 })
  .map((bytes) =>
    Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, ""),
  );

/** Unique file path for manifest entries */
const filePath = fc
  .tuple(alphaNum, fc.constantFrom(".md", ".txt", ".json", ".ts"))
  .map(([name, ext]) => `${name}${ext}`);

/** Single ManifestFileEntry */
const fileEntry = fc
  .tuple(filePath, hexString(64), fc.integer({ min: 1, max: 1_000_000 }))
  .map(([path, sha256, size]) => ({ path, sha256, size }));

/** Array of file entries with unique paths */
const uniqueFileEntries = fc
  .array(fileEntry, { minLength: 1, maxLength: 10 })
  .map((entries) => {
    const seen = new Set<string>();
    return entries.filter((e) => {
      if (seen.has(e.path)) return false;
      seen.add(e.path);
      return true;
    });
  })
  .filter((entries) => entries.length > 0);

/** Valid Manifest arbitrary */
const manifestArb: fc.Arbitrary<Manifest> = fc
  .tuple(
    alphaNum,
    semver,
    alphaNum,
    alphaNum,
    hexString(64),
    iso8601,
    fc.option(iso8601, { nil: undefined }),
    uniqueFileEntries,
  )
  .map(
    ([pkg, version, pubName, keyId, fingerprint, publishedAt, expiresAt, files]) =>
      ({
        schema: "tcv-manifest/v1" as const,
        package: pkg,
        version,
        publisher: {
          name: pubName,
          key_id: keyId,
          public_key_fingerprint: fingerprint,
        },
        published_at: publishedAt,
        ...(expiresAt !== undefined ? { expires_at: expiresAt } : {}),
        files,
      }) as Manifest,
  );

/** Valid DetachedSignature arbitrary */
const signatureArb: fc.Arbitrary<DetachedSignature> = fc
  .tuple(hexString(64), alphaNum, base64url)
  .map(([manifestSha256, keyId, signature]) => ({
    schema: "tcv-signature/v1" as const,
    manifest_sha256: manifestSha256,
    algorithm: "Ed25519" as const,
    key_id: keyId,
    signature,
  }));

// ---- Property 3: Manifest round-trip ----

describe("Property 3: Manifest round-trip", () => {
  // **Validates: Requirements 2.5, 13.3**
  it("parseManifest(serializeManifest(m)) deep-equals m for any valid Manifest", () => {
    fc.assert(
      fc.property(manifestArb, (m) => {
        const json = serializeManifest(m);
        const parsed = parseManifest(json);
        expect(parsed).toEqual(m);
      }),
      { numRuns: 100 },
    );
  });
});

// ---- Property 4: Detached signature round-trip ----

describe("Property 4: Detached signature round-trip", () => {
  // **Validates: Requirements 13.4**
  it("parseSignature(serializeSignature(s)) deep-equals s for any valid DetachedSignature", () => {
    fc.assert(
      fc.property(signatureArb, (s) => {
        const json = serializeSignature(s);
        const parsed = parseSignature(json);
        expect(parsed).toEqual(s);
      }),
      { numRuns: 100 },
    );
  });
});

// ---- Property 5: Invalid manifest rejection ----

/**
 * Generates JSON objects that violate the tcv-manifest/v1 schema in various ways:
 * - Missing required fields
 * - Wrong schema value
 * - files set to non-array
 * - Required string fields set to numbers or empty strings
 */
const invalidManifestArb = fc.oneof(
  // Strategy 1: Remove a random required field
  fc
    .constantFrom("schema", "package", "version", "publisher", "published_at", "files")
    .map((fieldToRemove) => {
      const base: Record<string, unknown> = {
        schema: "tcv-manifest/v1",
        package: "test-pkg",
        version: "1.0.0",
        publisher: {
          name: "Alice",
          key_id: "key-1",
          public_key_fingerprint: "a".repeat(64),
        },
        published_at: "2025-01-15T12:00:00Z",
        files: [{ path: "README.md", sha256: "b".repeat(64), size: 100 }],
      };
      delete base[fieldToRemove];
      return base;
    }),

  // Strategy 2: Wrong schema value
  fc.string({ minLength: 1, maxLength: 20 }).map((wrongSchema) => ({
    schema: wrongSchema === "tcv-manifest/v1" ? "wrong/v1" : wrongSchema,
    package: "test-pkg",
    version: "1.0.0",
    publisher: {
      name: "Alice",
      key_id: "key-1",
      public_key_fingerprint: "a".repeat(64),
    },
    published_at: "2025-01-15T12:00:00Z",
    files: [{ path: "README.md", sha256: "b".repeat(64), size: 100 }],
  })),

  // Strategy 3: files set to non-array types
  fc.oneof(fc.string(), fc.integer(), fc.constant(null), fc.constant({})).map(
    (badFiles) => ({
      schema: "tcv-manifest/v1",
      package: "test-pkg",
      version: "1.0.0",
      publisher: {
        name: "Alice",
        key_id: "key-1",
        public_key_fingerprint: "a".repeat(64),
      },
      published_at: "2025-01-15T12:00:00Z",
      files: badFiles,
    }),
  ),

  // Strategy 4: Required string fields set to empty strings or numbers
  fc
    .constantFrom("package", "version")
    .chain((field) =>
      fc.oneof(fc.constant(""), fc.integer()).map((badValue) => ({
        schema: "tcv-manifest/v1",
        [field]: badValue,
        package: field === "package" ? badValue : "test-pkg",
        version: field === "version" ? badValue : "1.0.0",
        publisher: {
          name: "Alice",
          key_id: "key-1",
          public_key_fingerprint: "a".repeat(64),
        },
        published_at: "2025-01-15T12:00:00Z",
        files: [{ path: "README.md", sha256: "b".repeat(64), size: 100 }],
      })),
    ),

  // Strategy 5: publisher set to non-object
  fc.oneof(fc.string(), fc.integer(), fc.constant(null)).map((badPub) => ({
    schema: "tcv-manifest/v1",
    package: "test-pkg",
    version: "1.0.0",
    publisher: badPub,
    published_at: "2025-01-15T12:00:00Z",
    files: [{ path: "README.md", sha256: "b".repeat(64), size: 100 }],
  })),
);

describe("Property 5: Invalid manifest rejection", () => {
  // **Validates: Requirements 2.2**
  it("parseManifest throws with a descriptive reason for any invalid manifest JSON", () => {
    fc.assert(
      fc.property(invalidManifestArb, (invalidObj) => {
        const json = JSON.stringify(invalidObj);
        expect(() => parseManifest(json)).toThrow(/Invalid manifest/);
      }),
      { numRuns: 100 },
    );
  });
});
