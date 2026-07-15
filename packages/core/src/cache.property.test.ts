// Feature: contextlock, Property 18: Manifest cache stores only verified manifests
// **Validates: Requirements 15.1, 15.4**

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { ManifestCache } from "./cache.js";
import type { CacheEntry } from "./cache.js";
import type { Manifest } from "./manifest.js";

// ---- Arbitraries ----

const alphaNum = fc
  .array(
    fc.constantFrom(
      ..."abcdefghijklmnopqrstuvwxyz0123456789".split(""),
    ),
    { minLength: 1, maxLength: 12 },
  )
  .map((chars) => chars.join(""));

const hexString = (len: number) =>
  fc
    .array(fc.integer({ min: 0, max: 15 }), { minLength: len, maxLength: len })
    .map((nums) => nums.map((n) => n.toString(16)).join(""));

const isoDate = fc
  .date({ min: new Date("2020-01-01"), max: new Date("2030-01-01"), noInvalidDate: true })
  .map((d) => d.toISOString());

const manifestArb: fc.Arbitrary<Manifest> = fc
  .tuple(alphaNum, fc.integer({ min: 1, max: 1_000_000 }), alphaNum, alphaNum, isoDate)
  .map(([pkg, version, pubName, keyId, publishedAt]) => ({
    spec_version: "contextlock/2" as const,
    package: pkg,
    version,
    publisher: {
      name: pubName,
      key_id: keyId,
    },
    published_at: publishedAt,
    expires_at: "2030-01-01T00:00:00Z",
    files: [],
  }));

const cacheEntryArb = (verified: boolean): fc.Arbitrary<CacheEntry> =>
  fc.tuple(manifestArb, isoDate, hexString(64)).map(([manifest, fetchedAt, fingerprint]) => ({
    manifest,
    fetchedAt,
    fingerprint,
    verified,
  }));

// ---- Property 18 ----

describe("Property 18: Manifest cache stores only verified manifests", () => {
  it("rejects unverified manifests with an error", () => {
    fc.assert(
      fc.property(cacheEntryArb(false), (entry) => {
        const cache = new ManifestCache("/tmp/test-cache.json");
        expect(() => cache.put(entry)).toThrow("Cannot cache an unverified manifest");
      }),
      { numRuns: 100 },
    );
  });

  it("accepts verified manifests and retrieves them by package, version, fingerprint", () => {
    fc.assert(
      fc.property(cacheEntryArb(true), (entry) => {
        const cache = new ManifestCache("/tmp/test-cache.json");
        cache.put(entry);

        const retrieved = cache.get(
          entry.manifest.package,
          entry.manifest.version,
          entry.fingerprint,
        );
        expect(retrieved).toBeDefined();
        expect(retrieved!.manifest.package).toBe(entry.manifest.package);
        expect(retrieved!.manifest.version).toBe(entry.manifest.version);
        expect(retrieved!.fingerprint).toBe(entry.fingerprint);
        expect(retrieved!.verified).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});
