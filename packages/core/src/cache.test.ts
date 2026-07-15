import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ManifestCache } from "./cache.js";
import type { CacheEntry } from "./cache.js";
import type { Manifest } from "./manifest.js";
import { TrustStore } from "./trust-store.js";
import type { TrustedPublisher } from "./trust-store.js";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

// ---- Helpers ----

function makeManifest(overrides: Partial<Manifest> = {}): Manifest {
  return {
    spec_version: "contextlock/2",
    package: "test-pkg",
    version: 1,
    publisher: {
      name: "pub",
      key_id: "key-001",
    },
    published_at: "2024-01-01T00:00:00Z",
    expires_at: "2030-01-01T00:00:00Z",
    files: [],
    ...overrides,
  };
}

function makeEntry(overrides: Partial<CacheEntry> = {}): CacheEntry {
  return {
    manifest: makeManifest(),
    fetchedAt: "2024-06-01T00:00:00Z",
    fingerprint: "fp-aabbccdd",
    verified: true,
    ...overrides,
  };
}

function makePublisher(overrides: Partial<TrustedPublisher> = {}): TrustedPublisher {
  return {
    publisher: "pub",
    key_id: "key-001",
    public_key: "dGVzdC1rZXk=",
    fingerprint: "fp-aabbccdd",
    revoked: false,
    policy: {
      default_action: "block",
      allow_expired_manifest: false,
      allow_offline_cached_manifest: false,
    },
    ...overrides,
  };
}

describe("ManifestCache", () => {
  let cache: ManifestCache;

  beforeEach(() => {
    cache = new ManifestCache("/tmp/cache-test.json");
  });

  // ---- put / get / remove lifecycle ----

  describe("put / get / remove lifecycle", () => {
    it("stores and retrieves a verified entry", () => {
      const entry = makeEntry();
      cache.put(entry);
      const got = cache.get("test-pkg", 1, "fp-aabbccdd");
      expect(got).toEqual(entry);
    });

    it("returns undefined for missing entry", () => {
      expect(cache.get("no-pkg", "0.0.0", "no-fp")).toBeUndefined();
    });

    it("removes an entry", () => {
      cache.put(makeEntry());
      cache.remove("test-pkg", 1, "fp-aabbccdd");
      expect(cache.get("test-pkg", 1, "fp-aabbccdd")).toBeUndefined();
    });

    it("listEntries returns all cached entries", () => {
      cache.put(makeEntry());
      cache.put(
        makeEntry({
          manifest: makeManifest({ package: "other-pkg" }),
          fingerprint: "fp-other",
        }),
      );
      expect(cache.listEntries()).toHaveLength(2);
    });

    it("overwrites entry with same key", () => {
      cache.put(makeEntry({ fetchedAt: "2024-01-01T00:00:00Z" }));
      cache.put(makeEntry({ fetchedAt: "2024-12-01T00:00:00Z" }));
      const got = cache.get("test-pkg", 1, "fp-aabbccdd");
      expect(got?.fetchedAt).toBe("2024-12-01T00:00:00Z");
      expect(cache.listEntries()).toHaveLength(1);
    });
  });

  // ---- Reject unverified writes ----

  describe("reject unverified write", () => {
    it("throws when entry.verified is false", () => {
      const entry = makeEntry({ verified: false });
      expect(() => cache.put(entry)).toThrow("Cannot cache an unverified manifest");
    });
  });

  // ---- refresh removes failed entries ----

  describe("refresh", () => {
    it("removes entries whose fingerprint is not in the trust store", async () => {
      cache.put(makeEntry({ fingerprint: "fp-unknown" }));
      cache.put(makeEntry({
        manifest: makeManifest({ package: "known-pkg" }),
        fingerprint: "fp-known",
      }));

      const store = new TrustStore();
      store.addPublisher(makePublisher({ fingerprint: "fp-known" }));

      await cache.refresh(store);

      expect(cache.get("test-pkg", 1, "fp-unknown")).toBeUndefined();
      expect(cache.get("known-pkg", 1, "fp-known")).toBeDefined();
    });

    it("removes entries whose key is revoked in the trust store", async () => {
      cache.put(makeEntry({ fingerprint: "fp-revoked" }));

      const store = new TrustStore();
      store.addPublisher(makePublisher({ fingerprint: "fp-revoked", revoked: true }));

      await cache.refresh(store);

      expect(cache.get("test-pkg", 1, "fp-revoked")).toBeUndefined();
    });

    it("keeps entries whose fingerprint is active in the trust store", async () => {
      cache.put(makeEntry());

      const store = new TrustStore();
      store.addPublisher(makePublisher());

      await cache.refresh(store);

      expect(cache.get("test-pkg", 1, "fp-aabbccdd")).toBeDefined();
    });
  });

  // ---- save / load persistence ----

  describe("save / load", () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), "cache-test-"));
    });

    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });

    it("round-trips entries through save and load", async () => {
      const filePath = join(tmpDir, "cache.json");
      const c1 = new ManifestCache(filePath);
      c1.put(makeEntry());
      await c1.save();

      const c2 = new ManifestCache(filePath);
      await c2.load();
      expect(c2.listEntries()).toHaveLength(1);
      expect(c2.get("test-pkg", 1, "fp-aabbccdd")).toBeDefined();
    });

    it("load rejects invalid JSON", async () => {
      const filePath = join(tmpDir, "bad.json");
      const { writeFile } = await import("node:fs/promises");
      await writeFile(filePath, "not json");

      const c = new ManifestCache(filePath);
      await expect(c.load()).rejects.toThrow("Invalid JSON");
    });

    it("load rejects non-existent file", async () => {
      const c = new ManifestCache(join(tmpDir, "missing.json"));
      await expect(c.load()).rejects.toThrow();
    });
  });
});
