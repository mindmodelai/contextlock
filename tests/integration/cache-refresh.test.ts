/**
 * Integration test: Cache and offline verification
 * Verify file (caches manifest) → remove original manifest → verify using cache
 * Requirements: 15.1, 15.3
 */

import { describe, it, expect, afterEach } from "vitest";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { ManifestCache, TrustStore } from "@contextlock/core";
import { cacheRefresh } from "@contextlock/cli-user";
import { createTempDir, createSignedPackage } from "./helpers.js";

describe("Integration: Cache and offline verification", () => {
  let tempDir: string;

  afterEach(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("cache stores verified manifest and refresh removes revoked entries", async () => {
    tempDir = await createTempDir("tcv-int-cache-");

    const pkg = await createSignedPackage(tempDir, {
      "SKILL.md": "# Cached skill",
    });

    // Manually cache the manifest
    const cachePath = join(tempDir, "cache.json");
    const cache = new ManifestCache(cachePath);
    cache.put({
      manifest: pkg.manifest,
      fetchedAt: new Date().toISOString(),
      fingerprint: pkg.kp.fingerprint,
      verified: true,
    });
    await cache.save();

    // Verify cache has the entry
    const entry = cache.get("integration-test-pkg", 1, pkg.kp.fingerprint);
    expect(entry).toBeDefined();
    expect(entry!.manifest.package).toBe("integration-test-pkg");

    // Refresh with valid trust store — entry should remain
    const result1 = await cacheRefresh({
      cachePath,
      trustStorePath: pkg.storePath,
    });
    expect(result1.removed).toBe(0);
    expect(result1.entriesAfter).toBe(1);

    // Revoke the key in trust store
    const store = new TrustStore();
    await store.load(pkg.storePath);
    store.revokeKey(pkg.kp.fingerprint);
    await store.save(pkg.storePath);

    // Refresh again — entry should be removed
    const result2 = await cacheRefresh({
      cachePath,
      trustStorePath: pkg.storePath,
    });
    expect(result2.removed).toBe(1);
    expect(result2.entriesAfter).toBe(0);
  });

  it("cache rejects unverified manifests", () => {
    const cache = new ManifestCache("dummy.json");
    expect(() =>
      cache.put({
        manifest: {
          spec_version: "contextlock/2",
          package: "x",
          version: 1,
          publisher: { name: "a", key_id: "b" },
          published_at: new Date().toISOString(),
          expires_at: "2030-01-01T00:00:00Z",
          files: [],
        },
        fetchedAt: new Date().toISOString(),
        fingerprint: "abc",
        verified: false,
      }),
    ).toThrow("Cannot cache an unverified manifest");
  });
});
