import { readFile, writeFile } from "node:fs/promises";
import type { Manifest } from "./manifest.js";
import type { TrustStore } from "./trust-store.js";

// ---- Interfaces ----

export interface CacheEntry {
  manifest: Manifest;
  fetchedAt: string;       // ISO 8601
  expiresAt?: string;      // from manifest
  fingerprint: string;     // key fingerprint used for verification
  verified: boolean;       // must be true for cache to accept
}

// ---- ManifestCache class ----

export class ManifestCache {
  private entries: Map<string, CacheEntry> = new Map();
  private cachePath: string;

  constructor(cachePath: string) {
    this.cachePath = cachePath;
  }

  /** Build the composite key used to index cache entries. */
  private static key(packageName: string, version: string, fingerprint: string): string {
    return `${packageName}:${version}:${fingerprint}`;
  }

  /**
   * Retrieve a cached entry by package name, version, and key fingerprint.
   */
  get(packageName: string, version: string, fingerprint: string): CacheEntry | undefined {
    return this.entries.get(ManifestCache.key(packageName, version, fingerprint));
  }

  /**
   * Store a verified cache entry.
   * Throws if `entry.verified` is false — the cache only accepts verified manifests.
   */
  put(entry: CacheEntry): void {
    if (!entry.verified) {
      throw new Error("Cannot cache an unverified manifest");
    }
    const k = ManifestCache.key(
      entry.manifest.package,
      entry.manifest.version,
      entry.fingerprint,
    );
    this.entries.set(k, entry);
  }

  /**
   * Remove a cached entry by package name, version, and key fingerprint.
   */
  remove(packageName: string, version: string, fingerprint: string): void {
    this.entries.delete(ManifestCache.key(packageName, version, fingerprint));
  }

  /**
   * Re-verify all cached entries against the trust store.
   * Removes any entry whose key fingerprint is not found in the trust store
   * or whose key is revoked.
   */
  async refresh(trustStore: TrustStore): Promise<void> {
    for (const [key, entry] of this.entries) {
      const publishers = trustStore.listPublishers();
      const match = publishers.find((p) => p.fingerprint === entry.fingerprint);
      if (!match || match.revoked) {
        this.entries.delete(key);
      }
    }
  }

  /**
   * Return all cached entries as an array.
   */
  listEntries(): CacheEntry[] {
    return [...this.entries.values()];
  }

  /**
   * Persist the cache to the JSON file at `cachePath`.
   */
  async save(): Promise<void> {
    const serializable: Array<{ key: string; entry: CacheEntry }> = [];
    for (const [key, entry] of this.entries) {
      serializable.push({ key, entry });
    }
    await writeFile(this.cachePath, JSON.stringify(serializable, null, 2), "utf-8");
  }

  /**
   * Load the cache from the JSON file at `cachePath`.
   */
  async load(): Promise<void> {
    const content = await readFile(this.cachePath, "utf-8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error(`Invalid JSON in cache file: ${this.cachePath}`);
    }
    if (!Array.isArray(parsed)) {
      throw new Error(`Invalid cache format: expected an array`);
    }
    this.entries = new Map();
    for (const item of parsed) {
      if (item && typeof item === "object" && typeof item.key === "string" && item.entry) {
        this.entries.set(item.key, item.entry as CacheEntry);
      }
    }
  }
}
