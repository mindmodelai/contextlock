/**
 * cache refresh command — Re-verify all cached manifests, remove failures.
 * Requirements: 15.5
 */

import { ManifestCache, TrustStore } from "@contextlock/core";

export interface CacheRefreshOptions {
  cachePath: string;
  trustStorePath: string;
}

export interface CacheRefreshResult {
  entriesBefore: number;
  entriesAfter: number;
  removed: number;
}

/**
 * Re-verifies all cached manifests and removes entries that fail.
 */
export async function cacheRefresh(options: CacheRefreshOptions): Promise<CacheRefreshResult> {
  const { cachePath, trustStorePath } = options;

  const cache = new ManifestCache(cachePath);
  try {
    await cache.load();
  } catch {
    return { entriesBefore: 0, entriesAfter: 0, removed: 0 };
  }

  const entriesBefore = cache.listEntries().length;

  const store = new TrustStore();
  try {
    await store.load(trustStorePath);
  } catch {
    // No trust store — all entries will be removed
  }

  await cache.refresh(store);
  const entriesAfter = cache.listEntries().length;

  await cache.save();

  return {
    entriesBefore,
    entriesAfter,
    removed: entriesBefore - entriesAfter,
  };
}
