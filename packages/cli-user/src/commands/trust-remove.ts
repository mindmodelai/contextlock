/**
 * trust remove command — Remove a trusted publisher by key ID.
 * Requirements: 5.3
 */

import { TrustStore } from "@contextlock/core";

export interface TrustRemoveOptions {
  keyId: string;
  trustStorePath: string;
}

export interface TrustRemoveResult {
  removed: boolean;
  keyId: string;
}

/**
 * Removes a publisher entry by key ID from the trust store.
 */
export async function trustRemove(options: TrustRemoveOptions): Promise<TrustRemoveResult> {
  const { keyId, trustStorePath } = options;

  const store = new TrustStore();
  await store.load(trustStorePath);

  const existing = store.getPublisher(keyId);
  if (!existing) {
    return { removed: false, keyId };
  }

  store.removePublisher(keyId);
  await store.save(trustStorePath);

  return { removed: true, keyId };
}
