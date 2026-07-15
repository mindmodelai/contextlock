/**
 * trust revoke command — Mark a key as revoked in the trust store.
 * Requirements: 9.1
 */

import { TrustStore } from "@contextlock/core";

export interface TrustRevokeOptions {
  keyId: string;
  trustStorePath: string;
}

export interface TrustRevokeResult {
  revoked: boolean;
  keyId: string;
}

/**
 * Marks a key as revoked in the trust store.
 */
export async function trustRevoke(options: TrustRevokeOptions): Promise<TrustRevokeResult> {
  const { keyId, trustStorePath } = options;

  const store = new TrustStore();
  await store.load(trustStorePath);

  const existing = store.getPublisher(keyId);
  if (!existing) {
    return { revoked: false, keyId };
  }

  store.revokeKey(keyId);
  await store.save(trustStorePath);

  return { revoked: true, keyId };
}
