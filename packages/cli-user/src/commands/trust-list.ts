/**
 * trust list command — Display all trusted publishers.
 * Requirements: 5.6
 */

import { TrustStore } from "@contextlock/core";
import type { TrustedPublisher } from "@contextlock/core";

export interface TrustListOptions {
  trustStorePath: string;
}

export interface TrustListResult {
  publishers: TrustedPublisher[];
}

/**
 * Lists all trusted publishers from the trust store.
 */
export async function trustList(options: TrustListOptions): Promise<TrustListResult> {
  const { trustStorePath } = options;

  const store = new TrustStore();
  try {
    await store.load(trustStorePath);
  } catch {
    return { publishers: [] };
  }

  return { publishers: store.listPublishers() };
}
