/**
 * trust identity add / list / remove — keyless identity pinning (SPEC v2 5,
 * Profile B).
 *
 * A pinned identity is a (certificate-identity, certificate-oidc-issuer)
 * pair, exactly the model npm provenance uses. The identity is a glob pattern
 * over the Fulcio SAN (`*` does not cross `/`, `**` does; an exact URI or
 * email works verbatim); the issuer must match exactly.
 */

import { TrustStore } from "@contextlock/core";
import type { TrustedIdentity } from "@contextlock/core";

export interface TrustIdentityAddOptions {
  publisher: string;
  identity: string;
  issuer: string;
  trustStorePath: string;
}

export interface TrustIdentityAddResult {
  added: TrustedIdentity;
}

export async function trustIdentityAdd(
  options: TrustIdentityAddOptions,
): Promise<TrustIdentityAddResult> {
  if (!/^https?:\/\//.test(options.issuer)) {
    throw new Error(`issuer must be an OIDC issuer URL, got: ${options.issuer}`);
  }
  const store = new TrustStore();
  try {
    await store.load(options.trustStorePath);
  } catch {
    // Trust store doesn't exist yet — start fresh
  }
  const entry: TrustedIdentity = {
    publisher: options.publisher,
    identity: options.identity,
    issuer: options.issuer,
  };
  store.addIdentity(entry);
  await store.save(options.trustStorePath);
  return { added: entry };
}

export interface TrustIdentityListOptions {
  trustStorePath: string;
}

export interface TrustIdentityListResult {
  identities: TrustedIdentity[];
}

export async function trustIdentityList(
  options: TrustIdentityListOptions,
): Promise<TrustIdentityListResult> {
  const store = new TrustStore();
  try {
    await store.load(options.trustStorePath);
  } catch {
    return { identities: [] };
  }
  return { identities: store.listIdentities() };
}

export interface TrustIdentityRemoveOptions {
  publisher: string;
  /** Exact identity pattern to remove; omit to remove all for the publisher. */
  identity?: string;
  trustStorePath: string;
}

export interface TrustIdentityRemoveResult {
  removed: number;
}

export async function trustIdentityRemove(
  options: TrustIdentityRemoveOptions,
): Promise<TrustIdentityRemoveResult> {
  const store = new TrustStore();
  await store.load(options.trustStorePath);
  const removed = store.removeIdentity(options.publisher, options.identity);
  if (removed > 0) {
    await store.save(options.trustStorePath);
  }
  return { removed };
}
