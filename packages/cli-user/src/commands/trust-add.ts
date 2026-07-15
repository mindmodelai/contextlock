/**
 * trust add command — Add a trusted publisher by public key file.
 * Requirements: 5.2, 5.4
 */

import { readFile } from "node:fs/promises";
import { computeFingerprint, TrustStore } from "@contextlock/core";
import type { TrustedPublisher, PublisherPolicy } from "@contextlock/core";

export interface TrustAddOptions {
  publicKeyPath: string;
  publisherName: string;
  trustStorePath: string;
  policy?: Partial<PublisherPolicy>;
}

export interface TrustAddResult {
  keyId: string;
  fingerprint: string;
  publisherName: string;
}

/**
 * Reads a public key file, computes fingerprint, and adds to trust store.
 */
export async function trustAdd(options: TrustAddOptions): Promise<TrustAddResult> {
  const { publicKeyPath, publisherName, trustStorePath } = options;

  const pubKeyB64 = (await readFile(publicKeyPath, "utf-8")).trim();
  const pubKeyBytes = Buffer.from(pubKeyB64, "base64");
  const fingerprint = computeFingerprint(pubKeyBytes);

  const store = new TrustStore();
  try {
    await store.load(trustStorePath);
  } catch {
    // Trust store doesn't exist yet — start fresh
  }

  const policy: PublisherPolicy = {
    default_action: options.policy?.default_action ?? "warn",
    allow_expired_manifest: options.policy?.allow_expired_manifest ?? false,
    allow_offline_cached_manifest: options.policy?.allow_offline_cached_manifest ?? false,
  };

  const entry: TrustedPublisher = {
    publisher: publisherName,
    key_id: fingerprint,
    public_key: pubKeyB64,
    fingerprint,
    revoked: false,
    policy,
  };

  store.addPublisher(entry);
  await store.save(trustStorePath);

  return { keyId: fingerprint, fingerprint, publisherName };
}
