/**
 * trust add command — Add a trusted publisher by public key file.
 *
 * Keys are raw 32-byte Ed25519, base64url (legacy standard base64 accepted).
 * The key_id is a short human-chosen label (SPEC v2 6.6) defaulting to
 * "cl-<first 8 hex of fingerprint>"; trust decisions pin the KEY, the label
 * is only a hint.
 */

import { readFile } from "node:fs/promises";
import { computeFingerprint, base64urlDecode, TrustStore } from "@contextlock/core";
import type { TrustedPublisher, PublisherPolicy } from "@contextlock/core";

export interface TrustAddOptions {
  publicKeyPath: string;
  publisherName: string;
  trustStorePath: string;
  /** Short key label. Defaults to cl-<fp8>. */
  keyId?: string;
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

  const pubKeyText = (await readFile(publicKeyPath, "utf-8")).trim();
  const pubKeyBytes = Buffer.from(base64urlDecode(pubKeyText));
  if (pubKeyBytes.length !== 32) {
    throw new Error(
      `public key at ${publicKeyPath} is malformed (expected raw 32 bytes, got ${pubKeyBytes.length})`,
    );
  }
  const fingerprint = computeFingerprint(pubKeyBytes);
  const keyId = options.keyId ?? `cl-${fingerprint.slice(0, 8)}`;

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
    key_id: keyId,
    public_key: pubKeyBytes.toString("base64"),
    fingerprint,
    revoked: false,
    policy,
  };

  store.addPublisher(entry);
  await store.save(trustStorePath);

  return { keyId, fingerprint, publisherName };
}
