/**
 * init-key command — Generate an Ed25519 keypair (SPEC v2 6.6).
 *
 * Key format: raw 32-byte Ed25519 keys, base64url, one line per file, with a
 * short minisign-style key id label (default "cl-<first 8 hex of fingerprint>").
 * PEM/JWK are import/export conveniences elsewhere, never the wire format.
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { computeFingerprint, base64urlEncode } from "@contextlock/core";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

export const PRIVATE_KEY_FILENAME = "contextlock-private.key";
export const PUBLIC_KEY_FILENAME = "contextlock-public.key";

export interface InitKeyOptions {
  output?: string;
  /** Short key label recorded as the DSSE keyid hint (default cl-<fp8>). */
  keyId?: string;
}

export interface InitKeyResult {
  privateKeyPath: string;
  publicKeyPath: string;
  fingerprint: string;
  keyId: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function defaultKeyId(fingerprint: string): string {
  return `cl-${fingerprint.slice(0, 8)}`;
}

/**
 * Generates an Ed25519 keypair, saves to files (base64url raw keys), and
 * returns metadata.
 */
export async function initKey(options: InitKeyOptions = {}): Promise<InitKeyResult> {
  const outputDir = options.output ?? process.cwd();

  // Generate cryptographically secure random private key
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const privateKeyPath = join(outputDir, PRIVATE_KEY_FILENAME);
  const publicKeyPath = join(outputDir, PUBLIC_KEY_FILENAME);

  await writeFile(privateKeyPath, base64urlEncode(privateKey) + "\n", "utf-8");
  await writeFile(publicKeyPath, base64urlEncode(publicKey) + "\n", "utf-8");

  const fingerprint = computeFingerprint(Buffer.from(publicKey));
  const keyId = options.keyId ?? defaultKeyId(fingerprint);

  return {
    privateKeyPath,
    publicKeyPath,
    fingerprint,
    keyId,
    publicKey,
    privateKey,
  };
}
