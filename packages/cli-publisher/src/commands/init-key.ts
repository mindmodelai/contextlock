/**
 * init-key command — Generate Ed25519 keypair.
 * Requirements: 10.1, 10.2, 10.3, 10.4
 */

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { computeFingerprint } from "@contextlock/core";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

export interface InitKeyOptions {
  output?: string;
}

export interface InitKeyResult {
  privateKeyPath: string;
  publicKeyPath: string;
  fingerprint: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Generates an Ed25519 keypair, saves to files, and returns metadata.
 */
export async function initKey(options: InitKeyOptions = {}): Promise<InitKeyResult> {
  const outputDir = options.output ?? process.cwd();

  // Generate cryptographically secure random private key
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  // Encode keys as base64
  const privB64 = Buffer.from(privateKey).toString("base64");
  const pubB64 = Buffer.from(publicKey).toString("base64");

  // Save to files
  const privateKeyPath = join(outputDir, "tcv-private.key");
  const publicKeyPath = join(outputDir, "tcv-public.key");

  await writeFile(privateKeyPath, privB64, "utf-8");
  await writeFile(publicKeyPath, pubB64, "utf-8");

  // Compute fingerprint
  const fingerprint = computeFingerprint(Buffer.from(publicKey));

  return {
    privateKeyPath,
    publicKeyPath,
    fingerprint,
    publicKey,
    privateKey,
  };
}
