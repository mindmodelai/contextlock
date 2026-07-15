/**
 * key-fingerprint command — Display SHA-256 fingerprint of a public key file.
 * Requirements: 20.1, 20.2
 */

import { readFile } from "node:fs/promises";
import { computeFingerprint } from "@contextlock/core";

export interface KeyFingerprintOptions {
  publicKeyPath: string;
}

export interface KeyFingerprintResult {
  fingerprint: string;
}

/**
 * Reads a public key file (base64-encoded) and computes its SHA-256 fingerprint.
 */
export async function keyFingerprint(options: KeyFingerprintOptions): Promise<KeyFingerprintResult> {
  const { publicKeyPath } = options;

  const pubKeyB64 = (await readFile(publicKeyPath, "utf-8")).trim();
  const pubKeyBytes = Buffer.from(pubKeyB64, "base64");
  const fingerprint = computeFingerprint(pubKeyBytes);

  return { fingerprint };
}
