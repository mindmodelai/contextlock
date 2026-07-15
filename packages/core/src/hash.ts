import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { readFile } from "node:fs/promises";
import { canonicalize } from "./canonicalize.js";

/**
 * Computes SHA-256 hash of data and returns lowercase hex string.
 */
export function sha256(data: Buffer): string {
  return Buffer.from(nobleSha256(data)).toString("hex");
}

/**
 * Computes SHA-256 hash of data and returns raw bytes.
 */
export function sha256Bytes(data: Buffer): Buffer {
  return Buffer.from(nobleSha256(data));
}

/**
 * Reads a file and computes SHA-256 over its EXACT bytes on disk (lowercase hex).
 *
 * SPEC v2 6.1: no canonicalization at verify time. Two byte streams that hash
 * identically only after normalization are a smuggling channel, so the thing we
 * attest must be the thing the model reads. Publishers/seal normalize at WRITE
 * time (normalizeFileOnDisk) and then hash the resulting raw bytes.
 */
export async function computeFileHash(filePath: string): Promise<string> {
  const raw = await readFile(filePath);
  return sha256(raw);
}

/**
 * Verify-time DIAGNOSTIC ONLY: SHA-256 of the LF-normalized content. Never used
 * as a verdict input; only to detect a line-endings-only difference so the error
 * message can hint "difference is line endings only" (SPEC v2 6.1).
 */
export async function computeNormalizedFileHash(filePath: string): Promise<string> {
  const raw = await readFile(filePath);
  return sha256(canonicalize(raw));
}

/**
 * Computes the fingerprint of an Ed25519 public key as SHA-256 lowercase hex.
 */
export function computeFingerprint(publicKey: Buffer): string {
  return sha256(publicKey);
}
