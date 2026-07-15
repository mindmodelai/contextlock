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
 * Reads a file, canonicalizes its content, then computes SHA-256 (lowercase hex).
 */
export async function computeFileHash(filePath: string): Promise<string> {
  const raw = await readFile(filePath);
  const canonical = canonicalize(raw);
  return sha256(canonical);
}

/**
 * Computes the fingerprint of an Ed25519 public key as SHA-256 lowercase hex.
 */
export function computeFingerprint(publicKey: Buffer): string {
  return sha256(publicKey);
}
