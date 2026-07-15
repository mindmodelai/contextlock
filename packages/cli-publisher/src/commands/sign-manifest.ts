/**
 * sign-manifest command — Sign a manifest file with Ed25519 private key.
 * Requirements: 12.1, 12.2, 12.3, 12.4
 */

import { readFile, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { sha256, computeFingerprint, serializeSignature } from "@contextlock/core";
import type { DetachedSignature } from "@contextlock/core";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

export interface SignManifestOptions {
  manifestPath: string;
  privateKeyPath: string;
  outputPath?: string;
}

export interface SignManifestResult {
  signaturePath: string;
  signature: DetachedSignature;
  keyId: string;
}

/**
 * Encodes a Uint8Array to base64url string.
 */
function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Signs a manifest file and generates manifest.sig.json.
 */
export async function signManifest(options: SignManifestOptions): Promise<SignManifestResult> {
  const { manifestPath, privateKeyPath, outputPath } = options;

  // Read manifest content
  const manifestContent = await readFile(manifestPath);

  // Compute SHA-256 of manifest
  const manifestHash = sha256(manifestContent);

  // Read private key (base64-encoded)
  const privKeyB64 = (await readFile(privateKeyPath, "utf-8")).trim();
  const privateKey = Uint8Array.from(Buffer.from(privKeyB64, "base64"));

  // Derive public key for key_id (fingerprint)
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const keyId = computeFingerprint(Buffer.from(publicKey));

  // Sign the manifest content
  const sigBytes = await ed.signAsync(manifestContent, privateKey);
  const sigB64url = base64urlEncode(sigBytes);

  const signature: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: manifestHash,
    algorithm: "Ed25519",
    key_id: keyId,
    signature: sigB64url,
  };

  const sigPath = outputPath ?? join(dirname(manifestPath), "manifest.sig.json");
  const json = serializeSignature(signature);
  await writeFile(sigPath, json, "utf-8");

  return {
    signaturePath: sigPath,
    signature,
    keyId,
  };
}
