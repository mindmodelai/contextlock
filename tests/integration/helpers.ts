/**
 * Shared helpers for integration tests.
 */

import { writeFile, mkdtemp, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  computeFingerprint,
  sha256,
  serializeManifest,
  serializeSignature,
  TrustStore,
} from "@contextlock/core";
import type { Manifest, DetachedSignature, TrustedPublisher } from "@contextlock/core";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

export function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privB64: string;
  pubB64: string;
  fingerprint: string;
  privPath: string;
  pubPath: string;
}

export async function generateKeypair(dir: string): Promise<Keypair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const privB64 = Buffer.from(privateKey).toString("base64");
  const pubB64 = Buffer.from(publicKey).toString("base64");
  const privPath = join(dir, "tcv-private.key");
  const pubPath = join(dir, "tcv-public.key");
  await writeFile(privPath, privB64, "utf-8");
  await writeFile(pubPath, pubB64, "utf-8");
  const fingerprint = computeFingerprint(Buffer.from(publicKey));
  return { privateKey, publicKey, privB64, pubB64, fingerprint, privPath, pubPath };
}

export async function createTempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

export interface SignedPackage {
  dir: string;
  kp: Keypair;
  storePath: string;
  manifest: Manifest;
}

/**
 * Creates a complete signed package with trust store.
 */
export async function createSignedPackage(
  dir: string,
  files: Record<string, string>,
  options?: { expiresAt?: string },
): Promise<SignedPackage> {
  const kp = await generateKeypair(dir);

  // Write files
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, "utf-8");
  }

  // Build manifest
  const fileEntries = Object.entries(files).map(([name, content]) => ({
    path: name,
    sha256: sha256(Buffer.from(content)),
    size: Buffer.byteLength(content),
  }));

  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "integration-test-pkg",
    version: "1.0.0",
    publisher: {
      name: "IntegrationPublisher",
      key_id: kp.fingerprint,
      public_key_fingerprint: kp.fingerprint,
    },
    published_at: new Date().toISOString(),
    files: fileEntries,
  };

  if (options?.expiresAt) {
    manifest.expires_at = options.expiresAt;
  }

  const manifestJson = serializeManifest(manifest);
  await writeFile(join(dir, "manifest.json"), manifestJson, "utf-8");

  // Sign
  const manifestBuf = Buffer.from(manifestJson);
  const sigBytes = await ed.signAsync(manifestBuf, kp.privateKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: sha256(manifestBuf),
    algorithm: "Ed25519",
    key_id: kp.fingerprint,
    signature: base64urlEncode(sigBytes),
  };
  await writeFile(join(dir, "manifest.sig.json"), serializeSignature(sig), "utf-8");

  // Trust store
  const storePath = join(dir, "truststore.json");
  const store = new TrustStore();
  store.addPublisher({
    publisher: "IntegrationPublisher",
    key_id: kp.fingerprint,
    public_key: kp.pubB64,
    fingerprint: kp.fingerprint,
    revoked: false,
    policy: {
      default_action: "warn",
      allow_expired_manifest: false,
      allow_offline_cached_manifest: false,
    },
  });
  await store.save(storePath);

  return { dir, kp, storePath, manifest };
}
