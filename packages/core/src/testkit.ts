/**
 * Test fixture builders for the v2 format (contextlock/2 + DSSE).
 *
 * NOT part of the public API surface documented in the README; exported as a
 * plain module (not *.test.ts) so unit, integration, and red-team tests across
 * packages can build signed packages without re-implementing the format.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { sha256 } from "./hash.js";
import { serializeManifest, MANIFEST_SPEC_VERSION } from "./manifest.js";
import type { Manifest } from "./manifest.js";
import {
  signEnvelope,
  serializeEnvelope,
  MANIFEST_PAYLOAD_TYPE,
  ENVELOPE_FILENAME,
} from "./dsse.js";
import type { DsseEnvelope } from "./dsse.js";
import { TrustStore } from "./trust-store.js";
import type { PublisherPolicy } from "./trust-store.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export interface TestKeypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** Standard base64 of the raw public key (trust-store wire format). */
  pubB64: string;
  fingerprint: string;
  keyId: string;
}

export async function makeKeypair(keyId?: string): Promise<TestKeypair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const fingerprint = sha256(Buffer.from(publicKey));
  return {
    privateKey,
    publicKey,
    pubB64: Buffer.from(publicKey).toString("base64"),
    fingerprint,
    keyId: keyId ?? `cl-${fingerprint.slice(0, 8)}`,
  };
}

export interface MakeManifestOptions {
  packageName: string;
  version?: number;
  displayVersion?: string;
  publisherName?: string;
  keyId: string;
  publishedAt?: string;
  expiresAt?: string;
  files: Record<string, string>;
  lints?: Record<string, string>;
}

const FAR_FUTURE = "2030-01-01T00:00:00Z";

export function makeManifest(opts: MakeManifestOptions): Manifest {
  return {
    spec_version: MANIFEST_SPEC_VERSION,
    package: opts.packageName,
    version: opts.version ?? 1,
    ...(opts.displayVersion ? { display_version: opts.displayVersion } : {}),
    publisher: {
      name: opts.publisherName ?? "Test Publisher",
      key_id: opts.keyId,
    },
    published_at: opts.publishedAt ?? "2026-01-01T00:00:00Z",
    expires_at: opts.expiresAt ?? FAR_FUTURE,
    files: Object.entries(opts.files).map(([path, content]) => ({
      path,
      sha256: sha256(Buffer.from(content, "utf-8")),
      length: Buffer.byteLength(content, "utf-8"),
    })),
    ...(opts.lints ? { lints: opts.lints } : {}),
  };
}

export async function signManifestEnvelope(
  manifest: Manifest,
  kp: TestKeypair,
): Promise<DsseEnvelope> {
  const payload = Buffer.from(serializeManifest(manifest), "utf-8");
  return signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
    { privateKey: kp.privateKey, keyid: kp.keyId },
  ]);
}

/**
 * Writes the package files plus a signed contextlock.dsse.json into `dir`.
 * Returns the manifest and envelope for further tampering in tests.
 */
export async function writeSignedPackage(
  dir: string,
  kp: TestKeypair,
  opts: Omit<MakeManifestOptions, "keyId"> & { keyId?: string },
): Promise<{ manifest: Manifest; envelope: DsseEnvelope; envelopePath: string }> {
  for (const [rel, content] of Object.entries(opts.files)) {
    const filePath = join(dir, rel);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, content, "utf-8");
  }
  const manifest = makeManifest({ ...opts, keyId: opts.keyId ?? kp.keyId });
  const envelope = await signManifestEnvelope(manifest, kp);
  const envelopePath = join(dir, ENVELOPE_FILENAME);
  await writeFile(envelopePath, serializeEnvelope(envelope), "utf-8");
  return { manifest, envelope, envelopePath };
}

export interface WriteTrustStoreOptions {
  publisherName?: string;
  revoked?: boolean;
  policy?: Partial<PublisherPolicy>;
}

/**
 * Writes a signed trust store (machine-local key; CONTEXTLOCK_HOME must point
 * at a temp dir in tests) containing the given keypairs.
 */
export async function writeTrustStore(
  path: string,
  keypairs: TestKeypair[],
  opts: WriteTrustStoreOptions = {},
): Promise<TrustStore> {
  const store = new TrustStore();
  for (const kp of keypairs) {
    store.addPublisher({
      publisher: opts.publisherName ?? "Test Publisher",
      key_id: kp.keyId,
      public_key: kp.pubB64,
      fingerprint: kp.fingerprint,
      revoked: opts.revoked ?? false,
      policy: {
        default_action: opts.policy?.default_action ?? "block",
        allow_expired_manifest: opts.policy?.allow_expired_manifest ?? false,
        allow_offline_cached_manifest: opts.policy?.allow_offline_cached_manifest ?? false,
      },
    });
  }
  await store.save(path);
  return store;
}

/** Unique-enough package name so shared rollback state never collides across tests. */
export function uniquePackageName(prefix = "pkg"): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
