/**
 * sign-manifest command — Wrap a contextlock/2 manifest in a signed DSSE
 * envelope (SPEC v2 6.2). One file replaces v1's two: the package ships
 * `contextlock.dsse.json` (envelope containing the manifest).
 */

import { readFile, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  computeFingerprint,
  parseManifest,
  signEnvelope,
  serializeEnvelope,
  base64urlDecode,
  MANIFEST_PAYLOAD_TYPE,
  ENVELOPE_FILENAME,
} from "@contextlock/core";
import type { DsseEnvelope } from "@contextlock/core";
import { defaultKeyId } from "./init-key.js";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

export interface SignManifestOptions {
  /** Path to the unsigned manifest JSON. Ignored when manifestBytes is given. */
  manifestPath?: string;
  /** Exact manifest bytes to sign (verbatim payload). */
  manifestBytes?: Buffer | string;
  privateKeyPath: string;
  /** keyid hint recorded on the signature (default: manifest publisher.key_id). */
  keyId?: string;
  outputPath?: string;
}

export interface SignManifestResult {
  envelopePath: string;
  envelope: DsseEnvelope;
  keyId: string;
  fingerprint: string;
}

/** Reads a raw 32-byte Ed25519 key file (base64url or legacy base64). */
export async function readRawKey(path: string): Promise<Uint8Array> {
  const raw = (await readFile(path, "utf-8")).trim();
  const key = base64urlDecode(raw);
  if (key.length !== 32) {
    throw new Error(`key at ${path} is malformed (expected raw 32 bytes, got ${key.length})`);
  }
  return key;
}

/**
 * Signs a manifest and writes the DSSE envelope (contextlock.dsse.json).
 */
export async function signManifest(options: SignManifestOptions): Promise<SignManifestResult> {
  const { manifestPath, manifestBytes, privateKeyPath, outputPath } = options;

  let payload: Buffer;
  if (manifestBytes !== undefined) {
    payload = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes, "utf-8");
  } else if (manifestPath) {
    payload = await readFile(manifestPath);
  } else {
    throw new Error("signManifest requires manifestPath or manifestBytes");
  }

  // Fail early on a malformed manifest — never sign an invalid payload.
  const manifest = parseManifest(payload);

  const privateKey = await readRawKey(privateKeyPath);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const fingerprint = computeFingerprint(Buffer.from(publicKey));
  const keyId = options.keyId ?? manifest.publisher.key_id ?? defaultKeyId(fingerprint);

  const envelope = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
    { privateKey, keyid: keyId },
  ]);

  if (!outputPath && !manifestPath) {
    throw new Error("signManifest requires outputPath when signing manifestBytes directly");
  }
  const envelopePath = outputPath ?? join(dirname(manifestPath!), ENVELOPE_FILENAME);
  await writeFile(envelopePath, serializeEnvelope(envelope), "utf-8");

  return {
    envelopePath,
    envelope,
    keyId,
    fingerprint,
  };
}
