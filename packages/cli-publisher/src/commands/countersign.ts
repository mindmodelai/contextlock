/**
 * countersign command — Append a reviewer signature to an existing DSSE
 * envelope (SPEC v2 6.2: multiple signatures are supported by the envelope
 * natively; reviewer attestations converge with SkillSeal's idea).
 *
 * The payload bytes are NOT re-read or re-serialized: the countersignature is
 * computed over PAE(payloadType, payload) of the exact existing payload, so
 * every earlier signature stays valid.
 */

import { readFile, writeFile } from "node:fs/promises";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  computeFingerprint,
  parseEnvelope,
  serializeEnvelope,
  pae,
  b64Decode,
  b64Encode,
} from "@contextlock/core";
import type { DsseEnvelope } from "@contextlock/core";
import { defaultKeyId } from "./init-key.js";
import { readRawKey } from "./sign-manifest.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

export interface CountersignOptions {
  envelopePath: string;
  privateKeyPath: string;
  /** keyid hint recorded on the appended signature (default cl-<fp8>). */
  keyId?: string;
  outputPath?: string;
}

export interface CountersignResult {
  envelopePath: string;
  envelope: DsseEnvelope;
  keyId: string;
  fingerprint: string;
  signatureCount: number;
}

export async function countersign(options: CountersignOptions): Promise<CountersignResult> {
  const envelope = parseEnvelope(await readFile(options.envelopePath));

  const privateKey = await readRawKey(options.privateKeyPath);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const fingerprint = computeFingerprint(Buffer.from(publicKey));
  const keyId = options.keyId ?? defaultKeyId(fingerprint);

  // Sign the EXACT existing payload bytes over PAE.
  const payload = b64Decode(envelope.payload);
  const preAuth = pae(envelope.payloadType, payload);
  const sig = await ed.signAsync(new Uint8Array(preAuth), privateKey);

  // Refuse a duplicate countersignature by the same key.
  for (const existing of envelope.signatures) {
    try {
      const existingSig = new Uint8Array(b64Decode(existing.sig));
      if (await ed.verifyAsync(existingSig, new Uint8Array(preAuth), publicKey)) {
        throw new Error(`envelope is already signed by this key (${keyId})`);
      }
    } catch (e) {
      if ((e as Error).message.includes("already signed")) throw e;
      // Malformed/foreign signature - not ours, keep going.
    }
  }

  envelope.signatures.push({ keyid: keyId, sig: b64Encode(sig) });

  const outPath = options.outputPath ?? options.envelopePath;
  await writeFile(outPath, serializeEnvelope(envelope), "utf-8");

  return {
    envelopePath: outPath,
    envelope,
    keyId,
    fingerprint,
    signatureCount: envelope.signatures.length,
  };
}
