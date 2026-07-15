/**
 * DSSE v1.0.2 envelope (SPEC v2 6.2).
 *
 * Replaces v1's bespoke `tcv-signature/v1` detached signature. The envelope is
 * the one used by in-toto, SLSA, npm provenance, and Sigstore bundles:
 *
 *   { "payload": "<base64>", "payloadType": "...", "signatures": [{keyid?, sig}] }
 *
 * The signature is computed over PAE(payloadType, payload):
 *   "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 * Length-prefixing is injective and the payloadType is covered, killing
 * cross-protocol replay (threat T12).
 *
 * Per the DSSE spec, `keyid` is an UNAUTHENTICATED HINT and MUST NOT be used
 * for security decisions. Trust resolution walks the candidate key set and
 * tries pinned keys; the keyid only orders the candidate list.
 *
 * Verify-then-parse: callers must consume the payload returned by the verify
 * functions here, never a re-read of a sidecar file.
 */

import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import type { ValidationError } from "./manifest.js";
import { sha256 } from "./hash.js";

// @noble/ed25519 v2 needs a sha512 implementation wired up.
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// ---- Constants ----

/** payloadType for a contextlock/2 manifest payload. */
export const MANIFEST_PAYLOAD_TYPE = "application/vnd.contextlock.manifest+json";

/** payloadType for a contextlock-root/1 root-of-trust payload. */
export const ROOT_PAYLOAD_TYPE = "application/vnd.contextlock.root+json";

/** The single shipped artifact: envelope containing the manifest (SPEC v2 6.2). */
export const ENVELOPE_FILENAME = "contextlock.dsse.json";

/** Oversize defense (T11): refuse to parse envelopes beyond this size. */
export const MAX_ENVELOPE_BYTES = 2 * 1024 * 1024;

// ---- Types ----

export interface DsseSignature {
  /** Unauthenticated hint. MUST NOT be used for security decisions. */
  keyid?: string;
  /** base64 (standard or url-safe accepted; standard emitted). */
  sig: string;
}

export interface DsseEnvelope {
  /** base64 of the payload bytes (standard or url-safe accepted). */
  payload: string;
  payloadType: string;
  signatures: DsseSignature[];
}

/** A candidate verification key resolved from local trust state. */
export interface CandidateKey {
  /** Key label (short minisign-style id or fingerprint). */
  keyid: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Publisher display name this key belongs to. */
  publisher: string;
  /** Whether the key is revoked. Revoked keys still identify the signer. */
  revoked: boolean;
}

export interface EnvelopeVerification {
  valid: boolean;
  reason?: string;
  /** The candidate keyid that verified (or was revoked). */
  keyId?: string;
  /** SHA-256 hex fingerprint of the verifying public key (anti-rollback keying). */
  keyFingerprint?: string;
  publisher?: string;
  /** Decoded payload bytes of the VERIFIED envelope. Only set when valid. */
  payload?: Buffer;
}

// ---- base64 helpers (accept standard and url-safe; emit standard) ----

export function b64Decode(input: string): Buffer {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  else if (pad === 1) throw new Error("invalid base64 length");
  if (!/^[A-Za-z0-9+/]*=*$/.test(base64)) {
    throw new Error("invalid base64 characters");
  }
  return Buffer.from(base64, "base64");
}

export function b64Encode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

// ---- PAE ----

/**
 * DSSE Pre-Authentication Encoding:
 *   PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
 * Lengths are ASCII decimal byte lengths.
 */
export function pae(payloadType: string, payload: Uint8Array): Buffer {
  const typeBytes = Buffer.from(payloadType, "utf-8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${typeBytes.length} `, "utf-8"),
    typeBytes,
    Buffer.from(` ${payload.length} `, "utf-8"),
    Buffer.from(payload),
  ]);
}

// ---- Validation / parse / serialize ----

export function validateEnvelope(env: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (env == null || typeof env !== "object") {
    errors.push({ field: "envelope", message: "Envelope must be a non-null object" });
    return errors;
  }
  const e = env as Record<string, unknown>;

  if (typeof e.payloadType !== "string" || e.payloadType.length === 0) {
    errors.push({ field: "payloadType", message: "payloadType is required and must be a non-empty string" });
  }
  if (typeof e.payload !== "string" || e.payload.length === 0) {
    errors.push({ field: "payload", message: "payload is required and must be a non-empty base64 string" });
  } else {
    try {
      b64Decode(e.payload);
    } catch {
      errors.push({ field: "payload", message: "payload is not valid base64" });
    }
  }
  if (!Array.isArray(e.signatures) || e.signatures.length === 0) {
    errors.push({ field: "signatures", message: "signatures is required and must be a non-empty array" });
  } else {
    for (let i = 0; i < e.signatures.length; i++) {
      const s = e.signatures[i] as Record<string, unknown> | null;
      if (s == null || typeof s !== "object" || typeof s.sig !== "string" || s.sig.length === 0) {
        errors.push({ field: `signatures[${i}]`, message: `signatures[${i}].sig is required and must be a non-empty string` });
        continue;
      }
      try {
        b64Decode(s.sig);
      } catch {
        errors.push({ field: `signatures[${i}].sig`, message: `signatures[${i}].sig is not valid base64` });
      }
      if (s.keyid !== undefined && typeof s.keyid !== "string") {
        errors.push({ field: `signatures[${i}].keyid`, message: `signatures[${i}].keyid must be a string if present` });
      }
    }
  }
  return errors;
}

export function parseEnvelope(json: string | Buffer): DsseEnvelope {
  const text = typeof json === "string" ? json : json.toString("utf-8");
  if (Buffer.byteLength(text) > MAX_ENVELOPE_BYTES) {
    throw new Error(`envelope exceeds maximum size (${MAX_ENVELOPE_BYTES} bytes)`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }
  const errors = validateEnvelope(parsed);
  if (errors.length > 0) {
    throw new Error(`Invalid envelope: ${errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`);
  }
  return parsed as DsseEnvelope;
}

export function serializeEnvelope(env: DsseEnvelope): string {
  return JSON.stringify(env, null, 2);
}

// ---- Sign ----

export interface EnvelopeSigner {
  /** Raw 32-byte Ed25519 private key (seed). */
  privateKey: Uint8Array;
  /** Optional keyid hint recorded on the signature entry. */
  keyid?: string;
}

/**
 * Creates a DSSE envelope over `payload`, signed by each of `signers`.
 * Multiple signers are supported natively (root rotation, future multi-sig).
 */
export async function signEnvelope(
  payload: Uint8Array,
  payloadType: string,
  signers: EnvelopeSigner[],
): Promise<DsseEnvelope> {
  if (signers.length === 0) {
    throw new Error("signEnvelope requires at least one signer");
  }
  const preAuth = pae(payloadType, payload);
  const signatures: DsseSignature[] = [];
  for (const signer of signers) {
    const sig = await ed.signAsync(new Uint8Array(preAuth), signer.privateKey);
    signatures.push(
      signer.keyid !== undefined
        ? { keyid: signer.keyid, sig: b64Encode(sig) }
        : { sig: b64Encode(sig) },
    );
  }
  return { payload: b64Encode(payload), payloadType, signatures };
}

// ---- Verify ----

/**
 * Returns true if ANY signature in the envelope verifies with `publicKey`
 * over PAE(payloadType, payload).
 */
export async function envelopeVerifiesWithKey(
  envelope: DsseEnvelope,
  publicKey: Uint8Array,
): Promise<boolean> {
  let payload: Buffer;
  try {
    payload = b64Decode(envelope.payload);
  } catch {
    return false;
  }
  const preAuth = new Uint8Array(pae(envelope.payloadType, payload));
  for (const s of envelope.signatures) {
    try {
      const sigBytes = new Uint8Array(b64Decode(s.sig));
      if (await ed.verifyAsync(sigBytes, preAuth, publicKey)) {
        return true;
      }
    } catch {
      // try next signature
    }
  }
  return false;
}

/**
 * Verifies an envelope against a set of candidate keys (SPEC v2 6.2).
 *
 * The keyid hint only ORDERS the candidates (hinted keys tried first); it
 * never excludes a key. Non-revoked candidates are tried before revoked ones
 * so that a signature by a revoked key is reported as "key revoked" rather
 * than "unknown signing key" (the more actionable verdict).
 */
export async function verifyEnvelope(
  envelope: DsseEnvelope,
  candidates: CandidateKey[],
): Promise<EnvelopeVerification> {
  const structural = validateEnvelope(envelope);
  if (structural.length > 0) {
    return {
      valid: false,
      reason: `invalid envelope: ${structural.map((e) => e.message).join("; ")}`,
    };
  }

  const hints = new Set(
    envelope.signatures.map((s) => s.keyid).filter((k): k is string => typeof k === "string"),
  );
  const ordered = [...candidates].sort((a, b) => {
    // non-revoked first, then hint matches first; stable otherwise
    if (a.revoked !== b.revoked) return a.revoked ? 1 : -1;
    const ah = hints.has(a.keyid) ? 0 : 1;
    const bh = hints.has(b.keyid) ? 0 : 1;
    return ah - bh;
  });

  for (const candidate of ordered) {
    if (await envelopeVerifiesWithKey(envelope, candidate.publicKey)) {
      const keyFingerprint = sha256(Buffer.from(candidate.publicKey));
      if (candidate.revoked) {
        return {
          valid: false,
          reason: "key revoked",
          keyId: candidate.keyid,
          keyFingerprint,
          publisher: candidate.publisher,
        };
      }
      return {
        valid: true,
        keyId: candidate.keyid,
        keyFingerprint,
        publisher: candidate.publisher,
        payload: b64Decode(envelope.payload),
      };
    }
  }

  return {
    valid: false,
    reason: "unknown signing key",
    keyId: envelope.signatures.find((s) => s.keyid)?.keyid,
  };
}

/**
 * Threshold verification: returns the set of keyids from `keys` whose key
 * verifies at least one signature in the envelope. Used for root rotation
 * (a new root must be signed by a threshold of both old and new keys).
 */
export async function verifyingKeyIds(
  envelope: DsseEnvelope,
  keys: Record<string, Uint8Array>,
): Promise<Set<string>> {
  const verified = new Set<string>();
  for (const [keyid, pub] of Object.entries(keys)) {
    if (await envelopeVerifiesWithKey(envelope, pub)) {
      verified.add(keyid);
    }
  }
  return verified;
}
