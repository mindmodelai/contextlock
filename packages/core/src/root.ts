/**
 * Root of trust and rotation (SPEC v2 6.5) - a minimal chained root file,
 * TUF root role stripped to essentials:
 *
 *   { spec_version: "contextlock-root/1", version, expires_at,
 *     keys: { "<keyid>": { alg: "ed25519", pub: "<base64url raw 32B>" } },
 *     threshold }
 *
 * The root ships inside a DSSE envelope (payloadType
 * application/vnd.contextlock.root+json); the envelope's native multi-signature
 * support carries the rotation rule: a new root version must be signed by a
 * THRESHOLD OF BOTH the old root's keys and the new root's keys, with version
 * exactly N+1 (the TUF rotation chain).
 *
 * Deliberately NOT adopted from TUF: snapshot/timestamp roles, delegations,
 * consistent snapshots (SPEC v2 6.5 records the reasoning).
 */

import type { DsseEnvelope } from "./dsse.js";
import { ROOT_PAYLOAD_TYPE, b64Decode, verifyingKeyIds } from "./dsse.js";
import type { ValidationError } from "./manifest.js";

export const ROOT_SPEC_VERSION = "contextlock-root/1";

/** The conventional filename for a publisher's root envelope. */
export const ROOT_ENVELOPE_FILENAME = "contextlock.root.dsse.json";

export interface RootKey {
  alg: "ed25519";
  /** base64url raw 32-byte Ed25519 public key. */
  pub: string;
}

export interface RootFile {
  spec_version: typeof ROOT_SPEC_VERSION;
  version: number;
  expires_at: string;
  keys: Record<string, RootKey>;
  threshold: number;
}

// ---- Validation ----

const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/;

export function validateRoot(root: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (root == null || typeof root !== "object") {
    errors.push({ field: "root", message: "Root must be a non-null object" });
    return errors;
  }
  const r = root as Record<string, unknown>;

  if (r.spec_version !== ROOT_SPEC_VERSION) {
    errors.push({ field: "spec_version", message: `spec_version must be "${ROOT_SPEC_VERSION}"` });
  }
  if (typeof r.version !== "number" || !Number.isSafeInteger(r.version) || r.version < 1) {
    errors.push({ field: "version", message: "version is required and must be a positive integer" });
  }
  if (typeof r.expires_at !== "string" || !ISO_8601_RE.test(r.expires_at) || isNaN(new Date(r.expires_at).getTime())) {
    errors.push({ field: "expires_at", message: "expires_at is required and must be a valid ISO 8601 date-time" });
  }

  let keyCount = 0;
  if (r.keys == null || typeof r.keys !== "object" || Array.isArray(r.keys)) {
    errors.push({ field: "keys", message: "keys is required and must be an object" });
  } else {
    for (const [keyid, key] of Object.entries(r.keys as Record<string, unknown>)) {
      keyCount++;
      const k = key as Record<string, unknown> | null;
      if (k == null || typeof k !== "object") {
        errors.push({ field: `keys.${keyid}`, message: `keys.${keyid} must be an object` });
        continue;
      }
      if (k.alg !== "ed25519") {
        errors.push({ field: `keys.${keyid}.alg`, message: `keys.${keyid}.alg must be "ed25519"` });
      }
      if (typeof k.pub !== "string" || k.pub.length === 0) {
        errors.push({ field: `keys.${keyid}.pub`, message: `keys.${keyid}.pub is required` });
      } else {
        try {
          const raw = b64Decode(k.pub);
          if (raw.length !== 32) {
            errors.push({ field: `keys.${keyid}.pub`, message: `keys.${keyid}.pub must be a raw 32-byte Ed25519 key` });
          }
        } catch {
          errors.push({ field: `keys.${keyid}.pub`, message: `keys.${keyid}.pub is not valid base64url` });
        }
      }
    }
    if (keyCount === 0) {
      errors.push({ field: "keys", message: "keys must contain at least one key" });
    }
  }

  if (typeof r.threshold !== "number" || !Number.isSafeInteger(r.threshold) || r.threshold < 1) {
    errors.push({ field: "threshold", message: "threshold is required and must be a positive integer" });
  } else if (keyCount > 0 && r.threshold > keyCount) {
    errors.push({ field: "threshold", message: "threshold must not exceed the number of keys" });
  }

  return errors;
}

export function parseRoot(json: string | Buffer): RootFile {
  const text = typeof json === "string" ? json : json.toString("utf-8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }
  const errors = validateRoot(parsed);
  if (errors.length > 0) {
    throw new Error(`Invalid root: ${errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`);
  }
  return parsed as RootFile;
}

// ---- Verification ----

function rootKeyBytes(root: RootFile): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  for (const [keyid, key] of Object.entries(root.keys)) {
    out[keyid] = new Uint8Array(b64Decode(key.pub));
  }
  return out;
}

export function rootExpired(root: RootFile, now: Date = new Date()): boolean {
  return new Date(root.expires_at).getTime() < now.getTime();
}

export interface RootVerification {
  ok: boolean;
  reason?: string;
  root?: RootFile;
}

function envelopePayloadRoot(envelope: DsseEnvelope): RootFile {
  if (envelope.payloadType !== ROOT_PAYLOAD_TYPE) {
    throw new Error(
      `unexpected payloadType "${envelope.payloadType}" (expected "${ROOT_PAYLOAD_TYPE}")`,
    );
  }
  return parseRoot(b64Decode(envelope.payload));
}

/**
 * Verifies an INITIAL root envelope (trust-on-first-use pin): the payload must
 * be a valid root and the envelope must carry signatures meeting the root's
 * OWN threshold with its own keys (self-consistency).
 */
export async function verifyInitialRoot(envelope: DsseEnvelope): Promise<RootVerification> {
  let root: RootFile;
  try {
    root = envelopePayloadRoot(envelope);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  if (rootExpired(root)) {
    return { ok: false, reason: `root expired at ${root.expires_at}` };
  }
  const verified = await verifyingKeyIds(envelope, rootKeyBytes(root));
  if (verified.size < root.threshold) {
    return {
      ok: false,
      reason: `root self-signature threshold not met (${verified.size}/${root.threshold})`,
    };
  }
  return { ok: true, root };
}

/**
 * Verifies a rotation: `candidate` must contain root version exactly
 * current.version + 1, signed by a threshold of the CURRENT root's keys AND a
 * threshold of the NEW root's keys (each root's own threshold applies).
 */
export async function verifyRootTransition(
  current: RootFile,
  candidate: DsseEnvelope,
): Promise<RootVerification> {
  let next: RootFile;
  try {
    next = envelopePayloadRoot(candidate);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }

  if (next.version !== current.version + 1) {
    return {
      ok: false,
      reason: `root version must be exactly ${current.version + 1}, got ${next.version}`,
    };
  }
  if (rootExpired(next)) {
    return { ok: false, reason: `new root expired at ${next.expires_at}` };
  }

  const oldVerified = await verifyingKeyIds(candidate, rootKeyBytes(current));
  if (oldVerified.size < current.threshold) {
    return {
      ok: false,
      reason: `old-key threshold not met (${oldVerified.size}/${current.threshold})`,
    };
  }
  const newVerified = await verifyingKeyIds(candidate, rootKeyBytes(next));
  if (newVerified.size < next.threshold) {
    return {
      ok: false,
      reason: `new-key threshold not met (${newVerified.size}/${next.threshold})`,
    };
  }

  return { ok: true, root: next };
}
