import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { sha256 } from "./hash.js";
import type { DetachedSignature } from "./manifest.js";
import type { TrustStore } from "./trust-store.js";

// Configure @noble/ed25519 v2 sha512 sync
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

// ---- Interfaces ----

export interface SignatureVerificationInput {
  manifestContent: Buffer;
  signature: DetachedSignature;
  trustStore: TrustStore;
}

export interface SignatureVerificationOutput {
  valid: boolean;
  reason?: string;
  keyId?: string;
  publisher?: string;
}

// ---- Helpers ----

/**
 * Decodes a base64url string to a Uint8Array.
 */
function base64urlDecode(input: string): Uint8Array {
  // Convert base64url to standard base64
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

// ---- Main function ----

/**
 * Verifies an Ed25519 detached signature against a manifest and trust store.
 *
 * Steps:
 * 1. Compute SHA-256 of manifestContent
 * 2. Compare with signature.manifest_sha256 — mismatch → invalid
 * 3. Look up signature.key_id in trust store — not found → invalid
 * 4. Check key revocation status — revoked → invalid
 * 5. Verify Ed25519 signature over manifestContent using the public key
 */
export async function verifySignature(
  input: SignatureVerificationInput
): Promise<SignatureVerificationOutput> {
  const { manifestContent, signature, trustStore } = input;

  // Step 1 & 2: Compute manifest hash and compare
  const computedHash = sha256(manifestContent);
  if (computedHash !== signature.manifest_sha256) {
    return {
      valid: false,
      reason: "manifest hash mismatch",
    };
  }

  // Step 3: Look up key_id in trust store
  const entry = trustStore.getPublisher(signature.key_id);
  if (!entry) {
    return {
      valid: false,
      reason: "unknown signing key",
      keyId: signature.key_id,
    };
  }

  // Step 4: Check revocation status
  if (entry.revoked) {
    return {
      valid: false,
      reason: "key revoked",
      keyId: signature.key_id,
      publisher: entry.publisher,
    };
  }

  // Step 5: Verify Ed25519 signature
  try {
    const sigBytes = base64urlDecode(signature.signature);
    const pubKeyBytes = Uint8Array.from(
      Buffer.from(entry.public_key, "base64")
    );

    const isValid = await ed.verifyAsync(sigBytes, manifestContent, pubKeyBytes);

    if (!isValid) {
      return {
        valid: false,
        reason: "signature verification failed",
        keyId: signature.key_id,
        publisher: entry.publisher,
      };
    }

    return {
      valid: true,
      keyId: signature.key_id,
      publisher: entry.publisher,
    };
  } catch {
    return {
      valid: false,
      reason: "signature verification failed",
      keyId: signature.key_id,
      publisher: entry.publisher,
    };
  }
}
