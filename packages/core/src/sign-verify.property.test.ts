// Feature: contextlock, Properties 6, 13 — Signature verification and Ed25519 keypair property tests
// Property 6: Sign-then-verify round-trip — Validates: Requirements 3.2, 3.4, 12.1, 12.2, 12.3
// Property 13: Ed25519 keypair validity — Validates: Requirements 10.1

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { verifySignature } from "./signature.js";
import { sha256 } from "./hash.js";
import { TrustStore } from "./trust-store.js";
import type { DetachedSignature } from "./manifest.js";
import type { TrustedPublisher } from "./trust-store.js";

// Configure @noble/ed25519 v2 sha512 sync
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

// ---- Helpers ----

async function signAndBuildFixture(manifestContent: Buffer, privKey: Uint8Array, pubKey: Uint8Array) {
  const manifestHash = sha256(manifestContent);
  const sigBytes = await ed.signAsync(manifestContent, privKey);

  const sigBase64url = Buffer.from(sigBytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const keyId = "prop-test-key";
  const pubKeyBase64 = Buffer.from(pubKey).toString("base64");
  const fingerprint = sha256(Buffer.from(pubKey));

  const signature: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: manifestHash,
    algorithm: "Ed25519",
    key_id: keyId,
    signature: sigBase64url,
  };

  const publisher: TrustedPublisher = {
    publisher: "Property Test Publisher",
    key_id: keyId,
    public_key: pubKeyBase64,
    fingerprint,
    revoked: false,
    policy: {
      default_action: "block",
      allow_expired_manifest: false,
      allow_offline_cached_manifest: false,
    },
  };

  return { signature, publisher };
}

// ---- Property 6: Sign-then-verify round-trip ----

describe("Property 6: Sign-then-verify round-trip", () => {
  // **Validates: Requirements 3.2, 3.4, 12.1, 12.2, 12.3**
  it("signing with private key and verifying with matching public key succeeds; different public key fails", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 512 }),
        async (contentBytes) => {
          const manifestContent = Buffer.from(contentBytes);

          // Generate keypair
          const privKey = ed.utils.randomPrivateKey();
          const pubKey = await ed.getPublicKeyAsync(privKey);

          // Sign and build fixture
          const { signature, publisher } = await signAndBuildFixture(manifestContent, privKey, pubKey);

          // Verify with correct public key — should succeed
          const trustStore = new TrustStore();
          trustStore.addPublisher(publisher);

          const result = await verifySignature({
            manifestContent,
            signature,
            trustStore,
          });

          expect(result.valid).toBe(true);
          expect(result.keyId).toBe("prop-test-key");

          // Generate a different keypair and verify with wrong public key — should fail
          const otherPriv = ed.utils.randomPrivateKey();
          const otherPub = await ed.getPublicKeyAsync(otherPriv);

          const wrongPublisher: TrustedPublisher = {
            ...publisher,
            public_key: Buffer.from(otherPub).toString("base64"),
            fingerprint: sha256(Buffer.from(otherPub)),
          };

          const wrongStore = new TrustStore();
          wrongStore.addPublisher(wrongPublisher);

          const wrongResult = await verifySignature({
            manifestContent,
            signature,
            trustStore: wrongStore,
          });

          expect(wrongResult.valid).toBe(false);
          expect(wrongResult.reason).toBe("signature verification failed");
        },
      ),
      { numRuns: 100 },
    );
  });
});


// ---- Property 13: Ed25519 keypair validity ----

describe("Property 13: Ed25519 keypair validity", () => {
  // **Validates: Requirements 10.1**
  it("generated keypairs produce valid signatures that verify with the matching public key", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 1024 }),
        async (messageBytes) => {
          const message = new Uint8Array(messageBytes);

          // Generate keypair
          const privKey = ed.utils.randomPrivateKey();
          const pubKey = await ed.getPublicKeyAsync(privKey);

          // Sign arbitrary message
          const sig = await ed.signAsync(message, privKey);

          // Verify with matching public key — should succeed
          const isValid = await ed.verifyAsync(sig, message, pubKey);
          expect(isValid).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});
