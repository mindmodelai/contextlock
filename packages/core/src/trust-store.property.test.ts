// Feature: contextlock, Properties 9, 12 — Trust store and revoked key property tests
// Property 9: Trust store add-then-remove round-trip — Validates: Requirements 5.3
// Property 12: Revoked key rejection — Validates: Requirements 9.1, 9.2, 9.3

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { TrustStore } from "./trust-store.js";
import type { TrustedPublisher } from "./trust-store.js";
import { verifySignature } from "./signature.js";
import { sha256 } from "./hash.js";
import type { DetachedSignature } from "./manifest.js";

// Configure @noble/ed25519 v2 sha512 sync
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

// ---- Arbitraries ----

/** Non-empty alphanumeric string */
const alphaNum = fc
  .array(
    fc.constantFrom(..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("")),
    { minLength: 1, maxLength: 20 },
  )
  .map((chars) => chars.join(""));

/** Lowercase hex string of exact length */
const hexString = (len: number) =>
  fc
    .array(fc.integer({ min: 0, max: 15 }), { minLength: len, maxLength: len })
    .map((nums) => nums.map((n) => n.toString(16)).join(""));

/** Random base64 string (simulating a public key) */
const base64Key = fc
  .uint8Array({ minLength: 32, maxLength: 32 })
  .map((bytes) => Buffer.from(bytes).toString("base64"));

/** Random PublisherPolicy */
const policyArb = fc.record({
  default_action: fc.constantFrom("block" as const, "warn" as const, "allow" as const),
  allow_expired_manifest: fc.boolean(),
  allow_offline_cached_manifest: fc.boolean(),
});

/** Random TrustedPublisher with a unique key_id */
const trustedPublisherArb = (keyIdArb: fc.Arbitrary<string> = alphaNum): fc.Arbitrary<TrustedPublisher> =>
  fc
    .tuple(alphaNum, keyIdArb, base64Key, hexString(64), policyArb)
    .map(([publisher, key_id, public_key, fingerprint, policy]) => ({
      publisher,
      key_id,
      public_key,
      fingerprint,
      revoked: false,
      policy,
    }));


// ---- Property 9: Trust store add-then-remove round-trip ----

describe("Property 9: Trust store add-then-remove round-trip", () => {
  // **Validates: Requirements 5.3**
  it("adding then removing a publisher by key_id leaves it absent and other entries unchanged", () => {
    fc.assert(
      fc.property(
        // Generate a list of publishers with unique key_ids, plus one target to add/remove
        fc.array(trustedPublisherArb(alphaNum.map((s) => `other-${s}`)), { minLength: 0, maxLength: 5 }),
        trustedPublisherArb(fc.constant("target-key")),
        (otherPublishers, targetPublisher) => {
          // Deduplicate other publishers by key_id
          const seen = new Set<string>();
          const uniqueOthers = otherPublishers.filter((p) => {
            if (seen.has(p.key_id) || p.key_id === "target-key") return false;
            seen.add(p.key_id);
            return true;
          });

          const store = new TrustStore();

          // Add other publishers first
          for (const p of uniqueOthers) {
            store.addPublisher(p);
          }

          // Add the target publisher
          store.addPublisher(targetPublisher);
          expect(store.getPublisher("target-key")).toBeDefined();

          // Remove the target publisher
          store.removePublisher("target-key");

          // Target should be absent
          expect(store.getPublisher("target-key")).toBeUndefined();

          // Other entries should be unchanged
          const remaining = store.listPublishers();
          expect(remaining).toHaveLength(uniqueOthers.length);
          for (const p of uniqueOthers) {
            expect(store.getPublisher(p.key_id)).toEqual(p);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---- Property 12: Revoked key rejection ----

describe("Property 12: Revoked key rejection", () => {
  // **Validates: Requirements 9.1, 9.2, 9.3**
  it("verification returns invalid with reason 'key revoked' for any signature whose key_id is revoked", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        async (contentBytes) => {
          const manifestContent = Buffer.from(contentBytes);

          // Generate a real keypair and sign the content
          const privKey = ed.utils.randomPrivateKey();
          const pubKey = await ed.getPublicKeyAsync(privKey);

          const manifestHash = sha256(manifestContent);
          const sigBytes = await ed.signAsync(manifestContent, privKey);

          const sigBase64url = Buffer.from(sigBytes)
            .toString("base64")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");

          const keyId = "revoked-key-id";

          const signature: DetachedSignature = {
            schema: "tcv-signature/v1",
            manifest_sha256: manifestHash,
            algorithm: "Ed25519",
            key_id: keyId,
            signature: sigBase64url,
          };

          // Add publisher with revoked=true
          const revokedPublisher: TrustedPublisher = {
            publisher: "Revoked Publisher",
            key_id: keyId,
            public_key: Buffer.from(pubKey).toString("base64"),
            fingerprint: sha256(Buffer.from(pubKey)),
            revoked: true,
            policy: {
              default_action: "block",
              allow_expired_manifest: false,
              allow_offline_cached_manifest: false,
            },
          };

          const trustStore = new TrustStore();
          trustStore.addPublisher(revokedPublisher);

          const result = await verifySignature({
            manifestContent,
            signature,
            trustStore,
          });

          // Should be invalid with reason "key revoked" regardless of signature validity
          expect(result.valid).toBe(false);
          expect(result.reason).toBe("key revoked");
          expect(result.keyId).toBe(keyId);
        },
      ),
      { numRuns: 100 },
    );
  });
});
