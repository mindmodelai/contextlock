// Feature: contextlock, Properties 9, 12 — Trust store and revoked key property tests
// Property 9: Trust store add-then-remove round-trip
// Property 12: Revoked key rejection (v2: DSSE envelope verification)

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { TrustStore } from "./trust-store.js";
import type { TrustedPublisher } from "./trust-store.js";
import { signEnvelope, verifyEnvelope, MANIFEST_PAYLOAD_TYPE } from "./dsse.js";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

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
  it("adding then removing a publisher by key_id leaves it absent and other entries unchanged", () => {
    fc.assert(
      fc.property(
        fc.array(trustedPublisherArb(alphaNum.map((s) => `other-${s}`)), { minLength: 0, maxLength: 5 }),
        trustedPublisherArb(fc.constant("target-key")),
        (otherPublishers, targetPublisher) => {
          // Deduplicate other publishers by key_id; removePublisher also
          // matches fingerprints, so keep those distinct from the target too.
          const seen = new Set<string>();
          const uniqueOthers = otherPublishers.filter((p) => {
            if (seen.has(p.key_id) || p.key_id === "target-key") return false;
            if (p.fingerprint === targetPublisher.fingerprint) return false;
            seen.add(p.key_id);
            return true;
          });

          const store = new TrustStore();

          for (const p of uniqueOthers) {
            store.addPublisher(p);
          }

          store.addPublisher(targetPublisher);
          expect(store.getPublisher("target-key")).toBeDefined();

          store.removePublisher("target-key");

          expect(store.getPublisher("target-key")).toBeUndefined();

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

describe("Property 12: Revoked key rejection (DSSE)", () => {
  it("envelope verification returns 'key revoked' for any payload signed by a revoked key", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 1, maxLength: 256 }),
        async (contentBytes) => {
          const payload = Buffer.from(contentBytes);

          // Generate a real keypair and sign the payload
          const privKey = ed.utils.randomPrivateKey();
          const pubKey = await ed.getPublicKeyAsync(privKey);
          const keyId = "revoked-key-id";

          const envelope = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
            { privateKey: privKey, keyid: keyId },
          ]);

          const trustStore = new TrustStore();
          trustStore.addPublisher({
            publisher: "Revoked Publisher",
            key_id: keyId,
            public_key: Buffer.from(pubKey).toString("base64"),
            fingerprint: "f".repeat(64),
            revoked: true,
            policy: {
              default_action: "block",
              allow_expired_manifest: false,
              allow_offline_cached_manifest: false,
            },
          });

          const result = await verifyEnvelope(envelope, trustStore.candidateKeys());

          // Invalid with reason "key revoked" regardless of signature validity
          expect(result.valid).toBe(false);
          expect(result.reason).toBe("key revoked");
          expect(result.keyId).toBe(keyId);
        },
      ),
      { numRuns: 100 },
    );
  });
});
