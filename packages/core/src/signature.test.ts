import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { verifySignature } from "./signature.js";
import { sha256 } from "./hash.js";
import { TrustStore } from "./trust-store.js";
import type { DetachedSignature } from "./manifest.js";
import type { TrustedPublisher } from "./trust-store.js";

// Ensure sha512 sync is configured for key generation
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

/**
 * Helper: generate an Ed25519 keypair and build a valid signed manifest setup.
 */
async function buildSignedFixture(manifestContent: Buffer) {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);

  const manifestHash = sha256(manifestContent);
  const sigBytes = await ed.signAsync(manifestContent, privKey);

  // base64url-encode the signature
  const sigBase64url = Buffer.from(sigBytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const keyId = "test-key-001";
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
    publisher: "Test Publisher",
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

  return { privKey, pubKey, signature, publisher, keyId };
}

describe("verifySignature", () => {
  it("returns valid for a correctly signed manifest", async () => {
    const manifestContent = Buffer.from('{"schema":"tcv-manifest/v1","test":true}');
    const { signature, publisher } = await buildSignedFixture(manifestContent);

    const trustStore = new TrustStore();
    trustStore.addPublisher(publisher);

    const result = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    expect(result.valid).toBe(true);
    expect(result.keyId).toBe(publisher.key_id);
    expect(result.publisher).toBe("Test Publisher");
    expect(result.reason).toBeUndefined();
  });

  it("returns invalid with 'manifest hash mismatch' when hash differs", async () => {
    const manifestContent = Buffer.from("original content");
    const { signature } = await buildSignedFixture(manifestContent);

    // Tamper with the manifest_sha256
    const badSig: DetachedSignature = {
      ...signature,
      manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    };

    const trustStore = new TrustStore();

    const result = await verifySignature({
      manifestContent,
      signature: badSig,
      trustStore,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("manifest hash mismatch");
  });

  it("returns invalid with 'unknown signing key' when key_id not in trust store", async () => {
    const manifestContent = Buffer.from("some manifest");
    const { signature } = await buildSignedFixture(manifestContent);

    // Empty trust store — key_id won't be found
    const trustStore = new TrustStore();

    const result = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown signing key");
    expect(result.keyId).toBe(signature.key_id);
  });

  it("returns invalid with 'key revoked' when key is revoked", async () => {
    const manifestContent = Buffer.from("manifest for revoked key");
    const { signature, publisher } = await buildSignedFixture(manifestContent);

    const revokedPublisher: TrustedPublisher = {
      ...publisher,
      revoked: true,
    };

    const trustStore = new TrustStore();
    trustStore.addPublisher(revokedPublisher);

    const result = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("key revoked");
    expect(result.keyId).toBe(signature.key_id);
    expect(result.publisher).toBe("Test Publisher");
  });

  it("returns invalid with 'signature verification failed' when signature is wrong", async () => {
    const manifestContent = Buffer.from("real manifest content");
    const { signature, publisher } = await buildSignedFixture(manifestContent);

    // Generate a different keypair and use its public key
    const otherPriv = ed.utils.randomPrivateKey();
    const otherPub = await ed.getPublicKeyAsync(otherPriv);

    const wrongKeyPublisher: TrustedPublisher = {
      ...publisher,
      public_key: Buffer.from(otherPub).toString("base64"),
      fingerprint: sha256(Buffer.from(otherPub)),
    };

    const trustStore = new TrustStore();
    trustStore.addPublisher(wrongKeyPublisher);

    const result = await verifySignature({
      manifestContent,
      signature,
      trustStore,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature verification failed");
    expect(result.keyId).toBe(signature.key_id);
    expect(result.publisher).toBe("Test Publisher");
  });

  it("returns invalid when manifest content was tampered after signing", async () => {
    const originalContent = Buffer.from("original manifest");
    const { signature, publisher } = await buildSignedFixture(originalContent);

    const trustStore = new TrustStore();
    trustStore.addPublisher(publisher);

    // Tamper with the manifest content but keep the same hash in signature
    // This should fail at hash comparison step
    const tamperedContent = Buffer.from("tampered manifest");

    const result = await verifySignature({
      manifestContent: tamperedContent,
      signature,
      trustStore,
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe("manifest hash mismatch");
  });
});
