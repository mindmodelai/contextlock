import { describe, it, expect } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  pae,
  parseEnvelope,
  serializeEnvelope,
  validateEnvelope,
  signEnvelope,
  verifyEnvelope,
  envelopeVerifiesWithKey,
  verifyingKeyIds,
  b64Decode,
  b64Encode,
  MANIFEST_PAYLOAD_TYPE,
} from "./dsse.js";
import type { CandidateKey, DsseEnvelope } from "./dsse.js";
import { sha256 } from "./hash.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

async function keypair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

function candidate(
  keyid: string,
  publicKey: Uint8Array,
  overrides: Partial<CandidateKey> = {},
): CandidateKey {
  return { keyid, publicKey, publisher: "TestPub", revoked: false, ...overrides };
}

// ---- PAE conformance ----

describe("PAE (Pre-Authentication Encoding)", () => {
  it("matches the DSSE specification test vector", () => {
    // https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
    const out = pae("http://example.com/HelloWorld", Buffer.from("hello world", "utf-8"));
    expect(out.toString("utf-8")).toBe("DSSEv1 29 http://example.com/HelloWorld 11 hello world");
  });

  it("uses BYTE lengths, not code-point counts", () => {
    // U+00E9 is 2 bytes in UTF-8
    const out = pae("t", Buffer.from("é", "utf-8"));
    expect(out.toString("utf-8")).toBe("DSSEv1 1 t 2 é");
  });

  it("is injective across type/body boundaries", () => {
    // Without length prefixes these two would collide.
    const a = pae("ab", Buffer.from("c", "utf-8"));
    const b = pae("a", Buffer.from("bc", "utf-8"));
    expect(a.equals(b)).toBe(false);
  });

  it("handles empty payloads", () => {
    const out = pae("t", Buffer.alloc(0));
    expect(out.toString("utf-8")).toBe("DSSEv1 1 t 0 ");
  });
});

// ---- Envelope structure ----

describe("validateEnvelope / parseEnvelope", () => {
  it("accepts a well-formed envelope", async () => {
    const { privateKey } = await keypair();
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-test" },
    ]);
    expect(validateEnvelope(env)).toEqual([]);
    expect(parseEnvelope(serializeEnvelope(env))).toEqual(env);
  });

  it("rejects missing payload / payloadType / signatures", () => {
    expect(validateEnvelope({}).length).toBeGreaterThan(0);
    expect(validateEnvelope({ payload: "e30=", payloadType: "t", signatures: [] }).length).toBeGreaterThan(0);
    expect(
      validateEnvelope({ payload: "!!!not-base64!!!", payloadType: "t", signatures: [{ sig: "e30=" }] })
        .some((e) => e.field === "payload"),
    ).toBe(true);
  });

  it("accepts both standard and url-safe base64", () => {
    const bytes = Buffer.from([0xfb, 0xef, 0xff]);
    const std = bytes.toString("base64");
    const url = bytes.toString("base64url");
    expect(b64Decode(std).equals(bytes)).toBe(true);
    expect(b64Decode(url).equals(bytes)).toBe(true);
    expect(b64Decode(b64Encode(bytes)).equals(bytes)).toBe(true);
  });
});

// ---- Sign / verify ----

describe("signEnvelope / verifyEnvelope", () => {
  it("round-trips: signed envelope verifies and returns the payload bytes", async () => {
    const { privateKey, publicKey } = await keypair();
    const payload = Buffer.from(JSON.stringify({ hello: "world" }), "utf-8");
    const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-test" },
    ]);

    const result = await verifyEnvelope(env, [candidate("cl-test", publicKey)]);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("cl-test");
    expect(result.publisher).toBe("TestPub");
    expect(result.keyFingerprint).toBe(sha256(Buffer.from(publicKey)));
    expect(result.payload!.equals(payload)).toBe(true);
  });

  it("fails on payload tampering", async () => {
    const { privateKey, publicKey } = await keypair();
    const env = await signEnvelope(Buffer.from('{"v":1}'), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-test" },
    ]);
    const tampered: DsseEnvelope = { ...env, payload: b64Encode(Buffer.from('{"v":2}')) };
    const result = await verifyEnvelope(tampered, [candidate("cl-test", publicKey)]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown signing key");
  });

  it("covers the payloadType (T12 cross-protocol replay)", async () => {
    const { privateKey, publicKey } = await keypair();
    const payload = Buffer.from("{}");
    const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [{ privateKey, keyid: "k" }]);
    const replayed: DsseEnvelope = { ...env, payloadType: "application/vnd.other+json" };
    expect(await envelopeVerifiesWithKey(replayed, publicKey)).toBe(false);
  });

  it("treats keyid as a hint only: wrong keyid still verifies with the right key", async () => {
    const { privateKey, publicKey } = await keypair();
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "totally-wrong-hint" },
    ]);
    // Candidate registered under a different keyid than the envelope's hint.
    const result = await verifyEnvelope(env, [candidate("cl-actual", publicKey)]);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("cl-actual");
  });

  it("reports 'key revoked' when the only verifying key is revoked", async () => {
    const { privateKey, publicKey } = await keypair();
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-rev" },
    ]);
    const result = await verifyEnvelope(env, [candidate("cl-rev", publicKey, { revoked: true })]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("key revoked");
    expect(result.keyId).toBe("cl-rev");
  });

  it("prefers a valid non-revoked key over a revoked copy of the same key", async () => {
    const { privateKey, publicKey } = await keypair();
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-a" },
    ]);
    const result = await verifyEnvelope(env, [
      candidate("cl-a", publicKey, { revoked: true }),
      candidate("cl-b", publicKey, { revoked: false }),
    ]);
    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("cl-b");
  });

  it("returns 'unknown signing key' when no candidate verifies", async () => {
    const { privateKey } = await keypair();
    const other = await keypair();
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey, keyid: "cl-x" },
    ]);
    const result = await verifyEnvelope(env, [candidate("cl-y", other.publicKey)]);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("unknown signing key");
  });

  it("supports multiple signatures and threshold counting", async () => {
    const k1 = await keypair();
    const k2 = await keypair();
    const k3 = await keypair();
    const payload = Buffer.from("{}");
    const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
      { privateKey: k1.privateKey, keyid: "k1" },
      { privateKey: k2.privateKey, keyid: "k2" },
    ]);
    const verified = await verifyingKeyIds(env, {
      k1: k1.publicKey,
      k2: k2.publicKey,
      k3: k3.publicKey,
    });
    expect(verified).toEqual(new Set(["k1", "k2"]));
  });
});
