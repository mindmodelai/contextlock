// Root of trust + rotation (SPEC v2 6.5): minimal chained root, threshold of
// both old and new keys, version exactly N+1, fast-forward recovery hooks.

import { describe, it, expect } from "vitest";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  parseRoot,
  validateRoot,
  verifyInitialRoot,
  verifyRootTransition,
  ROOT_SPEC_VERSION,
} from "./root.js";
import type { RootFile } from "./root.js";
import { signEnvelope, ROOT_PAYLOAD_TYPE, MANIFEST_PAYLOAD_TYPE } from "./dsse.js";
import type { EnvelopeSigner } from "./dsse.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

interface TestKey {
  keyid: string;
  privateKey: Uint8Array;
  pub: string; // base64url
}

async function makeKey(keyid: string): Promise<TestKey> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { keyid, privateKey, pub: Buffer.from(publicKey).toString("base64url") };
}

const FUTURE = "2030-01-01T00:00:00Z";

function makeRoot(version: number, keys: TestKey[], threshold = 1, expiresAt = FUTURE): RootFile {
  return {
    spec_version: ROOT_SPEC_VERSION,
    version,
    expires_at: expiresAt,
    keys: Object.fromEntries(keys.map((k) => [k.keyid, { alg: "ed25519" as const, pub: k.pub }])),
    threshold,
  };
}

async function signRoot(root: RootFile, signers: TestKey[]) {
  const payload = Buffer.from(JSON.stringify(root), "utf-8");
  const envSigners: EnvelopeSigner[] = signers.map((k) => ({
    privateKey: k.privateKey,
    keyid: k.keyid,
  }));
  return signEnvelope(payload, ROOT_PAYLOAD_TYPE, envSigners);
}

describe("validateRoot / parseRoot", () => {
  it("accepts a minimal valid root", async () => {
    const k = await makeKey("cl-acme-2026");
    const root = makeRoot(1, [k]);
    expect(validateRoot(root)).toEqual([]);
    expect(parseRoot(JSON.stringify(root))).toEqual(root);
  });

  it("rejects bad spec_version, version, threshold, and malformed keys", async () => {
    const k = await makeKey("k1");
    expect(validateRoot({ ...makeRoot(1, [k]), spec_version: "x" }).length).toBeGreaterThan(0);
    expect(validateRoot({ ...makeRoot(1, [k]), version: 0 }).length).toBeGreaterThan(0);
    expect(validateRoot({ ...makeRoot(1, [k]), threshold: 2 }).length).toBeGreaterThan(0); // > key count
    expect(validateRoot({ ...makeRoot(1, [k]), keys: {} }).length).toBeGreaterThan(0);
    expect(
      validateRoot({ ...makeRoot(1, [k]), keys: { k1: { alg: "rsa", pub: k.pub } } }).length,
    ).toBeGreaterThan(0);
    expect(
      validateRoot({ ...makeRoot(1, [k]), keys: { k1: { alg: "ed25519", pub: "AAAA" } } }).length,
    ).toBeGreaterThan(0); // not 32 bytes
  });
});

describe("verifyInitialRoot", () => {
  it("accepts a self-signed root meeting its own threshold", async () => {
    const k = await makeKey("cl-acme-2026");
    const root = makeRoot(1, [k]);
    const env = await signRoot(root, [k]);
    const verdict = await verifyInitialRoot(env);
    expect(verdict.ok).toBe(true);
    expect(verdict.root).toEqual(root);
  });

  it("rejects a root not meeting its own threshold", async () => {
    const k1 = await makeKey("k1");
    const k2 = await makeKey("k2");
    const root = makeRoot(1, [k1, k2], 2);
    const env = await signRoot(root, [k1]); // only 1 of 2
    const verdict = await verifyInitialRoot(env);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/threshold/);
  });

  it("rejects an expired root and a wrong payloadType", async () => {
    const k = await makeKey("k1");
    const expired = makeRoot(1, [k], 1, "2020-01-01T00:00:00Z");
    const env = await signRoot(expired, [k]);
    expect((await verifyInitialRoot(env)).ok).toBe(false);

    const root = makeRoot(1, [k]);
    const wrongType = await signEnvelope(
      Buffer.from(JSON.stringify(root)),
      MANIFEST_PAYLOAD_TYPE,
      [{ privateKey: k.privateKey, keyid: k.keyid }],
    );
    const verdict = await verifyInitialRoot(wrongType);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/payloadType/);
  });
});

describe("verifyRootTransition (TUF rotation chain)", () => {
  it("accepts version N+1 signed by both old and new keys", async () => {
    const oldKey = await makeKey("cl-2026");
    const newKey = await makeKey("cl-2027");
    const rootV1 = makeRoot(1, [oldKey]);
    const rootV2 = makeRoot(2, [newKey]);
    const env = await signRoot(rootV2, [oldKey, newKey]);

    const verdict = await verifyRootTransition(rootV1, env);
    expect(verdict.ok).toBe(true);
    expect(verdict.root).toEqual(rootV2);
  });

  it("rejects a rotation missing the OLD key signature", async () => {
    const oldKey = await makeKey("cl-2026");
    const newKey = await makeKey("cl-2027");
    const rootV2 = makeRoot(2, [newKey]);
    const env = await signRoot(rootV2, [newKey]); // new only

    const verdict = await verifyRootTransition(makeRoot(1, [oldKey]), env);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/old-key threshold/);
  });

  it("rejects a rotation missing the NEW key signature", async () => {
    const oldKey = await makeKey("cl-2026");
    const newKey = await makeKey("cl-2027");
    const rootV2 = makeRoot(2, [newKey]);
    const env = await signRoot(rootV2, [oldKey]); // old only

    const verdict = await verifyRootTransition(makeRoot(1, [oldKey]), env);
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/new-key threshold/);
  });

  it("rejects version jumps and replays (must be exactly N+1)", async () => {
    const oldKey = await makeKey("cl-2026");
    const newKey = await makeKey("cl-2027");
    const current = makeRoot(3, [oldKey]);

    for (const v of [3, 5, 2, 1]) {
      const candidateRoot = makeRoot(v, [newKey]);
      const env = await signRoot(candidateRoot, [oldKey, newKey]);
      const verdict = await verifyRootTransition(current, env);
      expect(verdict.ok, `version ${v} should be rejected`).toBe(false);
      expect(verdict.reason).toMatch(/exactly 4/);
    }
  });

  it("enforces multi-key thresholds on both sides", async () => {
    const o1 = await makeKey("o1");
    const o2 = await makeKey("o2");
    const n1 = await makeKey("n1");
    const n2 = await makeKey("n2");
    const current = makeRoot(1, [o1, o2], 2);
    const next = makeRoot(2, [n1, n2], 2);

    // 2 old + 1 new: new threshold unmet
    let env = await signRoot(next, [o1, o2, n1]);
    expect((await verifyRootTransition(current, env)).ok).toBe(false);

    // 1 old + 2 new: old threshold unmet
    env = await signRoot(next, [o1, n1, n2]);
    expect((await verifyRootTransition(current, env)).ok).toBe(false);

    // 2 old + 2 new: accepted
    env = await signRoot(next, [o1, o2, n1, n2]);
    expect((await verifyRootTransition(current, env)).ok).toBe(true);
  });
});
