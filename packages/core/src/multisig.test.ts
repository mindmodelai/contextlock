// Reviewer multi-signatures (SPEC v2 6.2): the DSSE envelope carries multiple
// signatures natively; verification collects every distinct trusted key and
// the engine can require a threshold.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { signEnvelope, verifyEnvelope, serializeEnvelope, MANIFEST_PAYLOAD_TYPE } from "./dsse.js";
import type { CandidateKey } from "./dsse.js";
import { VerificationEngine } from "./engine.js";
import { TrustStore } from "./trust-store.js";
import {
  makeKeypair,
  makeManifest,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "./testkit.js";
import type { TestKeypair } from "./testkit.js";
import { serializeManifest } from "./manifest.js";

function candidate(kp: TestKeypair, publisher = "TestPub", revoked = false): CandidateKey {
  return { keyid: kp.keyId, publicKey: kp.publicKey, publisher, revoked };
}

describe("verifyEnvelope multi-signature collection", () => {
  it("collects every distinct trusted key that signed", async () => {
    const author = await makeKeypair("cl-author");
    const reviewer = await makeKeypair("cl-reviewer");
    const payload = Buffer.from("{}");
    const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
      { privateKey: author.privateKey, keyid: author.keyId },
      { privateKey: reviewer.privateKey, keyid: reviewer.keyId },
    ]);

    const result = await verifyEnvelope(env, [
      candidate(author, "Author"),
      candidate(reviewer, "Reviewer"),
    ]);
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(2);
    expect(result.signers!.map((s) => s.keyId).sort()).toEqual(
      [author.keyId, reviewer.keyId].sort(),
    );
  });

  it("counts a key only once even if pinned twice", async () => {
    const kp = await makeKeypair("cl-dup");
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey: kp.privateKey, keyid: kp.keyId },
    ]);
    const result = await verifyEnvelope(env, [
      candidate(kp, "A"),
      { ...candidate(kp, "B"), keyid: "cl-alias" },
    ]);
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(1);
  });

  it("a revoked reviewer key does not count toward the signer list", async () => {
    const author = await makeKeypair("cl-author");
    const reviewer = await makeKeypair("cl-reviewer");
    const env = await signEnvelope(Buffer.from("{}"), MANIFEST_PAYLOAD_TYPE, [
      { privateKey: author.privateKey, keyid: author.keyId },
      { privateKey: reviewer.privateKey, keyid: reviewer.keyId },
    ]);
    const result = await verifyEnvelope(env, [
      candidate(author, "Author"),
      candidate(reviewer, "Reviewer", true),
    ]);
    expect(result.valid).toBe(true);
    expect(result.signers).toHaveLength(1);
    expect(result.signers![0].keyId).toBe(author.keyId);
  });
});

describe("engine requiredSigners threshold", () => {
  let dir: string;
  let trustStorePath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cl-multisig-"));
    trustStorePath = join(dir, "truststore.json");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  function makeEngine(requiredSigners: number): VerificationEngine {
    return new VerificationEngine({
      trustStorePath,
      cachePath: "",
      protectedPatterns: ["**/SKILL.md"],
      policyLevel: "strict",
      workspaceRoot: dir,
      stateStorePath: join(dir, "state.json"),
      requiredSigners,
    });
  }

  it("blocks below the threshold, passes at it, reports signerCount", async () => {
    const author = await makeKeypair("cl-author");
    const reviewer = await makeKeypair("cl-reviewer");
    const content = "# Reviewed skill\n";
    const pkg = uniquePackageName("multisig");

    // Author-only package first.
    const { manifest } = await writeSignedPackage(dir, author, {
      packageName: pkg,
      files: { "SKILL.md": content },
    });
    await writeTrustStore(trustStorePath, [author, reviewer]);

    const single = await makeEngine(2).verify(join(dir, "SKILL.md"));
    expect(single.status).toBe("untrusted");
    expect(single.reason).toContain("insufficient signatures");

    // Countersign the SAME payload with the reviewer key (both sigs valid).
    const env = await signEnvelope(
      Buffer.from(serializeManifest(manifest), "utf-8"),
      MANIFEST_PAYLOAD_TYPE,
      [
        { privateKey: author.privateKey, keyid: author.keyId },
        { privateKey: reviewer.privateKey, keyid: reviewer.keyId },
      ],
    );
    await writeFile(join(dir, "contextlock.dsse.json"), serializeEnvelope(env), "utf-8");

    const dual = await makeEngine(2).verify(join(dir, "SKILL.md"));
    expect(dual.status).toBe("trusted");
    expect(dual.signerCount).toBe(2);

    // Threshold 1 also passes, reporting both signers.
    const relaxed = await makeEngine(1).verify(join(dir, "SKILL.md"));
    expect(relaxed.status).toBe("trusted");
    expect(relaxed.signerCount).toBe(2);
  });

  it("an untrusted second signature does not satisfy the threshold", async () => {
    const author = await makeKeypair("cl-author");
    const stranger = await makeKeypair("cl-stranger");
    const pkg = uniquePackageName("multisig-stranger");
    const content = "# Skill\n";

    const manifest = makeManifest({ packageName: pkg, keyId: author.keyId, files: { "SKILL.md": content } });
    const env = await signEnvelope(
      Buffer.from(serializeManifest(manifest), "utf-8"),
      MANIFEST_PAYLOAD_TYPE,
      [
        { privateKey: author.privateKey, keyid: author.keyId },
        { privateKey: stranger.privateKey, keyid: stranger.keyId }, // not in trust store
      ],
    );
    await writeFile(join(dir, "SKILL.md"), content, "utf-8");
    await writeFile(join(dir, "contextlock.dsse.json"), serializeEnvelope(env), "utf-8");
    await writeTrustStore(trustStorePath, [author]);

    const result = await makeEngine(2).verify(join(dir, "SKILL.md"));
    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("insufficient signatures");
    expect(result.reason).toContain("1 distinct trusted key");
  });
});
