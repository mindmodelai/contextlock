/**
 * Integration test: root of trust through the full stack (SPEC v2 6.5).
 *
 * A manifest signed by a key that is only pinned via a publisher ROOT (not a
 * direct trust-store key) verifies; rotating the root swaps the accepted key
 * set and resets the anti-rollback baseline; an expired root's keys stop
 * verifying.
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import {
  VerificationEngine,
  TrustStore,
  signEnvelope,
  serializeEnvelope,
  ROOT_PAYLOAD_TYPE,
  ROOT_SPEC_VERSION,
} from "@contextlock/core";
import type { RootFile } from "@contextlock/core";
import { trustRootAdd, trustRootUpdate } from "@contextlock/cli-user";
import {
  makeKeypair,
  writeSignedPackage,
  uniquePackageName,
} from "../../packages/core/src/testkit.js";
import type { TestKeypair } from "../../packages/core/src/testkit.js";
import { createTempDir } from "./helpers.js";

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => {});
  dirs.length = 0;
});

const FUTURE = "2030-01-01T00:00:00Z";

function makeRoot(version: number, keys: TestKeypair[], expiresAt = FUTURE): RootFile {
  return {
    spec_version: ROOT_SPEC_VERSION as RootFile["spec_version"],
    version,
    expires_at: expiresAt,
    keys: Object.fromEntries(
      keys.map((k) => [
        k.keyId,
        { alg: "ed25519" as const, pub: Buffer.from(k.publicKey).toString("base64url") },
      ]),
    ),
    threshold: 1,
  };
}

async function writeRootEnvelope(
  path: string,
  root: RootFile,
  signers: TestKeypair[],
): Promise<void> {
  const envelope = await signEnvelope(
    Buffer.from(JSON.stringify(root), "utf-8"),
    ROOT_PAYLOAD_TYPE,
    signers.map((k) => ({ privateKey: k.privateKey, keyid: k.keyId })),
  );
  await writeFile(path, serializeEnvelope(envelope), "utf-8");
}

function engineFor(dir: string, trustStorePath: string): VerificationEngine {
  return new VerificationEngine({
    trustStorePath,
    cachePath: "",
    protectedPatterns: ["**/SKILL.md"],
    policyLevel: "strict",
    workspaceRoot: dir,
  });
}

describe("Root of trust end-to-end", () => {
  it("a manifest signed by a root-pinned key verifies; rotation swaps the key set", async () => {
    const root = await createTempDir("root-e2e-");
    dirs.push(root);
    const storePath = join(root, "truststore.json");

    const key2026 = await makeKeypair("cl-acme-2026");
    const key2027 = await makeKeypair("cl-acme-2027");

    // 1. Pin the initial root (v1, key2026) via the CLI command.
    const rootV1Path = join(root, "root-v1.dsse.json");
    await writeRootEnvelope(rootV1Path, makeRoot(1, [key2026]), [key2026]);
    const added = await trustRootAdd({
      publisher: "Acme",
      rootEnvelopePath: rootV1Path,
      trustStorePath: storePath,
    });
    expect(added.ok).toBe(true);

    // 2. A package signed by key2026 (root-derived; no direct trust entry).
    const pkgDir = join(root, "pkg");
    const pkg = uniquePackageName("root-pkg");
    await writeSignedPackage(pkgDir, key2026, {
      packageName: pkg,
      version: 7,
      publisherName: "Acme",
      files: { "SKILL.md": "# signed under root v1\n" },
    });

    const engine = engineFor(root, storePath);
    const verdict = await engine.verify(join(pkgDir, "SKILL.md"));
    expect(verdict.status).toBe("trusted");
    expect(verdict.publisher).toBe("Acme");

    // 3. Rotate: root v2 replaces key2026 with key2027 (signed by both).
    const rootV2Path = join(root, "root-v2.dsse.json");
    await writeRootEnvelope(rootV2Path, makeRoot(2, [key2027]), [key2026, key2027]);
    const updated = await trustRootUpdate({
      publisher: "Acme",
      rootEnvelopePath: rootV2Path,
      trustStorePath: storePath,
    });
    expect(updated.ok).toBe(true);
    expect(updated.root!.version).toBe(2);

    // 4. Old key no longer verifies; new key does. Rotation reset the
    //    rollback baseline, so the new key can restart its version counter.
    const oldKeyVerdict = await engine.verify(join(pkgDir, "SKILL.md"));
    expect(oldKeyVerdict.status).toBe("untrusted");

    await writeSignedPackage(pkgDir, key2027, {
      packageName: pkg,
      version: 1, // restarted counter: legal after fast-forward recovery
      publisherName: "Acme",
      files: { "SKILL.md": "# signed under root v2\n" },
    });
    const newKeyVerdict = await engine.verify(join(pkgDir, "SKILL.md"));
    expect(newKeyVerdict.status).toBe("trusted");
  });

  it("rejects a rotation not signed by the old root key", async () => {
    const root = await createTempDir("root-e2e-bad-");
    dirs.push(root);
    const storePath = join(root, "truststore.json");

    const oldKey = await makeKeypair("cl-old");
    const newKey = await makeKeypair("cl-new");

    const rootV1Path = join(root, "root-v1.dsse.json");
    await writeRootEnvelope(rootV1Path, makeRoot(1, [oldKey]), [oldKey]);
    await trustRootAdd({ publisher: "P", rootEnvelopePath: rootV1Path, trustStorePath: storePath });

    // Attacker forges a v2 root signed only by their own new key.
    const forgedPath = join(root, "root-v2-forged.dsse.json");
    await writeRootEnvelope(forgedPath, makeRoot(2, [newKey]), [newKey]);
    const result = await trustRootUpdate({
      publisher: "P",
      rootEnvelopePath: forgedPath,
      trustStorePath: storePath,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("old-key threshold");
  });

  it("keys from an expired root stop verifying", async () => {
    const root = await createTempDir("root-e2e-exp-");
    dirs.push(root);
    const storePath = join(root, "truststore.json");

    const key = await makeKeypair("cl-exp");
    // Pin an (already valid) root, then simulate time passing by writing the
    // expired root directly into the trust store.
    const store = new TrustStore();
    store.setRoot("ExpiredPub", makeRoot(1, [key], "2020-01-01T00:00:00Z"));
    await store.save(storePath);

    const pkgDir = join(root, "pkg");
    await writeSignedPackage(pkgDir, key, {
      packageName: uniquePackageName("root-exp"),
      publisherName: "ExpiredPub",
      files: { "SKILL.md": "# content\n" },
    });

    const verdict = await engineFor(root, storePath).verify(join(pkgDir, "SKILL.md"));
    expect(verdict.status).toBe("untrusted");
  });
});
