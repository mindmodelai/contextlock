// Engine integration for Mode 0 (SPEC v2 5): combination rules for the two
// evidence sources (seal store + manifest chain), line-endings diagnostics,
// and the seal-store-unavailable error path through the policy matrix.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VerificationEngine } from "./engine.js";
import { SealStore } from "./seal.js";
import { sha256 } from "./hash.js";
import { evaluatePolicy } from "./policy.js";
import { serializeManifest, serializeSignature } from "./manifest.js";
import type { Manifest, DetachedSignature } from "./manifest.js";
import type { TrustStoreData } from "./trust-store.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

function toBase64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Writes manifest.json + manifest.sig.json + truststore.json for a package dir. */
async function writeSignedPackage(
  pkgDir: string,
  fileName: string,
  fileContent: string,
): Promise<string> {
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const keyId = "seal-int-key";
  const fingerprint = sha256(Buffer.from(pubKey));

  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "seal-int-pkg",
    version: "1.0.0",
    publisher: { name: "SealIntPublisher", key_id: keyId, public_key_fingerprint: fingerprint },
    published_at: "2026-01-01T00:00:00Z",
    files: [
      {
        path: fileName,
        sha256: sha256(Buffer.from(fileContent, "utf-8")),
        size: Buffer.byteLength(fileContent, "utf-8"),
      },
    ],
  };
  const manifestJson = serializeManifest(manifest);
  const manifestBuf = Buffer.from(manifestJson, "utf-8");
  const sigBytes = await ed.signAsync(manifestBuf, privKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: sha256(manifestBuf),
    algorithm: "Ed25519",
    key_id: keyId,
    signature: toBase64url(sigBytes),
  };
  await writeFile(join(pkgDir, "manifest.json"), manifestJson, "utf-8");
  await writeFile(join(pkgDir, "manifest.sig.json"), serializeSignature(sig), "utf-8");

  const trustStoreData: TrustStoreData = {
    schema: "tcv-truststore/v1",
    trusted_publishers: [
      {
        publisher: "SealIntPublisher",
        key_id: keyId,
        public_key: Buffer.from(pubKey).toString("base64"),
        fingerprint,
        revoked: false,
        policy: {
          default_action: "block",
          allow_expired_manifest: false,
          allow_offline_cached_manifest: false,
        },
      },
    ],
  };
  const trustStorePath = join(pkgDir, "truststore.json");
  await writeFile(trustStorePath, JSON.stringify(trustStoreData, null, 2), "utf-8");
  return trustStorePath;
}

let homeDir: string;
let pkgDir: string;
let savedHome: string | undefined;

beforeEach(async () => {
  savedHome = process.env.CONTEXTLOCK_HOME;
  homeDir = await mkdtemp(join(tmpdir(), "cl-engine-home-"));
  pkgDir = await mkdtemp(join(tmpdir(), "cl-engine-pkg-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
});

afterEach(async () => {
  process.env.CONTEXTLOCK_HOME = savedHome;
  await rm(homeDir, { recursive: true, force: true }).catch(() => {});
  await rm(pkgDir, { recursive: true, force: true }).catch(() => {});
});

function makeEngine(trustStorePath: string): VerificationEngine {
  return new VerificationEngine({
    trustStorePath,
    cachePath: "",
    protectedPatterns: ["**/SKILL.md", "**/CLAUDE.md"],
    policyLevel: "strict",
  });
}

describe("Engine seal integration (SPEC v2 combination rules)", () => {
  it("seal ok + no manifest = sealed", async () => {
    const filePath = join(pkgDir, "CLAUDE.md");
    await writeFile(filePath, "# sealed only\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    const engine = makeEngine(join(pkgDir, "missing-truststore.json"));
    const result = await engine.verify(filePath);
    expect(result.status).toBe("sealed");
    expect(result.sealedAt).toBeDefined();
  });

  it("seal ok + manifest trusted = sealed+trusted", async () => {
    const content = "# sealed and signed\n";
    const filePath = join(pkgDir, "SKILL.md");
    await writeFile(filePath, content, "utf-8");
    const trustStorePath = await writeSignedPackage(pkgDir, "SKILL.md", content);

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    const engine = makeEngine(trustStorePath);
    const result = await engine.verify(filePath);
    expect(result.status).toBe("sealed+trusted");
    expect(result.publisher).toBe("SealIntPublisher");
    expect(result.sealedAt).toBeDefined();
  });

  it("seal mismatch = modified even when a manifest matches the new content (seal wins)", async () => {
    const original = "# the user reviewed this\n";
    const attacker = "# attacker swapped this in\n";
    const filePath = join(pkgDir, "SKILL.md");

    await writeFile(filePath, original, "utf-8");
    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    // Attacker replaces the content AND ships a valid manifest for it.
    await writeFile(filePath, attacker, "utf-8");
    const trustStorePath = await writeSignedPackage(pkgDir, "SKILL.md", attacker);

    const engine = makeEngine(trustStorePath);
    const result = await engine.verify(filePath);
    expect(result.status).toBe("modified");
    expect(result.expectedHash).toBe(sha256(Buffer.from(original, "utf-8")));
    expect(result.fileHash).toBe(sha256(Buffer.from(attacker, "utf-8")));
  });

  it("no seal + manifest trusted = trusted (existing behavior)", async () => {
    const content = "# signed only\n";
    const filePath = join(pkgDir, "SKILL.md");
    await writeFile(filePath, content, "utf-8");
    const trustStorePath = await writeSignedPackage(pkgDir, "SKILL.md", content);

    const engine = makeEngine(trustStorePath);
    const result = await engine.verify(filePath);
    expect(result.status).toBe("trusted");
  });

  it("CRLF-restored sealed file is modified with the line-endings-only hint", async () => {
    const filePath = join(pkgDir, "CLAUDE.md");
    await writeFile(filePath, "line a\r\nline b\r\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath); // normalizes to LF, then hashes

    // Convert back to CRLF (e.g. a git checkout with autocrlf).
    const lf = await readFile(filePath, "utf-8");
    await writeFile(filePath, lf.replace(/\n/g, "\r\n"), "utf-8");

    const engine = makeEngine(join(pkgDir, "missing-truststore.json"));
    const result = await engine.verify(filePath);
    expect(result.status).toBe("modified");
    expect(result.reason).toContain("line endings only");
    expect(result.reason).toContain("re-seal or restore LF endings");
  });

  it("tampered seal store = seal-store-unavailable, blocked under strict and balanced", async () => {
    const filePath = join(pkgDir, "CLAUDE.md");
    await writeFile(filePath, "# content\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    // Corrupt the store signature.
    const raw = JSON.parse(await readFile(store.path, "utf-8"));
    raw.entries[0].sha256 = "f".repeat(64);
    await writeFile(store.path, JSON.stringify(raw), "utf-8");

    const engine = makeEngine(join(pkgDir, "missing-truststore.json"));
    const result = await engine.verify(filePath);
    expect(result.status).toBe("seal-store-unavailable");
    expect(result.reason).toContain("possible tampering");

    expect(
      evaluatePolicy({ level: "strict", verificationResult: { status: result.status } }),
    ).toBe("block");
    expect(
      evaluatePolicy({ level: "balanced", verificationResult: { status: result.status } }),
    ).toBe("block");
  });

  it("policy: sealed and sealed+trusted behave as trusted (allow) at every level", () => {
    for (const level of ["strict", "balanced", "audit"] as const) {
      for (const status of ["sealed", "sealed+trusted"] as const) {
        expect(evaluatePolicy({ level, verificationResult: { status } })).toBe("allow");
      }
    }
  });
});
