/**
 * Unit tests for Claude Code and OpenClaw Tool Adapters.
 * Requirements: 17.1, 17.2, 17.3, 17.5
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  computeFingerprint,
  TrustStore,
  serializeManifest,
  serializeSignature,
  sha256,
} from "@contextlock/core";
import type { Manifest, DetachedSignature } from "@contextlock/core";
import { ClaudeCodeAdapter, formatBlockMessage } from "./index.js";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createSignedPackage(dir: string, content: string) {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const pubB64 = Buffer.from(publicKey).toString("base64");
  const fingerprint = computeFingerprint(Buffer.from(publicKey));

  await writeFile(join(dir, "SKILL.md"), content, "utf-8");

  const fileHash = sha256(Buffer.from(content));
  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "test-pkg",
    version: "1.0.0",
    publisher: { name: "TestPub", key_id: fingerprint, public_key_fingerprint: fingerprint },
    published_at: new Date().toISOString(),
    files: [{ path: "SKILL.md", sha256: fileHash, size: Buffer.byteLength(content) }],
  };

  const manifestJson = serializeManifest(manifest);
  await writeFile(join(dir, "manifest.json"), manifestJson, "utf-8");

  const manifestBuf = Buffer.from(manifestJson);
  const sigBytes = await ed.signAsync(manifestBuf, privateKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: sha256(manifestBuf),
    algorithm: "Ed25519",
    key_id: fingerprint,
    signature: base64urlEncode(sigBytes),
  };
  await writeFile(join(dir, "manifest.sig.json"), serializeSignature(sig), "utf-8");

  const storePath = join(dir, "truststore.json");
  const store = new TrustStore();
  store.addPublisher({
    publisher: "TestPub",
    key_id: fingerprint,
    public_key: pubB64,
    fingerprint,
    revoked: false,
    policy: { default_action: "warn", allow_expired_manifest: false, allow_offline_cached_manifest: false },
  });
  await store.save(storePath);

  return { fingerprint, storePath };
}

describe("ClaudeCodeAdapter", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tcv-adapter-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("allows trusted protected files", async () => {
    const pkg = await createSignedPackage(tempDir, "# Trusted skill");
    const adapter = new ClaudeCodeAdapter({
      trustStorePath: pkg.storePath,
      cachePath: "",
      policyLevel: "balanced",
    });

    const decision = await adapter.onFileLoad(join(tempDir, "SKILL.md"));
    expect(decision).toBe("allow");
  });

  it("blocks modified protected files in balanced mode", async () => {
    const pkg = await createSignedPackage(tempDir, "original");
    await writeFile(join(tempDir, "SKILL.md"), "TAMPERED", "utf-8");

    const adapter = new ClaudeCodeAdapter({
      trustStorePath: pkg.storePath,
      cachePath: "",
      policyLevel: "balanced",
    });

    const decision = await adapter.onFileLoad(join(tempDir, "SKILL.md"));
    expect(decision).toBe("block");
  });

  it("allows non-protected files without verification", async () => {
    const pkg = await createSignedPackage(tempDir, "skill content");
    await writeFile(join(tempDir, "README.md"), "readme", "utf-8");

    const adapter = new ClaudeCodeAdapter({
      trustStorePath: pkg.storePath,
      cachePath: "",
      policyLevel: "strict",
    });

    const decision = await adapter.onFileLoad(join(tempDir, "README.md"));
    expect(decision).toBe("allow");
  });

  it("returns full verification status", async () => {
    const pkg = await createSignedPackage(tempDir, "# Skill");
    const adapter = new ClaudeCodeAdapter({
      trustStorePath: pkg.storePath,
      cachePath: "",
      policyLevel: "balanced",
    });

    const result = await adapter.getVerificationStatus(join(tempDir, "SKILL.md"));
    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("TestPub");
  });

  it("generates block messages for different statuses", () => {
    expect(formatBlockMessage("f.md", { status: "modified", fileHash: "a", expectedHash: "b" }))
      .toContain("modified");
    expect(formatBlockMessage("f.md", { status: "untrusted", reason: "no manifest" }))
      .toContain("untrusted");
    expect(formatBlockMessage("f.md", { status: "revoked", keyId: "k1" }))
      .toContain("revoked");
    expect(formatBlockMessage("f.md", { status: "expired", expiresAt: "2024-01-01" }))
      .toContain("expired");
    expect(formatBlockMessage("f.md", { status: "error", reason: "parse fail" }))
      .toContain("error");
  });
});
