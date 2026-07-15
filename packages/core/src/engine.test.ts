// Verification Engine — unit tests
// Requirements: 4.1, 4.2, 4.3, 4.4, 8.1, 8.2, 8.3, 9.2, 9.3

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VerificationEngine } from "./engine.js";
import { sha256 } from "./hash.js";
import { canonicalize } from "./canonicalize.js";
import { serializeManifest, serializeSignature } from "./manifest.js";
import type { Manifest, DetachedSignature } from "./manifest.js";
import type { TrustStoreData } from "./trust-store.js";

// Configure @noble/ed25519 v2 sha512 sync
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

// ---- Helpers ----

function toBase64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

interface TestFixture {
  tmpDir: string;
  filePath: string;
  trustStorePath: string;
  keyId: string;
  pubKeyBase64: string;
  fingerprint: string;
  privKey: Uint8Array;
  pubKey: Uint8Array;
}

let fixture: TestFixture;

/**
 * Build a signed manifest + signature for the given file content and write them to tmpDir.
 */
async function writeSignedManifest(opts: {
  tmpDir: string;
  fileName: string;
  fileContent: string;
  privKey: Uint8Array;
  keyId: string;
  fingerprint: string;
  expiresAt?: string;
  revocationStatus?: string;
}): Promise<void> {
  const canonical = canonicalize(Buffer.from(opts.fileContent, "utf-8"));
  const fileHash = sha256(canonical);

  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "test-pkg",
    version: "1.0.0",
    publisher: {
      name: "Unit Test Publisher",
      key_id: opts.keyId,
      public_key_fingerprint: opts.fingerprint,
    },
    published_at: "2025-01-01T00:00:00Z",
    files: [
      {
        path: opts.fileName,
        sha256: fileHash,
        size: Buffer.byteLength(opts.fileContent, "utf-8"),
      },
    ],
  };
  if (opts.expiresAt) {
    manifest.expires_at = opts.expiresAt;
  }
  if (opts.revocationStatus) {
    manifest.revocation = { status: opts.revocationStatus };
  }

  const manifestJson = serializeManifest(manifest);
  const manifestBuf = Buffer.from(manifestJson, "utf-8");
  const manifestHash = sha256(manifestBuf);

  const sigBytes = await ed.signAsync(manifestBuf, opts.privKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: manifestHash,
    algorithm: "Ed25519",
    key_id: opts.keyId,
    signature: toBase64url(sigBytes),
  };

  await writeFile(join(opts.tmpDir, "manifest.json"), manifestJson, "utf-8");
  await writeFile(join(opts.tmpDir, "manifest.sig.json"), serializeSignature(sig), "utf-8");
}


describe("VerificationEngine", () => {
  // ---- Setup: create a shared keypair and trust store ----

  beforeAll(async () => {
    const tmpDir = await mkdtemp(join(tmpdir(), "engine-unit-"));
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const keyId = "unit-test-key";
    const pubKeyBase64 = Buffer.from(pubKey).toString("base64");
    const fingerprint = sha256(Buffer.from(pubKey));

    // Write trust store with the key (not revoked, expired not allowed)
    const trustStoreData: TrustStoreData = {
      schema: "tcv-truststore/v1",
      trusted_publishers: [
        {
          publisher: "Unit Test Publisher",
          key_id: keyId,
          public_key: pubKeyBase64,
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
    const trustStorePath = join(tmpDir, "truststore.json");
    await writeFile(trustStorePath, JSON.stringify(trustStoreData, null, 2), "utf-8");

    fixture = { tmpDir, filePath: "", trustStorePath, keyId, pubKeyBase64, fingerprint, privKey, pubKey };
  });

  afterAll(async () => {
    if (fixture?.tmpDir) {
      await rm(fixture.tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  });

  // ---- Helper to create a per-test package dir inside the shared tmpDir ----

  async function createTestPackage(name: string): Promise<string> {
    const pkgDir = join(fixture.tmpDir, name);
    await writeFile(join(pkgDir, ".keep"), "", "utf-8").catch(async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(pkgDir, { recursive: true });
    });
    // Ensure directory exists
    const { mkdir } = await import("node:fs/promises");
    await mkdir(pkgDir, { recursive: true });
    return pkgDir;
  }

  function makeEngine(trustStorePath?: string): VerificationEngine {
    return new VerificationEngine({
      trustStorePath: trustStorePath ?? fixture.trustStorePath,
      cachePath: join(fixture.tmpDir, "cache"),
      protectedPatterns: ["**/SKILL.md"],
      policyLevel: "strict",
    });
  }

  // ---- Test: trusted file ----

  it("returns 'trusted' for an unmodified signed file", async () => {
    const pkgDir = await createTestPackage("trusted-pkg");
    const content = "# Trusted SKILL\nThis is a trusted file.";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
    });

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("Unit Test Publisher");
    expect(result.keyId).toBe(fixture.keyId);
  });

  // ---- Test: modified file ----

  it("returns 'modified' when file content has been changed", async () => {
    const pkgDir = await createTestPackage("modified-pkg");
    const originalContent = "# Original content";
    await writeFile(join(pkgDir, "SKILL.md"), originalContent, "utf-8");
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: originalContent,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
    });

    // Tamper with the file
    await writeFile(join(pkgDir, "SKILL.md"), "# Tampered content", "utf-8");

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("modified");
    expect(result.fileHash).toBeDefined();
    expect(result.expectedHash).toBeDefined();
    expect(result.fileHash).not.toBe(result.expectedHash);
  });

  // ---- Test: untrusted (unknown signer) ----

  it("returns 'untrusted' when the signing key is not in the trust store", async () => {
    const pkgDir = await createTestPackage("untrusted-pkg");
    const content = "# Untrusted content";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");

    // Sign with a different key not in the trust store
    const otherPriv = ed.utils.randomPrivateKey();
    const otherPub = await ed.getPublicKeyAsync(otherPriv);
    const otherFingerprint = sha256(Buffer.from(otherPub));

    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: otherPriv,
      keyId: "unknown-key",
      fingerprint: otherFingerprint,
    });

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("unknown");
  });

  // ---- Test: no manifest ----

  it("returns 'untrusted' when no manifest is found", async () => {
    const pkgDir = await createTestPackage("no-manifest-pkg");
    await writeFile(join(pkgDir, "SKILL.md"), "# No manifest here", "utf-8");

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("no manifest");
  });

  // ---- Test: revoked key ----

  it("returns 'revoked' when the signing key is revoked in the trust store", async () => {
    const pkgDir = await createTestPackage("revoked-pkg");
    const content = "# Revoked key content";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
    });

    // Create a trust store with the key marked as revoked
    const revokedTrustStore: TrustStoreData = {
      schema: "tcv-truststore/v1",
      trusted_publishers: [
        {
          publisher: "Unit Test Publisher",
          key_id: fixture.keyId,
          public_key: fixture.pubKeyBase64,
          fingerprint: fixture.fingerprint,
          revoked: true,
          policy: {
            default_action: "block",
            allow_expired_manifest: false,
            allow_offline_cached_manifest: false,
          },
        },
      ],
    };
    const revokedTsPath = join(pkgDir, "revoked-truststore.json");
    await writeFile(revokedTsPath, JSON.stringify(revokedTrustStore, null, 2), "utf-8");

    const engine = makeEngine(revokedTsPath);
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("revoked");
    expect(result.keyId).toBe(fixture.keyId);
  });

  // ---- Test: expired manifest (disallowed) ----

  it("returns 'expired' when manifest is expired and allow_expired_manifest is false", async () => {
    const pkgDir = await createTestPackage("expired-pkg");
    const content = "# Expired manifest content";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");

    const pastDate = new Date(Date.now() - 7 * 86400000).toISOString();
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
      expiresAt: pastDate,
    });

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("expired");
    expect(result.expiresAt).toBe(pastDate);
  });

  // ---- Test: expired manifest (allowed) ----

  it("returns 'trusted' with warning when manifest is expired but allow_expired_manifest is true", async () => {
    const pkgDir = await createTestPackage("expired-allowed-pkg");
    const content = "# Expired but allowed";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");

    const pastDate = new Date(Date.now() - 7 * 86400000).toISOString();
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
      expiresAt: pastDate,
    });

    // Create trust store that allows expired manifests
    const allowExpiredTs: TrustStoreData = {
      schema: "tcv-truststore/v1",
      trusted_publishers: [
        {
          publisher: "Unit Test Publisher",
          key_id: fixture.keyId,
          public_key: fixture.pubKeyBase64,
          fingerprint: fixture.fingerprint,
          revoked: false,
          policy: {
            default_action: "block",
            allow_expired_manifest: true,
            allow_offline_cached_manifest: false,
          },
        },
      ],
    };
    const allowExpiredTsPath = join(pkgDir, "allow-expired-truststore.json");
    await writeFile(allowExpiredTsPath, JSON.stringify(allowExpiredTs, null, 2), "utf-8");

    const engine = makeEngine(allowExpiredTsPath);
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("trusted");
    expect(result.warning).toBeDefined();
    expect(result.warning!.toLowerCase()).toContain("expired");
  });

  // ---- Test: file not in manifest ----

  it("returns 'untrusted' when file is not listed in the manifest", async () => {
    const pkgDir = await createTestPackage("not-in-manifest-pkg");
    const content = "# Listed file";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");
    // Sign manifest for a different file name
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "OTHER.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
    });

    const engine = makeEngine();
    const result = await engine.verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("not listed");
  });

  // ---- Test: isProtected ----

  it("isProtected returns true for matching patterns", () => {
    const engine = makeEngine();
    expect(engine.isProtected("some/path/SKILL.md")).toBe(true);
    expect(engine.isProtected("random.txt")).toBe(false);
  });

  // ---- Test: verifyManifest ----

  it("verifyManifest returns trusted for a valid manifest+signature pair", async () => {
    const pkgDir = await createTestPackage("verify-manifest-pkg");
    const content = "# Manifest verify test";
    await writeFile(join(pkgDir, "SKILL.md"), content, "utf-8");
    await writeSignedManifest({
      tmpDir: pkgDir,
      fileName: "SKILL.md",
      fileContent: content,
      privKey: fixture.privKey,
      keyId: fixture.keyId,
      fingerprint: fixture.fingerprint,
    });

    const engine = makeEngine();
    const result = await engine.verifyManifest(
      join(pkgDir, "manifest.json"),
      join(pkgDir, "manifest.sig.json"),
    );

    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("Unit Test Publisher");
  });
});
