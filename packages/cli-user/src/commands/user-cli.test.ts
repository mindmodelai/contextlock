/**
 * Unit tests for User CLI commands.
 * Requirements: 5.2, 5.3, 5.6, 9.1, 14.3, 14.4
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm, mkdir } from "node:fs/promises";
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
import type { Manifest, DetachedSignature, TrustedPublisher } from "@contextlock/core";
import { trustAdd } from "./trust-add.js";
import { trustRemove } from "./trust-remove.js";
import { trustList } from "./trust-list.js";
import { trustRevoke } from "./trust-revoke.js";
import { userVerify } from "./verify.js";
import { keyFingerprint } from "./key-fingerprint.js";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

/** Helper: generate an Ed25519 keypair and save to files. */
async function generateKeypair(dir: string) {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  const privB64 = Buffer.from(privateKey).toString("base64");
  const pubB64 = Buffer.from(publicKey).toString("base64");
  const privPath = join(dir, "tcv-private.key");
  const pubPath = join(dir, "tcv-public.key");
  await writeFile(privPath, privB64, "utf-8");
  await writeFile(pubPath, pubB64, "utf-8");
  const fingerprint = computeFingerprint(Buffer.from(publicKey));
  return { privateKey, publicKey, privPath, pubPath, fingerprint, pubB64 };
}

function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Helper: create a signed package directory with a SKILL.md file. */
async function createSignedPackage(dir: string, content: string) {
  const kp = await generateKeypair(dir);

  // Write protected file
  await writeFile(join(dir, "SKILL.md"), content, "utf-8");

  // Build manifest
  const fileHash = sha256(Buffer.from(content));
  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "test-pkg",
    version: "1.0.0",
    publisher: {
      name: "TestPublisher",
      key_id: kp.fingerprint,
      public_key_fingerprint: kp.fingerprint,
    },
    published_at: new Date().toISOString(),
    files: [{ path: "SKILL.md", sha256: fileHash, size: Buffer.byteLength(content) }],
  };

  const manifestJson = serializeManifest(manifest);
  const manifestPath = join(dir, "manifest.json");
  await writeFile(manifestPath, manifestJson, "utf-8");

  // Sign manifest
  const manifestBuf = Buffer.from(manifestJson);
  const manifestHash = sha256(manifestBuf);
  const sigBytes = await ed.signAsync(manifestBuf, kp.privateKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: manifestHash,
    algorithm: "Ed25519",
    key_id: kp.fingerprint,
    signature: base64urlEncode(sigBytes),
  };
  await writeFile(join(dir, "manifest.sig.json"), serializeSignature(sig), "utf-8");

  // Create trust store with this publisher
  const storePath = join(dir, "truststore.json");
  const store = new TrustStore();
  store.addPublisher({
    publisher: "TestPublisher",
    key_id: kp.fingerprint,
    public_key: kp.pubB64,
    fingerprint: kp.fingerprint,
    revoked: false,
    policy: {
      default_action: "warn",
      allow_expired_manifest: false,
      allow_offline_cached_manifest: false,
    },
  });
  await store.save(storePath);

  return { ...kp, storePath, manifest };
}

describe("User CLI Commands", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tcv-user-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("trust add", () => {
    it("adds a publisher to the trust store", async () => {
      const kp = await generateKeypair(tempDir);
      const storePath = join(tempDir, "truststore.json");

      const result = await trustAdd({
        publicKeyPath: kp.pubPath,
        publisherName: "Alice",
        trustStorePath: storePath,
      });

      expect(result.fingerprint).toBe(kp.fingerprint);
      expect(result.publisherName).toBe("Alice");

      // Verify it was persisted
      const store = new TrustStore();
      await store.load(storePath);
      const entry = store.getPublisher(kp.fingerprint);
      expect(entry).toBeDefined();
      expect(entry!.publisher).toBe("Alice");
      expect(entry!.revoked).toBe(false);
    });
  });

  describe("trust remove", () => {
    it("removes a publisher from the trust store", async () => {
      const kp = await generateKeypair(tempDir);
      const storePath = join(tempDir, "truststore.json");

      // Add first
      await trustAdd({
        publicKeyPath: kp.pubPath,
        publisherName: "Bob",
        trustStorePath: storePath,
      });

      // Remove
      const result = await trustRemove({ keyId: kp.fingerprint, trustStorePath: storePath });
      expect(result.removed).toBe(true);

      // Verify removal
      const store = new TrustStore();
      await store.load(storePath);
      expect(store.getPublisher(kp.fingerprint)).toBeUndefined();
    });

    it("returns false for unknown key ID", async () => {
      const storePath = join(tempDir, "truststore.json");
      const store = new TrustStore();
      await store.save(storePath);

      const result = await trustRemove({ keyId: "nonexistent", trustStorePath: storePath });
      expect(result.removed).toBe(false);
    });
  });

  describe("trust list", () => {
    it("lists all trusted publishers", async () => {
      const kp = await generateKeypair(tempDir);
      const storePath = join(tempDir, "truststore.json");

      await trustAdd({
        publicKeyPath: kp.pubPath,
        publisherName: "Charlie",
        trustStorePath: storePath,
      });

      const result = await trustList({ trustStorePath: storePath });
      expect(result.publishers.length).toBe(1);
      expect(result.publishers[0].publisher).toBe("Charlie");
      expect(result.publishers[0].fingerprint).toBe(kp.fingerprint);
    });

    it("returns empty list when no trust store exists", async () => {
      const result = await trustList({ trustStorePath: join(tempDir, "nonexistent.json") });
      expect(result.publishers).toEqual([]);
    });
  });

  describe("trust revoke", () => {
    it("marks a key as revoked", async () => {
      const kp = await generateKeypair(tempDir);
      const storePath = join(tempDir, "truststore.json");

      await trustAdd({
        publicKeyPath: kp.pubPath,
        publisherName: "Dave",
        trustStorePath: storePath,
      });

      const result = await trustRevoke({ keyId: kp.fingerprint, trustStorePath: storePath });
      expect(result.revoked).toBe(true);

      // Verify revocation persisted
      const store = new TrustStore();
      await store.load(storePath);
      const entry = store.getPublisher(kp.fingerprint);
      expect(entry!.revoked).toBe(true);
    });

    it("returns false for unknown key ID", async () => {
      const storePath = join(tempDir, "truststore.json");
      const store = new TrustStore();
      await store.save(storePath);

      const result = await trustRevoke({ keyId: "nonexistent", trustStorePath: storePath });
      expect(result.revoked).toBe(false);
    });
  });

  describe("verify", () => {
    it("returns trusted for a valid signed file", async () => {
      const pkg = await createSignedPackage(tempDir, "# My Skill\nDo things.");
      const result = await userVerify({
        filePath: join(tempDir, "SKILL.md"),
        trustStorePath: pkg.storePath,
      });

      expect(result.result.status).toBe("trusted");
      expect(result.result.publisher).toBe("TestPublisher");
      expect(result.displayMessage).toContain("trusted");
      expect(result.displayMessage).toContain("TestPublisher");
      expect(result.displayMessage).toContain(pkg.fingerprint);
    });

    it("returns modified for a tampered file", async () => {
      const pkg = await createSignedPackage(tempDir, "original content");

      // Tamper with the file
      await writeFile(join(tempDir, "SKILL.md"), "TAMPERED content", "utf-8");

      const result = await userVerify({
        filePath: join(tempDir, "SKILL.md"),
        trustStorePath: pkg.storePath,
      });

      expect(result.result.status).toBe("modified");
      expect(result.displayMessage).toContain("modified");
      expect(result.displayMessage).toContain("expected:");
      expect(result.displayMessage).toContain("computed:");
    });

    it("returns untrusted when no manifest exists", async () => {
      // Create a file with no manifest
      await writeFile(join(tempDir, "SKILL.md"), "orphan file", "utf-8");
      const storePath = join(tempDir, "truststore.json");
      const store = new TrustStore();
      await store.save(storePath);

      const result = await userVerify({
        filePath: join(tempDir, "SKILL.md"),
        trustStorePath: storePath,
      });

      expect(result.result.status).toBe("untrusted");
      expect(result.displayMessage).toContain("untrusted");
    });

    it("includes filename-hash info for hash-embedded filenames", async () => {
      // Create a hash-embedded file manually
      const { canonicalize: canon, sha256: hash256 } = await import("@contextlock/core");
      const content = "# Hash-protected skill";
      const fileHash = hash256(canon(Buffer.from(content)));
      const embedded = fileHash.substring(0, 16);
      const hashedName = `SKILL.${embedded}.md`;
      await writeFile(join(tempDir, hashedName), content, "utf-8");

      const storePath = join(tempDir, "truststore.json");
      const store = new TrustStore();
      await store.save(storePath);

      const result = await userVerify({
        filePath: join(tempDir, hashedName),
        trustStorePath: storePath,
      });

      // No manifest → untrusted, but filename hash should match
      expect(result.result.status).toBe("untrusted");
      expect(result.filenameHash).toBeDefined();
      expect(result.filenameHash!.hasEmbeddedHash).toBe(true);
      expect(result.filenameHash!.matches).toBe(true);
      expect(result.displayMessage).toContain("filename hash matches");
    });

    it("reports filename-hash mismatch for tampered hash-embedded files", async () => {
      // Create a file with a hash that doesn't match its content
      await writeFile(join(tempDir, "SKILL.deadbeef12345678.md"), "tampered content", "utf-8");

      const storePath = join(tempDir, "truststore.json");
      const store = new TrustStore();
      await store.save(storePath);

      const result = await userVerify({
        filePath: join(tempDir, "SKILL.deadbeef12345678.md"),
        trustStorePath: storePath,
      });

      expect(result.filenameHash).toBeDefined();
      expect(result.filenameHash!.hasEmbeddedHash).toBe(true);
      expect(result.filenameHash!.matches).toBe(false);
      expect(result.displayMessage).toContain("filename hash MISMATCH");
    });
  });

  describe("key-fingerprint", () => {
    it("computes correct fingerprint", async () => {
      const kp = await generateKeypair(tempDir);
      const result = await keyFingerprint({ publicKeyPath: kp.pubPath });
      expect(result.fingerprint).toBe(kp.fingerprint);
      expect(result.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});
