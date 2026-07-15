/**
 * Unit tests for User CLI commands (v2 format fixtures).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { TrustStore, base64urlEncode as b64uEncode } from "@contextlock/core";
import { trustAdd } from "./trust-add.js";
import { trustRemove } from "./trust-remove.js";
import { trustList } from "./trust-list.js";
import { trustRevoke } from "./trust-revoke.js";
import { userVerify } from "./verify.js";
import { keyFingerprint } from "./key-fingerprint.js";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "../../../core/src/testkit.js";

/** Helper: generate an Ed25519 keypair and save to files (base64url raw). */
async function generateKeypair(dir: string) {
  const kp = await makeKeypair();
  const privPath = join(dir, "contextlock-private.key");
  const pubPath = join(dir, "contextlock-public.key");
  await writeFile(privPath, b64uEncode(kp.privateKey) + "\n", "utf-8");
  await writeFile(pubPath, b64uEncode(kp.publicKey) + "\n", "utf-8");
  return { ...kp, privPath, pubPath };
}

/** Helper: create a signed v2 package directory with a SKILL.md file. */
async function createSignedPackage(dir: string, content: string) {
  const kp = await makeKeypair();
  const { manifest } = await writeSignedPackage(dir, kp, {
    packageName: uniquePackageName("user-cli"),
    publisherName: "TestPublisher",
    files: { "SKILL.md": content },
  });
  const storePath = join(dir, "truststore.json");
  await writeTrustStore(storePath, [kp], {
    publisherName: "TestPublisher",
    policy: { default_action: "warn" },
  });
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
      expect(result.displayMessage).toContain(pkg.keyId);
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
