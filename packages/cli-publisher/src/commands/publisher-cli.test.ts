/**
 * Unit tests for Publisher CLI commands.
 * Requirements: 10.1, 11.1, 12.1, 19.1
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import { computeFingerprint, computeFileHash } from "@contextlock/core";
import { initKey } from "./init-key.js";
import { buildManifest } from "./build-manifest.js";
import { signManifest } from "./sign-manifest.js";
import { verify } from "./verify.js";
import { keyFingerprint } from "./key-fingerprint.js";
import { hashFilename } from "./hash-filename.js";
import { protect } from "./protect.js";

// Configure @noble/ed25519 v2 sha512 sync
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) =>
    sha512(ed.etc.concatBytes(...m));
}

describe("Publisher CLI Commands", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "tcv-cli-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("init-key", () => {
    it("generates a valid Ed25519 keypair", async () => {
      const result = await initKey({ output: tempDir });

      // Files exist and are base64-encoded
      const privB64 = await readFile(result.privateKeyPath, "utf-8");
      const pubB64 = await readFile(result.publicKeyPath, "utf-8");

      const privKey = Buffer.from(privB64.trim(), "base64");
      const pubKey = Buffer.from(pubB64.trim(), "base64");

      expect(privKey.length).toBe(32);
      expect(pubKey.length).toBe(32);

      // Verify keypair: sign and verify a message
      const msg = Buffer.from("test message");
      const sig = await ed.signAsync(msg, privKey);
      const valid = await ed.verifyAsync(sig, msg, pubKey);
      expect(valid).toBe(true);

      // Fingerprint matches
      const expectedFp = computeFingerprint(pubKey);
      expect(result.fingerprint).toBe(expectedFp);
    });

    it("saves keys to specified output directory", async () => {
      const keyDir = join(tempDir, "keys");
      await mkdir(keyDir, { recursive: true });
      const result = await initKey({ output: keyDir });
      expect(result.privateKeyPath).toContain("keys");
      expect(result.publicKeyPath).toContain("keys");
    });
  });

  describe("build-manifest", () => {
    it("builds manifest with known fixture files", async () => {
      // Create protected files
      await writeFile(join(tempDir, "SKILL.md"), "# My Skill\nDo things.", "utf-8");
      await writeFile(join(tempDir, "RULES.md"), "# Rules\nFollow them.", "utf-8");
      // Create non-protected file
      await writeFile(join(tempDir, "README.md"), "# Readme", "utf-8");

      const result = await buildManifest({
        directory: tempDir,
        packageName: "test-pkg",
        version: "1.0.0",
        publisherName: "Alice",
        keyId: "key-abc",
        fingerprint: "fp-abc",
      });

      expect(result.fileCount).toBe(2);
      expect(result.filePaths.sort()).toEqual(["RULES.md", "SKILL.md"]);
      expect(result.manifest.schema).toBe("tcv-manifest/v1");
      expect(result.manifest.package).toBe("test-pkg");
      expect(result.manifest.publisher.name).toBe("Alice");

      // Verify hashes
      for (const entry of result.manifest.files) {
        const expected = await computeFileHash(join(tempDir, entry.path));
        expect(entry.sha256).toBe(expected);
      }
    });

    it("warns when no protected files found", async () => {
      await writeFile(join(tempDir, "README.md"), "nothing protected", "utf-8");

      const result = await buildManifest({
        directory: tempDir,
        packageName: "empty-pkg",
        version: "1.0.0",
        publisherName: "Bob",
        keyId: "key-1",
        fingerprint: "fp-1",
      });

      expect(result.fileCount).toBe(0);
      expect(result.warning).toBeDefined();
    });
  });

  describe("sign-manifest", () => {
    it("produces a valid Ed25519 signature", async () => {
      // Generate keypair
      const keyResult = await initKey({ output: tempDir });

      // Create a protected file and build manifest
      await writeFile(join(tempDir, "SKILL.md"), "# Skill content", "utf-8");
      const buildResult = await buildManifest({
        directory: tempDir,
        packageName: "sig-test",
        version: "1.0.0",
        publisherName: "Signer",
        keyId: keyResult.fingerprint,
        fingerprint: keyResult.fingerprint,
      });

      // Sign the manifest
      const sigResult = await signManifest({
        manifestPath: buildResult.manifestPath,
        privateKeyPath: keyResult.privateKeyPath,
      });

      expect(sigResult.signature.schema).toBe("tcv-signature/v1");
      expect(sigResult.signature.algorithm).toBe("Ed25519");
      expect(sigResult.keyId).toBe(keyResult.fingerprint);

      // Verify the signature cryptographically
      const manifestContent = await readFile(buildResult.manifestPath);
      const pubKey = Buffer.from(
        (await readFile(keyResult.publicKeyPath, "utf-8")).trim(),
        "base64",
      );

      // Decode base64url signature
      let sigB64 = sigResult.signature.signature
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      const pad = sigB64.length % 4;
      if (pad === 2) sigB64 += "==";
      else if (pad === 3) sigB64 += "=";
      const sigBytes = Uint8Array.from(Buffer.from(sigB64, "base64"));

      const valid = await ed.verifyAsync(sigBytes, manifestContent, pubKey);
      expect(valid).toBe(true);
    });
  });

  describe("verify", () => {
    it("detects modified files", async () => {
      // Setup: generate key, create file, build manifest, sign
      const keyResult = await initKey({ output: tempDir });
      await writeFile(join(tempDir, "SKILL.md"), "original content", "utf-8");

      await buildManifest({
        directory: tempDir,
        packageName: "verify-test",
        version: "1.0.0",
        publisherName: "Verifier",
        keyId: keyResult.fingerprint,
        fingerprint: keyResult.fingerprint,
      });

      await signManifest({
        manifestPath: join(tempDir, "manifest.json"),
        privateKeyPath: keyResult.privateKeyPath,
      });

      // Verify passes initially
      const okResult = await verify({ directory: tempDir });
      expect(okResult.success).toBe(true);
      expect(okResult.fileResults[0].status).toBe("ok");

      // Modify the file
      await writeFile(join(tempDir, "SKILL.md"), "TAMPERED content", "utf-8");

      // Verify detects modification
      const failResult = await verify({ directory: tempDir });
      expect(failResult.success).toBe(false);
      const modified = failResult.fileResults.find((f) => f.status === "modified");
      expect(modified).toBeDefined();
      expect(modified!.expectedHash).toBeDefined();
      expect(modified!.computedHash).toBeDefined();
      expect(modified!.expectedHash).not.toBe(modified!.computedHash);
    });

    it("reports missing manifest", async () => {
      const result = await verify({ directory: tempDir });
      expect(result.success).toBe(false);
      expect(result.manifestFound).toBe(false);
    });
  });

  describe("key-fingerprint", () => {
    it("computes correct fingerprint from public key file", async () => {
      const keyResult = await initKey({ output: tempDir });
      const fpResult = await keyFingerprint({ publicKeyPath: keyResult.publicKeyPath });

      expect(fpResult.fingerprint).toBe(keyResult.fingerprint);
      // Verify it's lowercase hex
      expect(fpResult.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe("hash-filename", () => {
    it("produces a file with embedded hash in the name", async () => {
      const content = "# My Skill\nDo things safely.";
      await writeFile(join(tempDir, "SKILL.md"), content, "utf-8");

      const result = await hashFilename({ filePath: join(tempDir, "SKILL.md") });

      // Filename matches pattern: SKILL.<16-hex-chars>.md
      expect(result.hashedPath).toMatch(/SKILL\.[0-9a-f]{16}\.md$/);
      expect(result.embeddedHash).toHaveLength(16);
      expect(result.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.hash.startsWith(result.embeddedHash)).toBe(true);

      // The hashed file exists and has the same content
      const copied = await readFile(result.hashedPath, "utf-8");
      expect(copied).toBe(content);
    });

    it("respects custom hash length", async () => {
      await writeFile(join(tempDir, "RULES.md"), "# Rules", "utf-8");

      const result = await hashFilename({
        filePath: join(tempDir, "RULES.md"),
        hashLength: 8,
      });

      expect(result.embeddedHash).toHaveLength(8);
      expect(result.hashedPath).toMatch(/RULES\.[0-9a-f]{8}\.md$/);
    });

    it("verifies round-trip with core verifyFilenameHash", async () => {
      const { verifyFilenameHash } = await import("@contextlock/core");
      await writeFile(join(tempDir, "SKILL.md"), "# Skill content here", "utf-8");

      const result = await hashFilename({ filePath: join(tempDir, "SKILL.md") });
      const verification = await verifyFilenameHash(result.hashedPath);

      expect(verification.hasEmbeddedHash).toBe(true);
      expect(verification.matches).toBe(true);
    });
  });

  describe("protect", () => {
    it("protect --mode hash produces hash-embedded filenames for all protected files", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "# Skill", "utf-8");
      await writeFile(join(tempDir, "RULES.md"), "# Rules", "utf-8");
      await writeFile(join(tempDir, "README.md"), "# Readme", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "hash",
      });

      expect(result.mode).toBe("hash");
      expect(result.filesProtected).toBe(2);
      expect(result.hashResults).toHaveLength(2);
      for (const hr of result.hashResults!) {
        expect(hr.hashedPath).toMatch(/\.[0-9a-f]{16}\./);
      }
    });

    it("protect --mode sign generates keypair, manifest, and signature in one step", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "# Protected skill", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "protect-test",
        version: "1.0.0",
        publisherName: "Protector",
      });

      expect(result.mode).toBe("sign");
      expect(result.filesProtected).toBe(1);
      expect(result.keyGenerated).toBe(true);
      expect(result.keyResult).toBeDefined();
      expect(result.buildResult).toBeDefined();
      expect(result.signResult).toBeDefined();
      expect(result.signResult!.keyId).toBe(result.keyResult!.fingerprint);

      // Verify the package is valid
      const verifyResult = await verify({ directory: tempDir });
      expect(verifyResult.success).toBe(true);
    });

    it("protect --mode sign reuses existing keypair", async () => {
      // Generate a keypair first
      const keyResult = await initKey({ output: tempDir });
      await writeFile(join(tempDir, "SKILL.md"), "# Skill", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "reuse-key-test",
        version: "1.0.0",
        publisherName: "Reuser",
        privateKeyPath: keyResult.privateKeyPath,
      });

      expect(result.keyGenerated).toBeFalsy();
      expect(result.signResult!.keyId).toBe(keyResult.fingerprint);
    });

    it("protect returns zero files when no protected files found", async () => {
      await writeFile(join(tempDir, "README.md"), "nothing protected", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "sign",
      });

      expect(result.filesProtected).toBe(0);
    });
  });
});
