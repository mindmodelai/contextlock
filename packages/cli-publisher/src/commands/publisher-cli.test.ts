/**
 * Unit tests for Publisher CLI commands (v2: contextlock/2 + DSSE).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, readFile, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  computeFingerprint,
  computeFileHash,
  base64urlDecode,
  parseEnvelope,
  b64Decode,
  pae,
  parseManifest,
  ENVELOPE_FILENAME,
  MANIFEST_PAYLOAD_TYPE,
} from "@contextlock/core";
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
    it("generates a valid Ed25519 keypair (raw 32 bytes, base64url)", async () => {
      const result = await initKey({ output: tempDir });

      const privKey = Buffer.from(base64urlDecode((await readFile(result.privateKeyPath, "utf-8")).trim()));
      const pubKey = Buffer.from(base64urlDecode((await readFile(result.publicKeyPath, "utf-8")).trim()));

      expect(privKey.length).toBe(32);
      expect(pubKey.length).toBe(32);

      // Verify keypair: sign and verify a message
      const msg = Buffer.from("test message");
      const sig = await ed.signAsync(msg, privKey);
      const valid = await ed.verifyAsync(sig, msg, pubKey);
      expect(valid).toBe(true);

      // Fingerprint matches; default keyId is minisign-style short label
      const expectedFp = computeFingerprint(pubKey);
      expect(result.fingerprint).toBe(expectedFp);
      expect(result.keyId).toBe(`cl-${expectedFp.slice(0, 8)}`);
    });

    it("saves keys to specified output directory and honors --key-id", async () => {
      const keyDir = join(tempDir, "keys");
      await mkdir(keyDir, { recursive: true });
      const result = await initKey({ output: keyDir, keyId: "cl-acme-2026" });
      expect(result.privateKeyPath).toContain("keys");
      expect(result.publicKeyPath).toContain("keys");
      expect(result.keyId).toBe("cl-acme-2026");
    });
  });

  describe("build-manifest", () => {
    it("builds a contextlock/2 manifest with lints attestation", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "# My Skill\nDo things.", "utf-8");
      await writeFile(join(tempDir, "RULES.md"), "# Rules\nFollow them.", "utf-8");
      await writeFile(join(tempDir, "README.md"), "# Readme", "utf-8");

      const result = await buildManifest({
        directory: tempDir,
        packageName: "test-pkg",
        version: 3,
        displayVersion: "1.0.0",
        publisherName: "Alice",
        keyId: "cl-alice",
      });

      expect(result.fileCount).toBe(2);
      expect(result.filePaths.sort()).toEqual(["RULES.md", "SKILL.md"]);
      expect(result.manifest.spec_version).toBe("contextlock/2");
      expect(result.manifest.package).toBe("test-pkg");
      expect(result.manifest.version).toBe(3);
      expect(result.manifest.display_version).toBe("1.0.0");
      expect(result.manifest.publisher).toEqual({ name: "Alice", key_id: "cl-alice" });
      expect(result.manifest.expires_at).toBeDefined();
      expect(result.manifest.lints).toEqual({
        unicode_tags: "absent",
        zero_width: "absent",
        bidi_controls: "absent",
      });

      // Verify hashes and lengths over exact bytes
      for (const entry of result.manifest.files) {
        expect(entry.sha256).toBe(await computeFileHash(join(tempDir, entry.path)));
        expect(entry.length).toBeGreaterThan(0);
      }
    });

    it("rejects non-integer versions", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "# Skill", "utf-8");
      await expect(
        buildManifest({
          directory: tempDir,
          packageName: "p",
          version: 1.5,
          publisherName: "A",
          keyId: "k",
        }),
      ).rejects.toThrow(/positive integer/);
    });

    it("BLOCKS on lint hits unless the rule is allowed (SPEC v2 6.7)", async () => {
      const smuggled = `# Skill${String.fromCodePoint(0xe0041)}\nDo things.`;
      await writeFile(join(tempDir, "SKILL.md"), smuggled, "utf-8");

      await expect(
        buildManifest({
          directory: tempDir,
          packageName: "lint-pkg",
          version: 1,
          publisherName: "A",
          keyId: "k",
        }),
      ).rejects.toThrow(/content lints failed.*unicode_tags/s);

      const allowed = await buildManifest({
        directory: tempDir,
        packageName: "lint-pkg",
        version: 1,
        publisherName: "A",
        keyId: "k",
        allowLints: ["unicode_tags"],
      });
      expect(allowed.manifest.lints!.unicode_tags).toBe("allowed");
    });

    it("warns when no protected files found", async () => {
      await writeFile(join(tempDir, "README.md"), "nothing protected", "utf-8");

      const result = await buildManifest({
        directory: tempDir,
        packageName: "empty-pkg",
        version: 1,
        publisherName: "Bob",
        keyId: "k",
      });

      expect(result.fileCount).toBe(0);
      expect(result.warning).toBeDefined();
    });
  });

  describe("sign-manifest", () => {
    it("produces a DSSE envelope whose signature verifies over PAE", async () => {
      const keyResult = await initKey({ output: tempDir });

      await writeFile(join(tempDir, "SKILL.md"), "# Skill content", "utf-8");
      const buildResult = await buildManifest({
        directory: tempDir,
        packageName: "sig-test",
        version: 1,
        publisherName: "Signer",
        keyId: keyResult.keyId,
      });

      const sigResult = await signManifest({
        manifestPath: buildResult.manifestPath,
        privateKeyPath: keyResult.privateKeyPath,
      });

      expect(sigResult.envelopePath.endsWith(ENVELOPE_FILENAME)).toBe(true);
      expect(sigResult.keyId).toBe(keyResult.keyId);

      const envelope = parseEnvelope(await readFile(sigResult.envelopePath));
      expect(envelope.payloadType).toBe(MANIFEST_PAYLOAD_TYPE);
      expect(envelope.signatures[0].keyid).toBe(keyResult.keyId);

      // The payload IS the manifest bytes.
      const payload = b64Decode(envelope.payload);
      expect(payload.toString("utf-8")).toBe(buildResult.manifestJson);
      expect(parseManifest(payload).package).toBe("sig-test");

      // Verify the signature cryptographically over PAE(payloadType, payload).
      const pubKey = base64urlDecode((await readFile(keyResult.publicKeyPath, "utf-8")).trim());
      const sigBytes = new Uint8Array(b64Decode(envelope.signatures[0].sig));
      const preAuth = new Uint8Array(pae(envelope.payloadType, payload));
      expect(await ed.verifyAsync(sigBytes, preAuth, pubKey)).toBe(true);
    });

    it("refuses to sign an invalid manifest", async () => {
      const keyResult = await initKey({ output: tempDir });
      const badPath = join(tempDir, "bad-manifest.json");
      await writeFile(badPath, JSON.stringify({ spec_version: "contextlock/2" }), "utf-8");

      await expect(
        signManifest({ manifestPath: badPath, privateKeyPath: keyResult.privateKeyPath }),
      ).rejects.toThrow(/Invalid manifest/);
    });
  });

  describe("verify", () => {
    it("verifies an intact package and detects modified files", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "original content", "utf-8");
      await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "verify-test",
        version: 1,
        publisherName: "Verifier",
      });

      const okResult = await verify({ directory: tempDir });
      expect(okResult.success).toBe(true);
      expect(okResult.signatureValid).toBe(true);
      expect(okResult.fileResults[0].status).toBe("ok");

      await writeFile(join(tempDir, "SKILL.md"), "TAMPERED content", "utf-8");

      const failResult = await verify({ directory: tempDir });
      expect(failResult.success).toBe(false);
      const bad = failResult.fileResults.find((f) => f.status !== "ok");
      expect(bad).toBeDefined();
    });

    it("enforces length before hash (length-mismatch status)", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "original content", "utf-8");
      await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "verify-len",
        version: 1,
        publisherName: "Verifier",
      });

      await writeFile(join(tempDir, "SKILL.md"), "original content plus more", "utf-8");
      const failResult = await verify({ directory: tempDir });
      expect(failResult.success).toBe(false);
      expect(failResult.fileResults[0].status).toBe("length-mismatch");
    });

    it("reports missing envelope", async () => {
      const result = await verify({ directory: tempDir });
      expect(result.success).toBe(false);
      expect(result.envelopeFound).toBe(false);
    });
  });

  describe("key-fingerprint", () => {
    it("computes correct fingerprint from public key file", async () => {
      const keyResult = await initKey({ output: tempDir });
      const fpResult = await keyFingerprint({ publicKeyPath: keyResult.publicKeyPath });

      expect(fpResult.fingerprint).toBe(keyResult.fingerprint);
      expect(fpResult.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe("hash-filename", () => {
    it("produces a file with embedded hash in the name", async () => {
      const content = "# My Skill\nDo things safely.";
      await writeFile(join(tempDir, "SKILL.md"), content, "utf-8");

      const result = await hashFilename({ filePath: join(tempDir, "SKILL.md") });

      expect(result.hashedPath).toMatch(/SKILL\.[0-9a-f]{16}\.md$/);
      expect(result.embeddedHash).toHaveLength(16);
      expect(result.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(result.hash.startsWith(result.embeddedHash)).toBe(true);

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

    it("protect --mode sign generates keypair and DSSE envelope in one step", async () => {
      await writeFile(join(tempDir, "SKILL.md"), "# Protected skill", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "protect-test",
        version: 1,
        publisherName: "Protector",
      });

      expect(result.mode).toBe("sign");
      expect(result.filesProtected).toBe(1);
      expect(result.keyGenerated).toBe(true);
      expect(result.keyResult).toBeDefined();
      expect(result.buildResult).toBeDefined();
      expect(result.signResult).toBeDefined();
      expect(result.signResult!.keyId).toBe(result.keyResult!.keyId);

      // The one-shot flow writes ONLY the envelope (no sidecar manifest.json).
      const envelope = parseEnvelope(await readFile(join(tempDir, ENVELOPE_FILENAME)));
      expect(envelope.payloadType).toBe(MANIFEST_PAYLOAD_TYPE);

      const verifyResult = await verify({ directory: tempDir });
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.signatureValid).toBe(true);
    });

    it("protect --mode sign reuses existing keypair", async () => {
      const keyResult = await initKey({ output: tempDir });
      await writeFile(join(tempDir, "SKILL.md"), "# Skill", "utf-8");

      const result = await protect({
        directory: tempDir,
        mode: "sign",
        packageName: "reuse-key-test",
        version: 1,
        publisherName: "Reuser",
        privateKeyPath: keyResult.privateKeyPath,
      });

      expect(result.keyGenerated).toBeFalsy();
      expect(result.signResult!.fingerprint).toBe(keyResult.fingerprint);
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
