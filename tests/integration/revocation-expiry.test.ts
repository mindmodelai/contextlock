/**
 * Integration test: Revocation and expiry
 * Revoke a key → verify returns revoked → test expired manifest with both policy settings
 * Requirements: 8, 9
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { TrustStore } from "@contextlock/core";
import { userVerify, trustRevoke } from "@contextlock/cli-user";
import { createTempDir, createSignedPackage } from "./helpers.js";

describe("Integration: Revocation and expiry", () => {
  let tempDir: string;

  afterEach(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("revoked key causes verification to return revoked", async () => {
    tempDir = await createTempDir("tcv-int-revoke-");

    const pkg = await createSignedPackage(tempDir, {
      "SKILL.md": "# Skill content",
    });

    // Verify passes initially
    const okResult = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(okResult.result.status).toBe("trusted");

    // Revoke the key
    await trustRevoke({ keyId: pkg.kp.fingerprint, trustStorePath: pkg.storePath });

    // Verify now returns revoked
    const revokedResult = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(revokedResult.result.status).toBe("revoked");
  });

  it("expired manifest returns expired when policy disallows", async () => {
    tempDir = await createTempDir("tcv-int-expiry-");

    // Create package with past expiry
    const pkg = await createSignedPackage(
      tempDir,
      { "SKILL.md": "# Expired skill" },
      { expiresAt: "2020-01-01T00:00:00.000Z" },
    );

    const result = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(result.result.status).toBe("expired");
  });

  it("expired manifest returns trusted with warning when policy allows", async () => {
    tempDir = await createTempDir("tcv-int-expiry-allow-");

    const pkg = await createSignedPackage(
      tempDir,
      { "SKILL.md": "# Expired but allowed" },
      { expiresAt: "2020-01-01T00:00:00.000Z" },
    );

    // Update trust store to allow expired manifests
    const store = new TrustStore();
    await store.load(pkg.storePath);
    const publisher = store.getPublisher(pkg.kp.fingerprint);
    publisher!.policy.allow_expired_manifest = true;
    await store.save(pkg.storePath);

    const result = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(result.result.status).toBe("trusted");
    expect(result.result.warning).toContain("expired");
  });
});
