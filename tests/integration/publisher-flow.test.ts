/**
 * Integration test: Full publisher flow (v2)
 * init-key → build-manifest → sign-manifest (DSSE) → verify (all pass)
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { initKey } from "@contextlock/cli-publisher";
import { buildManifest } from "@contextlock/cli-publisher";
import { signManifest } from "@contextlock/cli-publisher";
import { verify } from "@contextlock/cli-publisher";
import { createTempDir } from "./helpers.js";

describe("Integration: Full publisher flow", () => {
  let tempDir: string;

  afterEach(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("init-key → build-manifest → sign-manifest → verify succeeds", async () => {
    tempDir = await createTempDir("tcv-int-pub-");

    // 1. Generate keypair
    const keyResult = await initKey({ output: tempDir });
    expect(keyResult.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(keyResult.keyId).toMatch(/^cl-[0-9a-f]{8}$/);

    // 2. Create protected files
    await writeFile(join(tempDir, "SKILL.md"), "# My Skill\nDo amazing things.", "utf-8");
    await writeFile(join(tempDir, "RULES.md"), "# Rules\n1. Be safe.\n2. Be correct.", "utf-8");

    // 3. Build manifest (contextlock/2)
    const buildResult = await buildManifest({
      directory: tempDir,
      packageName: "my-package",
      version: 1,
      displayVersion: "1.0.0",
      publisherName: "IntegrationTester",
      keyId: keyResult.keyId,
    });

    expect(buildResult.fileCount).toBe(2);
    expect(buildResult.manifest.spec_version).toBe("contextlock/2");
    expect(buildResult.manifest.expires_at).toBeDefined();
    expect(buildResult.manifest.lints).toBeDefined();

    // 4. Sign manifest into the DSSE envelope
    const sigResult = await signManifest({
      manifestPath: buildResult.manifestPath,
      privateKeyPath: keyResult.privateKeyPath,
    });

    expect(sigResult.envelopePath).toContain("contextlock.dsse.json");
    expect(sigResult.keyId).toBe(keyResult.keyId);
    expect(sigResult.fingerprint).toBe(keyResult.fingerprint);

    // 5. Verify — signature + all files should pass
    const verifyResult = await verify({ directory: tempDir });
    expect(verifyResult.success).toBe(true);
    expect(verifyResult.envelopeFound).toBe(true);
    expect(verifyResult.signatureValid).toBe(true);
    expect(verifyResult.fileResults.every((f) => f.status === "ok")).toBe(true);
  });

  it("verify detects modified file after signing", async () => {
    tempDir = await createTempDir("tcv-int-pub-mod-");

    const keyResult = await initKey({ output: tempDir });
    await writeFile(join(tempDir, "SKILL.md"), "original content", "utf-8");

    const buildResult = await buildManifest({
      directory: tempDir,
      packageName: "mod-test",
      version: 1,
      publisherName: "Tester",
      keyId: keyResult.keyId,
    });

    await signManifest({
      manifestPath: buildResult.manifestPath,
      privateKeyPath: keyResult.privateKeyPath,
    });

    // Tamper (same byte length, different content)
    await writeFile(join(tempDir, "SKILL.md"), "TAMPERED content", "utf-8");

    const verifyResult = await verify({ directory: tempDir });
    expect(verifyResult.success).toBe(false);
    const modified = verifyResult.fileResults.find((f) => f.status === "modified");
    expect(modified).toBeDefined();
    expect(modified!.expectedHash).not.toBe(modified!.computedHash);
  });
});
