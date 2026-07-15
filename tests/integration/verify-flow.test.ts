/**
 * Integration test: Full user verification flow
 * Trust a publisher → verify trusted file → modify file → verify again → verify unknown signer
 * Requirements: 4, 5, 14
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { TrustStore } from "@contextlock/core";
import { trustAdd, userVerify } from "@contextlock/cli-user";
import { createTempDir, createSignedPackage } from "./helpers.js";

describe("Integration: Full user verification flow", () => {
  let tempDir: string;

  afterEach(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  it("trust → verify trusted → modify → verify modified → unknown signer", async () => {
    tempDir = await createTempDir("tcv-int-user-");

    // Create a signed package
    const pkg = await createSignedPackage(tempDir, {
      "SKILL.md": "# Trusted Skill\nDo things safely.",
    });

    // 1. Verify trusted file succeeds
    const trustedResult = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(trustedResult.result.status).toBe("trusted");
    expect(trustedResult.result.publisher).toBe("IntegrationPublisher");
    expect(trustedResult.displayMessage).toContain("trusted");

    // 2. Modify the file
    await writeFile(join(tempDir, "SKILL.md"), "TAMPERED content", "utf-8");

    const modifiedResult = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: pkg.storePath,
    });
    expect(modifiedResult.result.status).toBe("modified");
    expect(modifiedResult.displayMessage).toContain("modified");

    // 3. Verify with empty trust store (unknown signer)
    const emptyStorePath = join(tempDir, "empty-store.json");
    const emptyStore = new TrustStore();
    await emptyStore.save(emptyStorePath);

    // Restore original file
    await writeFile(join(tempDir, "SKILL.md"), "# Trusted Skill\nDo things safely.", "utf-8");

    const untrustedResult = await userVerify({
      filePath: join(tempDir, "SKILL.md"),
      trustStorePath: emptyStorePath,
    });
    expect(untrustedResult.result.status).toBe("untrusted");
    expect(untrustedResult.displayMessage).toContain("untrusted");
  });
});
