/**
 * Unit tests for the Claude Code Tool Adapter (v2 format fixtures).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ClaudeCodeAdapter, formatBlockMessage } from "./index.js";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "../../core/src/testkit.js";

async function createSignedPackage(dir: string, content: string) {
  const kp = await makeKeypair();
  await writeSignedPackage(dir, kp, {
    packageName: uniquePackageName("adapter"),
    publisherName: "TestPub",
    files: { "SKILL.md": content },
  });
  const storePath = join(dir, "truststore.json");
  await writeTrustStore(storePath, [kp], {
    publisherName: "TestPub",
    policy: { default_action: "warn" },
  });
  return { fingerprint: kp.fingerprint, storePath };
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
