/**
 * The five v1 MVP acceptance criteria, re-run on the v2 format
 * (SPEC v2 14, Phase B acceptance):
 *
 *   1. a signed SKILL.md can be verified locally
 *   2. a modified SKILL.md is detected and blocked
 *   3. an unsigned file is marked untrusted
 *   4. a manifest signed by an unknown key is rejected
 *   5. the same verification engine works through CLI and plugin adapter
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { evaluatePolicy } from "@contextlock/core";
import { userVerify } from "@contextlock/cli-user";
import { ClaudeCodeAdapter } from "@contextlock/adapter-claude-code";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "../../packages/core/src/testkit.js";
import { createTempDir } from "./helpers.js";

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => {});
  dirs.length = 0;
});

async function signedSkill(content = "# MVP Skill\nDo things.\n") {
  const dir = await createTempDir("mvp-v2-");
  dirs.push(dir);
  const kp = await makeKeypair();
  await writeSignedPackage(dir, kp, {
    packageName: uniquePackageName("mvp"),
    publisherName: "MvpPublisher",
    files: { "SKILL.md": content },
  });
  const storePath = join(dir, "truststore.json");
  await writeTrustStore(storePath, [kp], { publisherName: "MvpPublisher" });
  return { dir, kp, storePath, filePath: join(dir, "SKILL.md") };
}

describe("MVP criteria on the v2 format", () => {
  it("1. a signed SKILL.md can be verified locally", async () => {
    const pkg = await signedSkill();
    const result = await userVerify({ filePath: pkg.filePath, trustStorePath: pkg.storePath });
    expect(result.result.status).toBe("trusted");
    expect(result.result.publisher).toBe("MvpPublisher");
  });

  it("2. a modified SKILL.md is detected and blocked", async () => {
    const pkg = await signedSkill("original body\n");
    await writeFile(pkg.filePath, "injected body\n", "utf-8");

    const result = await userVerify({ filePath: pkg.filePath, trustStorePath: pkg.storePath });
    expect(result.result.status).toBe("modified");
    expect(
      evaluatePolicy({ level: "balanced", verificationResult: result.result }),
    ).toBe("block");
  });

  it("3. an unsigned file is marked untrusted", async () => {
    const dir = await createTempDir("mvp-v2-unsigned-");
    dirs.push(dir);
    await writeFile(join(dir, "SKILL.md"), "# no signature anywhere\n", "utf-8");
    const kp = await makeKeypair();
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const result = await userVerify({
      filePath: join(dir, "SKILL.md"),
      trustStorePath: storePath,
    });
    expect(result.result.status).toBe("untrusted");
  });

  it("4. a manifest signed by an unknown key is rejected", async () => {
    const dir = await createTempDir("mvp-v2-unknown-");
    dirs.push(dir);
    const strangerKey = await makeKeypair();
    await writeSignedPackage(dir, strangerKey, {
      packageName: uniquePackageName("mvp-unknown"),
      files: { "SKILL.md": "# signed by a stranger\n" },
    });
    // The trust store knows a DIFFERENT key.
    const trustedKey = await makeKeypair();
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [trustedKey]);

    const result = await userVerify({
      filePath: join(dir, "SKILL.md"),
      trustStorePath: storePath,
    });
    expect(result.result.status).toBe("untrusted");
    expect(result.result.reason).toContain("unknown signing key");
  });

  it("5. the same engine verdict flows through CLI and plugin adapter", async () => {
    const pkg = await signedSkill();

    const cliResult = await userVerify({ filePath: pkg.filePath, trustStorePath: pkg.storePath });

    const adapter = new ClaudeCodeAdapter({
      trustStorePath: pkg.storePath,
      cachePath: "",
      policyLevel: "balanced",
    });
    const adapterResult = await adapter.getVerificationStatus(pkg.filePath);

    expect(cliResult.result.status).toBe("trusted");
    expect(adapterResult.status).toBe("trusted");
    expect(adapterResult.publisher).toBe(cliResult.result.publisher);

    // And after tampering, both surfaces agree again.
    await writeFile(pkg.filePath, "tampered after signing\n", "utf-8");
    const cliTampered = await userVerify({ filePath: pkg.filePath, trustStorePath: pkg.storePath });
    const adapterDecision = await adapter.onFileLoad(pkg.filePath);
    expect(cliTampered.result.status).toBe("modified");
    expect(adapterDecision).toBe("block");
  });
});
