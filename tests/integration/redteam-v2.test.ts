/**
 * Red-team tests for the v2 format (SPEC v2 14, Phase B acceptance):
 * rollback replay (T7), manifest stripping (T6), mix-and-match (T9),
 * cross-package confusion (T10), sidecar differential (verify-then-parse),
 * and keyid-hint spoofing (DSSE 6.2).
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import {
  VerificationEngine,
  evaluatePolicy,
  serializeEnvelope,
  serializeManifest,
  ENVELOPE_FILENAME,
} from "@contextlock/core";
import {
  makeKeypair,
  makeManifest,
  signManifestEnvelope,
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

async function tempDir(prefix: string): Promise<string> {
  const d = await createTempDir(prefix);
  dirs.push(d);
  return d;
}

function engineFor(dir: string, trustStorePath: string): VerificationEngine {
  return new VerificationEngine({
    trustStorePath,
    cachePath: "",
    protectedPatterns: ["**/SKILL.md", "**/CLAUDE.md"],
    policyLevel: "strict",
    workspaceRoot: dir,
  });
}

describe("Red team: rollback replay (T7)", () => {
  it("replaying an older signed release is detected and blocked", async () => {
    const dir = await tempDir("rt-rollback-");
    const kp = await makeKeypair();
    const pkg = uniquePackageName("rt-roll");
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    // The vulnerable v4 release (signed, legitimate at the time).
    const v4Content = "# SKILL v4 (has the vulnerability)\n";
    const v4Manifest = makeManifest({
      packageName: pkg,
      version: 4,
      keyId: kp.keyId,
      files: { "SKILL.md": v4Content },
    });
    const v4Envelope = await signManifestEnvelope(v4Manifest, kp);

    // The fixed v5 release, currently installed and verified.
    await writeSignedPackage(dir, kp, {
      packageName: pkg,
      version: 5,
      files: { "SKILL.md": "# SKILL v5 (fixed)\n" },
    });

    const engine = engineFor(dir, storePath);
    const current = await engine.verify(join(dir, "SKILL.md"));
    expect(current.status).toBe("trusted"); // baseline is now 5

    // Attacker swaps BOTH the envelope and the file back to the signed v4.
    await writeFile(join(dir, ENVELOPE_FILENAME), serializeEnvelope(v4Envelope), "utf-8");
    await writeFile(join(dir, "SKILL.md"), v4Content, "utf-8");

    const replayed = await engine.verify(join(dir, "SKILL.md"));
    expect(replayed.status).toBe("rollback");
    expect(replayed.reason).toContain("rollback");

    // Blocked under strict AND balanced (an active attack signal).
    expect(evaluatePolicy({ level: "strict", verificationResult: replayed })).toBe("block");
    expect(evaluatePolicy({ level: "balanced", verificationResult: replayed })).toBe("block");

    // Re-verifying the CURRENT release (equal version) still passes.
    await writeSignedPackage(dir, kp, {
      packageName: pkg,
      version: 5,
      files: { "SKILL.md": "# SKILL v5 (fixed)\n" },
    });
    const again = await engine.verify(join(dir, "SKILL.md"));
    expect(again.status).toBe("trusted");
  });
});

describe("Red team: manifest stripping (T6)", () => {
  it("deleting the envelope downgrades LOUDLY, never silently", async () => {
    const dir = await tempDir("rt-strip-");
    const kp = await makeKeypair();
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [kp]);
    await writeSignedPackage(dir, kp, {
      packageName: uniquePackageName("rt-strip"),
      files: { "SKILL.md": "# Signed skill\n" },
    });

    const engine = engineFor(dir, storePath);
    expect((await engine.verify(join(dir, "SKILL.md"))).status).toBe("trusted");

    // Strip the manifest.
    await rm(join(dir, ENVELOPE_FILENAME));

    const stripped = await engine.verify(join(dir, "SKILL.md"));
    expect(stripped.status).toBe("untrusted");
    expect(stripped.reason).toBeDefined();

    // Protected-class file without evidence: block under strict, warn under
    // balanced (SPEC v2 T6: loud, never silent).
    expect(evaluatePolicy({ level: "strict", verificationResult: stripped })).toBe("block");
    expect(evaluatePolicy({ level: "balanced", verificationResult: stripped })).toBe("warn");
  });
});

describe("Red team: mix-and-match (T9)", () => {
  it("a file from release A does not verify under release B's manifest", async () => {
    const dir = await tempDir("rt-mix-");
    const kp = await makeKeypair();
    const pkg = uniquePackageName("rt-mix");
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const releaseAContent = "# SKILL from release A\n";

    // Install release B (both files covered by ONE manifest).
    await writeSignedPackage(dir, kp, {
      packageName: pkg,
      version: 2,
      files: {
        "SKILL.md": "# SKILL from release B\n",
        "RULES.md": "# RULES from release B\n",
      },
    });

    // Attacker swaps one file back to release A's copy.
    await writeFile(join(dir, "SKILL.md"), releaseAContent, "utf-8");

    const result = await engineFor(dir, storePath).verify(join(dir, "SKILL.md"));
    expect(result.status).toBe("modified");
    // The sibling file still verifies - the manifest binds per-file hashes.
    const sibling = await engineFor(dir, storePath).verify(join(dir, "RULES.md"));
    expect(sibling.status).toBe("trusted");
  });
});

describe("Red team: cross-package confusion (T10)", () => {
  it("a file verified under package A is not trusted when presented under package B", async () => {
    const root = await tempDir("rt-xpkg-");
    const kp = await makeKeypair();
    const storePath = join(root, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const pkgA = join(root, "pkg-a");
    const pkgB = join(root, "pkg-b");
    const content = "# Legitimately signed in package A\n";

    await writeSignedPackage(pkgA, kp, {
      packageName: uniquePackageName("rt-a"),
      files: { "SKILL.md": content },
    });
    await writeSignedPackage(pkgB, kp, {
      packageName: uniquePackageName("rt-b"),
      files: { "OTHER.prompt.md": "# unrelated\n" },
    });

    // Copy A's (signed) file into B. B's manifest does not list it; A's
    // manifest is invisible because B's envelope shadows it (first found wins).
    await writeFile(join(pkgB, "SKILL.md"), content, "utf-8");

    const result = engineFor(root, storePath);
    const verdict = await result.verify(join(pkgB, "SKILL.md"));
    expect(verdict.status).toBe("untrusted");
    expect(verdict.reason).toContain("not listed");
  });
});

describe("Red team: sidecar differential (verify-then-parse, 6.2)", () => {
  it("a lying unsigned sidecar manifest file cannot influence the verdict", async () => {
    const dir = await tempDir("rt-sidecar-");
    const kp = await makeKeypair();
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const { manifest } = await writeSignedPackage(dir, kp, {
      packageName: uniquePackageName("rt-side"),
      files: { "SKILL.md": "# real content\n" },
    });

    // Attacker tampers the file AND plants a sidecar manifest that attests the
    // tampered bytes (mimicking v1's manifest.json path).
    const tampered = "# TAMPERED content\n";
    await writeFile(join(dir, "SKILL.md"), tampered, "utf-8");
    const lying = makeManifest({
      packageName: manifest.package,
      version: manifest.version,
      keyId: kp.keyId,
      files: { "SKILL.md": tampered },
    });
    await writeFile(join(dir, "contextlock.manifest.json"), serializeManifest(lying), "utf-8");

    // The engine consumes only the verified envelope payload: still modified.
    const verdict = await engineFor(dir, storePath).verify(join(dir, "SKILL.md"));
    expect(verdict.status).toBe("modified");
  });
});

describe("Red team: keyid hint spoofing (DSSE 6.2)", () => {
  it("an attacker claiming a trusted keyid on an untrusted signature is rejected", async () => {
    const dir = await tempDir("rt-keyid-");
    const trusted = await makeKeypair("cl-trusted");
    const attacker = await makeKeypair("cl-attacker");
    const storePath = join(dir, "truststore.json");
    await writeTrustStore(storePath, [trusted]);

    const content = "# malicious content\n";
    const manifest = makeManifest({
      packageName: uniquePackageName("rt-key"),
      keyId: "cl-trusted", // lies about the signer
      files: { "SKILL.md": content },
    });
    const envelope = await signManifestEnvelope(manifest, attacker);
    // Force the keyid HINT to the trusted label too.
    envelope.signatures[0].keyid = "cl-trusted";

    await writeFile(join(dir, "SKILL.md"), content, "utf-8");
    await writeFile(join(dir, ENVELOPE_FILENAME), serializeEnvelope(envelope), "utf-8");

    const verdict = await engineFor(dir, storePath).verify(join(dir, "SKILL.md"));
    expect(verdict.status).toBe("untrusted");
    expect(verdict.reason).toContain("unknown signing key");
  });
});
