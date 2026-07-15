// Verification Engine — unit tests (v2: DSSE envelope + contextlock/2)

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdtemp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VerificationEngine } from "./engine.js";
import { ENVELOPE_FILENAME, serializeEnvelope } from "./dsse.js";
import {
  makeKeypair,
  makeManifest,
  signManifestEnvelope,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "./testkit.js";
import type { TestKeypair } from "./testkit.js";

let tmpDir: string;
let trustStorePath: string;
let kp: TestKeypair;

beforeAll(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "engine-unit-"));
  kp = await makeKeypair();
  trustStorePath = join(tmpDir, "truststore.json");
  await writeTrustStore(trustStorePath, [kp], { publisherName: "Unit Test Publisher" });
});

afterAll(async () => {
  await rm(tmpDir, { recursive: true, force: true }).catch(() => {});
});

async function createTestPackage(name: string): Promise<string> {
  const pkgDir = join(tmpDir, name);
  await mkdir(pkgDir, { recursive: true });
  return pkgDir;
}

function makeEngine(overrides: { trustStorePath?: string; workspaceRoot?: string } = {}): VerificationEngine {
  return new VerificationEngine({
    trustStorePath: overrides.trustStorePath ?? trustStorePath,
    cachePath: join(tmpDir, "cache"),
    protectedPatterns: ["**/SKILL.md"],
    policyLevel: "strict",
    workspaceRoot: overrides.workspaceRoot ?? tmpDir,
  });
}

describe("VerificationEngine (v2)", () => {
  it("returns 'trusted' for an unmodified signed file", async () => {
    const pkgDir = await createTestPackage("trusted-pkg");
    const content = "# Trusted SKILL\nThis is a trusted file.";
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      publisherName: "Unit Test Publisher",
      files: { "SKILL.md": content },
      lints: { unicode_tags: "absent", zero_width: "absent", bidi_controls: "absent" },
    });

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("Unit Test Publisher");
    expect(result.keyId).toBe(kp.keyId);
    expect(result.warning).toBeUndefined();
  });

  it("returns 'modified' when file content has been changed", async () => {
    const pkgDir = await createTestPackage("modified-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": "# Original content" },
    });

    // Same length, different bytes -> caught by the hash comparison.
    await writeFile(join(pkgDir, "SKILL.md"), "# Tampered content", "utf-8");

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("modified");
    expect(result.fileHash).toBeDefined();
    expect(result.expectedHash).toBeDefined();
    expect(result.fileHash).not.toBe(result.expectedHash);
  });

  it("returns 'modified' on a LENGTH mismatch before hashing (endless-data defense)", async () => {
    const pkgDir = await createTestPackage("length-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": "# Original" },
    });

    await writeFile(join(pkgDir, "SKILL.md"), "# Original plus injected persistence line", "utf-8");

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("modified");
    expect(result.reason).toContain("length mismatch");
  });

  it("returns 'untrusted' when the signing key is not in the trust store", async () => {
    const pkgDir = await createTestPackage("untrusted-pkg");
    const stranger = await makeKeypair("unknown-key");
    await writeSignedPackage(pkgDir, stranger, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": "# Untrusted content" },
    });

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("unknown");
  });

  it("returns 'untrusted' when no envelope is found", async () => {
    const pkgDir = await createTestPackage("no-manifest-pkg");
    await writeFile(join(pkgDir, "SKILL.md"), "# No manifest here", "utf-8");

    const result = await makeEngine({ workspaceRoot: pkgDir }).verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("no manifest");
  });

  it("returns 'revoked' when the signing key is revoked in the trust store", async () => {
    const pkgDir = await createTestPackage("revoked-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": "# Revoked key content" },
    });

    const revokedTsPath = join(pkgDir, "revoked-truststore.json");
    await writeTrustStore(revokedTsPath, [kp], {
      publisherName: "Unit Test Publisher",
      revoked: true,
    });

    const result = await makeEngine({ trustStorePath: revokedTsPath }).verify(
      join(pkgDir, "SKILL.md"),
    );

    expect(result.status).toBe("revoked");
    expect(result.keyId).toBe(kp.keyId);
  });

  it("returns 'expired' when manifest is expired and allow_expired_manifest is false", async () => {
    const pkgDir = await createTestPackage("expired-pkg");
    const pastDate = new Date(Date.now() - 7 * 86400000).toISOString();
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      expiresAt: pastDate,
      files: { "SKILL.md": "# Expired manifest content" },
    });

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("expired");
    expect(result.expiresAt).toBe(pastDate);
  });

  it("returns 'trusted' with warning when expired but allow_expired_manifest is true", async () => {
    const pkgDir = await createTestPackage("expired-allowed-pkg");
    const pastDate = new Date(Date.now() - 7 * 86400000).toISOString();
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      expiresAt: pastDate,
      files: { "SKILL.md": "# Expired but allowed" },
      lints: { unicode_tags: "absent", zero_width: "absent", bidi_controls: "absent" },
    });

    const allowExpiredTsPath = join(pkgDir, "allow-expired-truststore.json");
    await writeTrustStore(allowExpiredTsPath, [kp], {
      publisherName: "Unit Test Publisher",
      policy: { allow_expired_manifest: true },
    });

    const result = await makeEngine({ trustStorePath: allowExpiredTsPath }).verify(
      join(pkgDir, "SKILL.md"),
    );

    expect(result.status).toBe("trusted");
    expect(result.warning).toBeDefined();
    expect(result.warning!.toLowerCase()).toContain("expired");
  });

  it("warns when a manifest lacks lint attestations", async () => {
    const pkgDir = await createTestPackage("no-lints-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": "# Content without lints field" },
      // no lints
    });

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("trusted");
    expect(result.warning).toContain("lint attestations");
  });

  it("returns 'untrusted' when file is not listed in the manifest", async () => {
    const pkgDir = await createTestPackage("not-in-manifest-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "OTHER.md": "# Listed file" },
    });
    await writeFile(join(pkgDir, "SKILL.md"), "# Listed file", "utf-8");

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));

    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("not listed");
  });

  it("returns 'error' on an unexpected payloadType (T12)", async () => {
    const pkgDir = await createTestPackage("payload-type-pkg");
    const content = "# payloadType test";
    const { envelope } = await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "SKILL.md": content },
    });
    await writeFile(
      join(pkgDir, ENVELOPE_FILENAME),
      serializeEnvelope({ ...envelope, payloadType: "application/vnd.other+json" }),
      "utf-8",
    );

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));
    expect(result.status).toBe("error");
    expect(result.reason).toContain("payloadType");
  });

  it("isProtected returns true for matching patterns", () => {
    const engine = makeEngine();
    expect(engine.isProtected("some/path/SKILL.md")).toBe(true);
    expect(engine.isProtected("random.txt")).toBe(false);
  });

  it("verifyEnvelopeFile returns trusted for a valid envelope", async () => {
    const pkgDir = await createTestPackage("verify-envelope-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      publisherName: "Unit Test Publisher",
      files: { "SKILL.md": "# Envelope verify test" },
      lints: { unicode_tags: "absent", zero_width: "absent", bidi_controls: "absent" },
    });

    const { result, manifest } = await makeEngine().verifyEnvelopeFile(
      join(pkgDir, ENVELOPE_FILENAME),
    );

    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("Unit Test Publisher");
    expect(manifest?.spec_version).toBe("contextlock/2");
  });
});

// ---- Bounded discovery (T10) ----

describe("bounded manifest discovery", () => {
  it("finds an envelope in a parent directory within the workspace boundary", async () => {
    const pkgDir = await createTestPackage("walkup-pkg");
    await writeSignedPackage(pkgDir, kp, {
      packageName: uniquePackageName(),
      files: { "nested/dir/SKILL.md": "# Nested" },
    });

    const result = await makeEngine({ workspaceRoot: pkgDir }).verify(
      join(pkgDir, "nested/dir/SKILL.md"),
    );
    expect(result.status).toBe("trusted");
  });

  it("does NOT walk past the workspace boundary (envelope above boundary is invisible)", async () => {
    const outer = await createTestPackage("boundary-outer");
    const inner = join(outer, "workspace");
    await mkdir(inner, { recursive: true });

    // Envelope lives ABOVE the boundary and covers the file.
    await writeSignedPackage(outer, kp, {
      packageName: uniquePackageName(),
      files: { "workspace/SKILL.md": "# Above boundary" },
    });

    const result = await makeEngine({ workspaceRoot: inner }).verify(join(inner, "SKILL.md"));
    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("no manifest");
  });

  it("deeper envelopes SHADOW shallower ones (first found wins, no fallback)", async () => {
    const outer = await createTestPackage("shadow-outer");
    const inner = join(outer, "sub");
    await mkdir(inner, { recursive: true });

    // Outer envelope covers sub/SKILL.md with the correct hash.
    const content = "# Shadowed";
    const outerPkg = uniquePackageName();
    await writeSignedPackage(outer, kp, {
      packageName: outerPkg,
      files: { "sub/SKILL.md": content },
    });

    // Inner envelope exists but does NOT list SKILL.md.
    await writeSignedPackage(inner, kp, {
      packageName: uniquePackageName(),
      files: { "UNRELATED.prompt.md": "unrelated" },
    });
    // writeSignedPackage rewrote sub/UNRELATED... and SKILL.md still there.
    await writeFile(join(inner, "SKILL.md"), content, "utf-8");

    // The inner envelope shadows the outer one; SKILL.md is not listed in it.
    const result = await makeEngine({ workspaceRoot: outer }).verify(join(inner, "SKILL.md"));
    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("not listed");
  });
});
