// Engine integration for Profile B (SPEC v2 5): a package whose evidence is
// contextlock.sigstore.json flows through the same bounded discovery,
// manifest evaluation, anti-rollback, and file checks as Profile A.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, copyFile, mkdir, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { VerificationEngine } from "./engine.js";
import type { VerificationEngineConfig } from "./engine.js";
import { RollbackState } from "./state.js";
import { TrustStore } from "./trust-store.js";
import { signerFingerprint, SIGSTORE_BUNDLE_FILENAME } from "./sigstore.js";

const FIXTURES = fileURLToPath(new URL("../../../tests/fixtures/sigstore/", import.meta.url));
const SYNTH_ROOT = `${FIXTURES}synthetic-trusted-root.json`;
const SYNTH_PKG = `${FIXTURES}synthetic-pkg`;

const SYNTH_SAN =
  "https://github.com/contextlock-test/demo/.github/workflows/release.yml@refs/heads/main";
const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const PKG_NAME = "sigstore-demo-pkg";

let root: string;
let pkgDir: string;
let trustStorePath: string;
let stateStorePath: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "cl-sig-engine-"));
  pkgDir = join(root, "pkg");
  await mkdir(pkgDir, { recursive: true });
  await copyFile(join(SYNTH_PKG, "SKILL.md"), join(pkgDir, "SKILL.md"));
  await copyFile(
    join(SYNTH_PKG, SIGSTORE_BUNDLE_FILENAME),
    join(pkgDir, SIGSTORE_BUNDLE_FILENAME),
  );

  trustStorePath = join(root, "truststore.json");
  stateStorePath = join(root, "state.json");
  const store = new TrustStore();
  store.addIdentity({ publisher: "Sigstore Demo", identity: SYNTH_SAN, issuer: GITHUB_ISSUER });
  await store.save(trustStorePath);
});

afterEach(async () => {
  await rm(root, { recursive: true, force: true }).catch(() => {});
});

function makeEngine(overrides: Partial<VerificationEngineConfig> = {}): VerificationEngine {
  return new VerificationEngine({
    trustStorePath,
    cachePath: "",
    protectedPatterns: ["**/SKILL.md"],
    policyLevel: "strict",
    workspaceRoot: root,
    stateStorePath,
    sigstore: { trustedRootPath: SYNTH_ROOT, thresholds: { tlogThreshold: 0 } },
    ...overrides,
  });
}

describe("Engine + Sigstore Profile B", () => {
  it("verifies a file covered by a keyless-signed manifest", async () => {
    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));
    expect(result.status).toBe("trusted");
    expect(result.publisher).toBe("Sigstore Demo");
    expect(result.identity).toBe(SYNTH_SAN);
    expect(result.issuer).toBe(GITHUB_ISSUER);
  });

  it("detects tampering of a covered file", async () => {
    const original = await readFile(join(pkgDir, "SKILL.md"), "utf-8");
    // Same length, different bytes
    await writeFile(join(pkgDir, "SKILL.md"), original.replace("Demo", "Evil"), "utf-8");
    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));
    expect(result.status).toBe("modified");
  });

  it("is untrusted when the signer identity is not pinned", async () => {
    const emptyStorePath = join(root, "empty-truststore.json");
    await new TrustStore().save(emptyStorePath);
    const result = await makeEngine({ trustStorePath: emptyStorePath }).verify(
      join(pkgDir, "SKILL.md"),
    );
    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("not pinned");
  });

  it("cannot satisfy a multi-signer requirement (single certificate)", async () => {
    const result = await makeEngine({ requiredSigners: 2 }).verify(join(pkgDir, "SKILL.md"));
    expect(result.status).toBe("untrusted");
    expect(result.reason).toContain("insufficient signatures");
  });

  it("enforces anti-rollback for keyless signers", async () => {
    // Seed the baseline ABOVE the fixture's version, keyed by the signer.
    const state = new RollbackState(stateStorePath);
    await state.load();
    await state.record(
      PKG_NAME,
      signerFingerprint(GITHUB_ISSUER, SYNTH_SAN),
      9,
      "Sigstore Demo",
    );

    const result = await makeEngine().verify(join(pkgDir, "SKILL.md"));
    expect(result.status).toBe("rollback");
    expect(result.reason).toContain("rollback");
  });

  it("verifyPackage accepts a Profile B package directory", async () => {
    const verdict = await makeEngine().verifyPackage(pkgDir);
    expect(verdict.ok).toBe(true);
    expect(verdict.manifest!.package).toBe(PKG_NAME);
    expect(verdict.envelopePath.endsWith(SIGSTORE_BUNDLE_FILENAME)).toBe(true);
  });
});
