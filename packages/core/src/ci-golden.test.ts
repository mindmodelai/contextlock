// CI golden vectors (captured 2026-07-15 from real GitHub Actions runs in the
// private validation repo mm-aiva/keyless-signing-lab):
//
//  - ci-real-pkg: a contextlock/2 manifest keyless-signed by
//    recipes/github-actions/keyless-sign.mjs (the Profile B recipe) - real
//    OIDC -> Fulcio certificate -> Rekor transparency log entry.
//  - nono-real-pkg: the SAME repo signed by nono's official agent-sign action
//    (nolabs-ai/agent-sign v0.1.0) - a genuine nono-format bundle, guarding
//    the interop layer against drift our mock fixture cannot see.
//
// Both verify with FULL DEFAULT thresholds (tlog 1, SCT 1, timestamp 1)
// against the pinned production Sigstore trusted root SHIPPED with core
// (assets/trusted_root.json) - no relaxation anywhere. Verification time is
// anchored to the Rekor integrated time, so these fixtures do not expire;
// the engine-level test additionally depends on the manifest's expires_at
// (2036-07-13).

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { verifySigstoreBundle } from "./sigstore.js";
import { verifyNonoBundle, REDUCED_GUARANTEE_WARNING } from "./intoto.js";
import { VerificationEngine } from "./engine.js";
import { TrustStore } from "./trust-store.js";
import { parseManifest } from "./manifest.js";
import { sha256 } from "./hash.js";

const FIXTURES = fileURLToPath(new URL("../../../tests/fixtures/sigstore/", import.meta.url));
const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const LAB = "https://github.com/mm-aiva/keyless-signing-lab/.github/workflows";

describe("CI golden vector: Profile B recipe output (real Fulcio + Rekor)", () => {
  const identity = `${LAB}/keyless-sign.yml@refs/heads/main`;
  const pkgDir = join(FIXTURES, "ci-real-pkg");

  it("verifies at full default thresholds against the SHIPPED trusted root", async () => {
    const result = await verifySigstoreBundle(
      await readFile(join(pkgDir, "contextlock.sigstore.json")),
      [{ publisher: "Keyless Lab", identity, issuer: GITHUB_ISSUER }],
      // no options: default thresholds AND the default (shipped) trusted root
    );
    expect(result.valid).toBe(true);
    expect(result.identity).toBe(identity);
    expect(result.payloadType).toBe("application/vnd.contextlock.manifest+json");

    const manifest = parseManifest(result.payload!);
    expect(manifest.package).toBe("recipe-test-pack");
    expect(manifest.version).toBe(2);
  });

  it("engine end-to-end: file and package verify as trusted (no threshold relaxation)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cl-ci-golden-"));
    const storePath = join(dir, "truststore.json");
    const store = new TrustStore();
    store.addIdentity({ publisher: "Keyless Lab", identity, issuer: GITHUB_ISSUER });
    await store.save(storePath);

    const engine = new VerificationEngine({
      trustStorePath: storePath,
      cachePath: "",
      protectedPatterns: ["**/SKILL.md"],
      policyLevel: "strict",
      workspaceRoot: pkgDir,
      stateStorePath: join(dir, "state.json"),
      // note: no sigstore overrides - shipped root, default thresholds
    });

    const fileResult = await engine.verify(join(pkgDir, "SKILL.md"));
    expect(fileResult.status).toBe("trusted");
    expect(fileResult.publisher).toBe("Keyless Lab");
    expect(fileResult.identity).toBe(identity);

    const pkgResult = await engine.verifyPackage(pkgDir);
    expect(pkgResult.ok).toBe(true);
  });
});

describe("CI golden vector: real nono bundle (agent-sign v0.1.0)", () => {
  const identity = `${LAB}/nono-sign.yml@refs/heads/main`;
  const pkgDir = join(FIXTURES, "nono-real-pkg");

  it("verifyNonoBundle accepts it at full default thresholds", async () => {
    const result = await verifyNonoBundle(
      await readFile(join(pkgDir, ".nono-trust.bundle")),
      [{ publisher: "Keyless Lab", identity, issuer: GITHUB_ISSUER }],
    );
    expect(result.valid).toBe(true);
    expect(result.predicateType).toBe("https://nono.sh/attestation/multi-file/v1");
    expect(result.warning).toBe(REDUCED_GUARANTEE_WARNING);

    // The single subject maps to the actual file with a matching digest.
    expect(result.files).toHaveLength(1);
    expect(result.files![0].path).toBe("package-dir/SKILL.md");
    const actual = sha256(await readFile(join(pkgDir, "package-dir/SKILL.md")));
    expect(actual).toBe(result.files![0].sha256);
  });

  it("rejects it when the identity is not pinned", async () => {
    const result = await verifyNonoBundle(
      await readFile(join(pkgDir, ".nono-trust.bundle")),
      [{ publisher: "Other", identity: "https://github.com/other/**", issuer: GITHUB_ISSUER }],
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("not pinned");
  });
});
