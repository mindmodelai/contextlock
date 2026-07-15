// Sigstore Profile B (SPEC v2 5): offline bundle verification against a
// pinned trusted root + identity-pin policy.
//
// Two fixture sets:
//  - REAL: the npm provenance bundle for sigstore@3.0.0 (signed by the
//    sigstore-js release workflow via GitHub Actions OIDC) verified against
//    the production Sigstore trusted root - full defaults (tlog, SCTs).
//  - SYNTHETIC: a contextlock/2 manifest signed via @sigstore/mock (mock
//    Fulcio CA + CT log + RFC3161 TSA), no transparency log entry, so
//    verification runs with tlogThreshold: 0.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  verifySigstoreBundle,
  matchTrustedIdentity,
  signerFingerprint,
} from "./sigstore.js";
import { parseManifest } from "./manifest.js";
import type { TrustedIdentity } from "./sigstore.js";

const FIXTURES = fileURLToPath(new URL("../../../tests/fixtures/sigstore/", import.meta.url));

const NPM_BUNDLE = `${FIXTURES}npm-provenance.sigstore.json`;
const PROD_ROOT = `${FIXTURES}trusted_root.json`;
const SYNTH_BUNDLE = `${FIXTURES}synthetic-pkg/contextlock.sigstore.json`;
const SYNTH_ROOT = `${FIXTURES}synthetic-trusted-root.json`;

const NPM_SAN =
  "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main";
const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
const SYNTH_SAN =
  "https://github.com/contextlock-test/demo/.github/workflows/release.yml@refs/heads/main";

function pin(identity: string, issuer = GITHUB_ISSUER, publisher = "TestPub"): TrustedIdentity {
  return { publisher, identity, issuer };
}

// ---- Identity policy ----

describe("matchTrustedIdentity", () => {
  it("matches exact identities and requires exact issuer", () => {
    expect(matchTrustedIdentity(NPM_SAN, GITHUB_ISSUER, [pin(NPM_SAN)])).toBeDefined();
    expect(matchTrustedIdentity(NPM_SAN, "https://evil.example.com", [pin(NPM_SAN)])).toBeUndefined();
    expect(matchTrustedIdentity(NPM_SAN, GITHUB_ISSUER, [pin("mailto:other@example.com")])).toBeUndefined();
  });

  it("supports globs: * does not cross /, ** does", () => {
    expect(
      matchTrustedIdentity(NPM_SAN, GITHUB_ISSUER, [pin("https://github.com/sigstore/**")]),
    ).toBeDefined();
    // Single * cannot span the nested path segments.
    expect(
      matchTrustedIdentity(NPM_SAN, GITHUB_ISSUER, [pin("https://github.com/sigstore/*")]),
    ).toBeUndefined();
  });

  it("returns undefined when signer identity is missing", () => {
    expect(matchTrustedIdentity(undefined, GITHUB_ISSUER, [pin("**")])).toBeUndefined();
    expect(matchTrustedIdentity(NPM_SAN, undefined, [pin("**")])).toBeUndefined();
  });
});

// ---- Real production fixture (full defaults) ----

describe("verifySigstoreBundle (real npm provenance bundle)", () => {
  it("verifies offline against the pinned production trusted root", async () => {
    const result = await verifySigstoreBundle(
      await readFile(NPM_BUNDLE),
      [pin(NPM_SAN, GITHUB_ISSUER, "sigstore-js")],
      { trustedRootPath: PROD_ROOT },
    );
    expect(result.valid).toBe(true);
    expect(result.publisher).toBe("sigstore-js");
    expect(result.identity).toBe(NPM_SAN);
    expect(result.issuer).toBe(GITHUB_ISSUER);
    expect(result.payloadType).toBe("application/vnd.in-toto+json");
    expect(result.payload!.toString("utf-8")).toContain("in-toto.io/Statement");
    expect(result.signerFingerprint).toBe(signerFingerprint(GITHUB_ISSUER, NPM_SAN));
  });

  it("accepts a glob identity pin", async () => {
    const result = await verifySigstoreBundle(
      await readFile(NPM_BUNDLE),
      [pin("https://github.com/sigstore/sigstore-js/**")],
      { trustedRootPath: PROD_ROOT },
    );
    expect(result.valid).toBe(true);
  });

  it("rejects a signer whose identity is not pinned", async () => {
    const result = await verifySigstoreBundle(
      await readFile(NPM_BUNDLE),
      [pin("https://github.com/other-org/**")],
      { trustedRootPath: PROD_ROOT },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("not pinned");
    expect(result.identity).toBe(NPM_SAN); // actual identity is surfaced
  });

  it("rejects when the issuer does not match exactly", async () => {
    const result = await verifySigstoreBundle(
      await readFile(NPM_BUNDLE),
      [pin(NPM_SAN, "https://accounts.google.com")],
      { trustedRootPath: PROD_ROOT },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("not pinned");
  });

  it("fails on a tampered payload (DSSE signature breaks)", async () => {
    const bundle = JSON.parse(await readFile(NPM_BUNDLE, "utf-8"));
    const payload = Buffer.from(bundle.dsseEnvelope.payload, "base64");
    payload[0] = payload[0] ^ 0x01;
    bundle.dsseEnvelope.payload = payload.toString("base64");

    const result = await verifySigstoreBundle(
      JSON.stringify(bundle),
      [pin(NPM_SAN)],
      { trustedRootPath: PROD_ROOT },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Sigstore verification failed");
  });

  it("fails with a wrong trusted root", async () => {
    const result = await verifySigstoreBundle(
      await readFile(NPM_BUNDLE),
      [pin(NPM_SAN)],
      { trustedRootPath: SYNTH_ROOT }, // mock CA cannot validate a Fulcio cert
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Sigstore verification failed");
  });
});

// ---- Synthetic contextlock-manifest fixture (mock CA/TSA, no tlog) ----

describe("verifySigstoreBundle (synthetic contextlock bundle)", () => {
  const OPTS = {
    trustedRootPath: SYNTH_ROOT,
    thresholds: { tlogThreshold: 0 },
  };

  it("verifies and yields the contextlock/2 manifest payload (verify-then-parse)", async () => {
    const result = await verifySigstoreBundle(
      await readFile(SYNTH_BUNDLE),
      [pin(SYNTH_SAN, GITHUB_ISSUER, "Sigstore Demo")],
      OPTS,
    );
    expect(result.valid).toBe(true);
    expect(result.publisher).toBe("Sigstore Demo");
    expect(result.payloadType).toBe("application/vnd.contextlock.manifest+json");
    const manifest = parseManifest(result.payload!);
    expect(manifest.package).toBe("sigstore-demo-pkg");
    expect(manifest.version).toBe(1);
  });

  it("enforces the default tlog threshold (no tlog entry -> fails without relaxation)", async () => {
    const result = await verifySigstoreBundle(
      await readFile(SYNTH_BUNDLE),
      [pin(SYNTH_SAN, GITHUB_ISSUER, "Sigstore Demo")],
      { trustedRootPath: SYNTH_ROOT }, // default thresholds
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("Sigstore verification failed");
  });
});
