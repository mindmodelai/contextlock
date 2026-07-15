// nono interop (Phase D): consuming nono-format skill attestations -
// Sigstore bundle v0.3 -> DSSE (in-toto payloadType) -> Statement v1 with
// nono predicateTypes. The fixture is nono-shaped byte-for-byte (constants
// confirmed from nolabs-ai/nono source) and signed via @sigstore/mock.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseStatement,
  statementFileEntries,
  statementSubjectNameError,
  verifyNonoBundle,
  IN_TOTO_STATEMENT_TYPE,
  NONO_PREDICATE_MULTI,
  REDUCED_GUARANTEE_WARNING,
} from "./intoto.js";
import { verifySigstoreBundle } from "./sigstore.js";
import type { TrustedIdentity } from "./sigstore.js";
import { sha256 } from "./hash.js";

const FIXTURES = fileURLToPath(new URL("../../../tests/fixtures/sigstore/", import.meta.url));
const NONO_PKG = join(FIXTURES, "nono-pkg");
const NONO_BUNDLE = join(NONO_PKG, ".nono-trust.bundle");
const NONO_ROOT = join(FIXTURES, "nono-trusted-root.json");

const SAN = "https://github.com/nono-interop/skill/.github/workflows/sign.yml@refs/heads/main";
const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";

const OPTS = { trustedRootPath: NONO_ROOT, thresholds: { tlogThreshold: 0 } };

function pin(identity: string, publisher = "Nono Interop"): TrustedIdentity {
  return { publisher, identity, issuer: GITHUB_ISSUER };
}

// ---- Statement parsing ----

describe("parseStatement", () => {
  const validStatement = () => ({
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: [{ name: "SKILL.md", digest: { sha256: "a".repeat(64) } }],
    predicateType: NONO_PREDICATE_MULTI,
    predicate: { version: 1 },
  });

  it("parses a valid statement", () => {
    const s = parseStatement(JSON.stringify(validStatement()));
    expect(s.predicateType).toBe(NONO_PREDICATE_MULTI);
    expect(statementFileEntries(s)).toEqual([{ path: "SKILL.md", sha256: "a".repeat(64) }]);
  });

  it("rejects wrong _type, missing subjects, and bad digests", () => {
    expect(() => parseStatement(JSON.stringify({ ...validStatement(), _type: "https://in-toto.io/Statement/v0.1" }))).toThrow(/_type/);
    expect(() => parseStatement(JSON.stringify({ ...validStatement(), subject: [] }))).toThrow(/at least one subject/);
    expect(() =>
      parseStatement(
        JSON.stringify({
          ...validStatement(),
          subject: [{ name: "SKILL.md", digest: { sha512: "aa" } }],
        }),
      ),
    ).toThrow(/sha256/);
  });

  it("rejects path-abuse subject names (mirroring nono's own rules)", () => {
    for (const bad of ["../escape.md", "/etc/passwd", "C:/evil.md", "a/../../b.md"]) {
      expect(statementSubjectNameError(bad), bad).toBeDefined();
      expect(() =>
        parseStatement(
          JSON.stringify({
            ...validStatement(),
            subject: [{ name: bad, digest: { sha256: "a".repeat(64) } }],
          }),
        ),
      ).toThrow();
    }
    expect(statementSubjectNameError("scripts/helper.py")).toBeUndefined();
    expect(statementSubjectNameError("SKILL.md")).toBeUndefined();
  });
});

// ---- End-to-end: consume a nono-shaped attestation ----

describe("verifyNonoBundle (nono-shaped fixture)", () => {
  it("verifies the bundle and maps subjects to file entries with a reduced-guarantee warning", async () => {
    const result = await verifyNonoBundle(await readFile(NONO_BUNDLE), [pin(SAN)], OPTS);

    expect(result.valid).toBe(true);
    expect(result.publisher).toBe("Nono Interop");
    expect(result.identity).toBe(SAN);
    expect(result.predicateType).toBe(NONO_PREDICATE_MULTI);
    expect(result.warning).toBe(REDUCED_GUARANTEE_WARNING);

    // Subjects map to (path, sha256) entries that match the actual files.
    expect(result.files!.map((f) => f.path).sort()).toEqual(["SKILL.md", "scripts/helper.py"]);
    for (const entry of result.files!) {
      const actual = sha256(await readFile(join(NONO_PKG, entry.path)));
      expect(actual).toBe(entry.sha256);
    }
  });

  it("detects tampering of an attested file via the mapped digests", async () => {
    const result = await verifyNonoBundle(await readFile(NONO_BUNDLE), [pin(SAN)], OPTS);
    const skill = result.files!.find((f) => f.path === "SKILL.md")!;
    const tampered = Buffer.from("# Interop Skill\n\nEVIL swapped content.\n", "utf-8");
    expect(sha256(tampered)).not.toBe(skill.sha256);
  });

  it("enforces identity pinning (glob pins work, unpinned signers fail)", async () => {
    const globbed = await verifyNonoBundle(
      await readFile(NONO_BUNDLE),
      [pin("https://github.com/nono-interop/**")],
      OPTS,
    );
    expect(globbed.valid).toBe(true);

    const unpinned = await verifyNonoBundle(
      await readFile(NONO_BUNDLE),
      [pin("https://github.com/other-org/**")],
      OPTS,
    );
    expect(unpinned.valid).toBe(false);
    expect(unpinned.reason).toContain("not pinned");
  });

  it("rejects a tampered statement payload (DSSE signature breaks)", async () => {
    const bundle = JSON.parse(await readFile(NONO_BUNDLE, "utf-8"));
    const payload = Buffer.from(bundle.dsseEnvelope.payload, "base64");
    payload[payload.length - 5] ^= 0x01;
    bundle.dsseEnvelope.payload = payload.toString("base64");

    const result = await verifyNonoBundle(JSON.stringify(bundle), [pin(SAN)], OPTS);
    expect(result.valid).toBe(false);
  });

  it("rejects a foreign in-toto attestation (SLSA provenance) despite a valid signature", async () => {
    // The npm provenance fixture is a REAL in-toto statement, but it is not a
    // nono attestation: its subjects carry sha512 digests (rejected by our
    // sha256 requirement) and its predicateType is SLSA provenance.
    const result = await verifyNonoBundle(
      await readFile(join(FIXTURES, "npm-provenance.sigstore.json")),
      [
        {
          publisher: "sigstore-js",
          identity: "https://github.com/sigstore/sigstore-js/**",
          issuer: GITHUB_ISSUER,
        },
      ],
      { trustedRootPath: join(FIXTURES, "trusted_root.json") },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/unrecognized predicateType|invalid in-toto statement/);
  });
});

// ---- Format asymmetry (documents the OQ3 boundary by test) ----

describe("format asymmetry between the two payload types", () => {
  it("a contextlock/2 bundle is NOT accepted by the nono reader (payloadType gate)", async () => {
    const result = await verifyNonoBundle(
      await readFile(join(FIXTURES, "synthetic-pkg/contextlock.sigstore.json")),
      [
        {
          publisher: "Sigstore Demo",
          identity: "https://github.com/contextlock-test/**",
          issuer: GITHUB_ISSUER,
        },
      ],
      { trustedRootPath: join(FIXTURES, "synthetic-trusted-root.json"), thresholds: { tlogThreshold: 0 } },
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("unexpected payloadType");
  });

  it("a nono bundle is NOT accepted as Profile B manifest evidence (same gate, other direction)", async () => {
    // verifySigstoreBundle succeeds cryptographically but reports the in-toto
    // payloadType; the ENGINE's manifest gate is what rejects it - shown here
    // at the module level.
    const result = await verifySigstoreBundle(await readFile(NONO_BUNDLE), [pin(SAN)], OPTS);
    expect(result.valid).toBe(true);
    expect(result.payloadType).not.toBe("application/vnd.contextlock.manifest+json");
  });
});
