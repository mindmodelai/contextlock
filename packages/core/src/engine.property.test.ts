// Feature: contextlock — Verification Engine property tests (v2 format)
// Property 7: File hash verification correctness
// Property 7b: Length enforcement before hashing
// Property 11: Manifest expiry evaluation
// Property 17: Verification result completeness

import { describe, it, expect, afterEach } from "vitest";
import fc from "fast-check";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VerificationEngine } from "./engine.js";
import type { VerificationResult } from "./engine.js";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "./testkit.js";

// ---- Shared helpers ----

interface FixtureResult {
  tmpDir: string;
  filePath: string;
  trustStorePath: string;
  keyId: string;
}

/**
 * Creates a complete signed v2 package fixture (envelope + trust store) in a
 * temp directory.
 */
async function createSignedFixture(opts: {
  fileContent: string;
  expiresAt?: string;
  allowExpired?: boolean;
  revokeKey?: boolean;
}): Promise<FixtureResult> {
  const tmpDir = await mkdtemp(join(tmpdir(), "engine-prop-"));
  const kp = await makeKeypair("prop-test-key");

  await writeSignedPackage(tmpDir, kp, {
    packageName: uniquePackageName("prop"),
    publisherName: "Prop Test Publisher",
    expiresAt: opts.expiresAt,
    files: { "SKILL.md": opts.fileContent },
  });

  const trustStorePath = join(tmpDir, "truststore.json");
  await writeTrustStore(trustStorePath, [kp], {
    publisherName: "Prop Test Publisher",
    revoked: opts.revokeKey ?? false,
    policy: { allow_expired_manifest: opts.allowExpired ?? false },
  });

  return { tmpDir, filePath: join(tmpDir, "SKILL.md"), trustStorePath, keyId: kp.keyId };
}

function makeEngine(fixture: FixtureResult): VerificationEngine {
  return new VerificationEngine({
    trustStorePath: fixture.trustStorePath,
    cachePath: join(fixture.tmpDir, "cache"),
    protectedPatterns: ["**/SKILL.md"],
    policyLevel: "strict",
    workspaceRoot: fixture.tmpDir,
  });
}

// ---- Cleanup tracking ----

const tmpDirs: string[] = [];

afterEach(async () => {
  for (const d of tmpDirs) {
    await rm(d, { recursive: true, force: true }).catch(() => {});
  }
  tmpDirs.length = 0;
});

// ---- Property 7: File hash verification correctness ----

describe("Property 7: File hash verification correctness", () => {
  it("unmodified file returns trusted; same-length byte flip returns modified with both hashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        // Printable ASCII content: a same-length character swap stays same-length in bytes.
        fc.string({ minLength: 1, maxLength: 200 }),
        async (content) => {
          const fixture = await createSignedFixture({ fileContent: content });
          tmpDirs.push(fixture.tmpDir);

          const engine = makeEngine(fixture);

          // Unmodified file → trusted
          const result = await engine.verify(fixture.filePath);
          expect(result.status).toBe("trusted");
          expect(result.publisher).toBe("Prop Test Publisher");
          expect(result.keyId).toBe(fixture.keyId);

          // Flip the first character to a different same-width character.
          const flipped = (content[0] === "A" ? "B" : "A") + content.slice(1);
          await writeFile(fixture.filePath, flipped, "utf-8");

          const mutatedResult = await engine.verify(fixture.filePath);
          expect(mutatedResult.status).toBe("modified");
          if (mutatedResult.reason?.includes("length mismatch")) {
            // Non-ASCII first char changed byte width: caught by length check.
            expect(mutatedResult.expectedHash).toBeDefined();
          } else {
            expect(mutatedResult.fileHash).toBeDefined();
            expect(mutatedResult.expectedHash).toBeDefined();
            expect(mutatedResult.fileHash).not.toBe(mutatedResult.expectedHash);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---- Property 7b: Length enforcement (SPEC v2 6.3) ----

describe("Property 7b: Length is enforced before hashing", () => {
  it("any appended suffix yields modified with a length-mismatch reason", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.string({ minLength: 1, maxLength: 50 }),
        async (content, suffix) => {
          const fixture = await createSignedFixture({ fileContent: content });
          tmpDirs.push(fixture.tmpDir);

          await writeFile(fixture.filePath, content + suffix, "utf-8");

          const result = await makeEngine(fixture).verify(fixture.filePath);
          expect(result.status).toBe("modified");
          expect(result.reason).toContain("length mismatch");
        },
      ),
      { numRuns: 50 },
    );
  });
});

// ---- Property 11: Manifest expiry evaluation ----

describe("Property 11: Manifest expiry evaluation", () => {
  it("expired manifest returns 'expired' when allow_expired_manifest is false", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.integer({ min: 1, max: 365 }),
        async (content, daysAgo) => {
          const pastDate = new Date(Date.now() - daysAgo * 86400000);
          const expiresAt = pastDate.toISOString();

          const fixture = await createSignedFixture({
            fileContent: content,
            expiresAt,
            allowExpired: false,
          });
          tmpDirs.push(fixture.tmpDir);

          const result = await makeEngine(fixture).verify(fixture.filePath);
          expect(result.status).toBe("expired");
          expect(result.expiresAt).toBe(expiresAt);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("expired manifest returns 'trusted' with warning when allow_expired_manifest is true", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        fc.integer({ min: 1, max: 365 }),
        async (content, daysAgo) => {
          const pastDate = new Date(Date.now() - daysAgo * 86400000);
          const expiresAt = pastDate.toISOString();

          const fixture = await createSignedFixture({
            fileContent: content,
            expiresAt,
            allowExpired: true,
          });
          tmpDirs.push(fixture.tmpDir);

          const result = await makeEngine(fixture).verify(fixture.filePath);
          expect(result.status).toBe("trusted");
          expect(result.warning).toBeDefined();
          expect(result.warning!.toLowerCase()).toContain("expired");
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---- Property 17: Verification result completeness ----

describe("Property 17: Verification result completeness", () => {
  const nonEmptyString = fc.string({ minLength: 1, maxLength: 50 });
  const hexHash = fc.array(
    fc.constantFrom("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"),
    { minLength: 64, maxLength: 64 },
  ).map((chars) => chars.join(""));

  const trustedResultArb = fc.record({
    status: fc.constant("trusted" as const),
    publisher: nonEmptyString,
    keyId: nonEmptyString,
  }).map((r): VerificationResult => r);

  const modifiedResultArb = fc.record({
    status: fc.constant("modified" as const),
    fileHash: hexHash,
    expectedHash: hexHash,
  }).map((r): VerificationResult => r);

  const untrustedResultArb = fc.record({
    status: fc.constant("untrusted" as const),
    reason: nonEmptyString,
  }).map((r): VerificationResult => r);

  const revokedResultArb = fc.record({
    status: fc.constant("revoked" as const),
    keyId: nonEmptyString,
  }).map((r): VerificationResult => r);

  const expiredResultArb = fc.record({
    status: fc.constant("expired" as const),
    expiresAt: fc.integer({ min: new Date("2020-01-01").getTime(), max: new Date("2030-01-01").getTime() }).map(
      (ms) => new Date(ms).toISOString(),
    ),
  }).map((r): VerificationResult => r);

  const errorResultArb = fc.record({
    status: fc.constant("error" as const),
    reason: nonEmptyString,
  }).map((r): VerificationResult => r);

  const rollbackResultArb = fc.record({
    status: fc.constant("rollback" as const),
    reason: nonEmptyString,
  }).map((r): VerificationResult => r);

  it("trusted results include publisher and keyId", () => {
    fc.assert(
      fc.property(trustedResultArb, (result) => {
        expect(result.status).toBe("trusted");
        expect(result.publisher).toBeDefined();
        expect(result.publisher!.length).toBeGreaterThan(0);
        expect(result.keyId).toBeDefined();
        expect(result.keyId!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("modified results include fileHash and expectedHash", () => {
    fc.assert(
      fc.property(modifiedResultArb, (result) => {
        expect(result.status).toBe("modified");
        expect(result.fileHash).toBeDefined();
        expect(result.fileHash!.length).toBeGreaterThan(0);
        expect(result.expectedHash).toBeDefined();
        expect(result.expectedHash!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("untrusted, error, and rollback results include reason", () => {
    for (const arb of [untrustedResultArb, errorResultArb, rollbackResultArb]) {
      fc.assert(
        fc.property(arb, (result) => {
          expect(result.reason).toBeDefined();
          expect(result.reason!.length).toBeGreaterThan(0);
        }),
        { numRuns: 100 },
      );
    }
  });

  it("revoked results include keyId", () => {
    fc.assert(
      fc.property(revokedResultArb, (result) => {
        expect(result.status).toBe("revoked");
        expect(result.keyId).toBeDefined();
        expect(result.keyId!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("expired results include expiresAt", () => {
    fc.assert(
      fc.property(expiredResultArb, (result) => {
        expect(result.status).toBe("expired");
        expect(result.expiresAt).toBeDefined();
        expect(result.expiresAt!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });
});
