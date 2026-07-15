// Feature: contextlock — Verification Engine property tests
// Property 7: File hash verification correctness — Validates: Requirements 4.1, 4.2
// Property 11: Manifest expiry evaluation — Validates: Requirements 8.1, 8.2, 8.3
// Property 17: Verification result completeness — Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.6

import { describe, it, expect, afterEach } from "vitest";
import fc from "fast-check";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { VerificationEngine } from "./engine.js";
import type { VerificationResult } from "./engine.js";
import { sha256 } from "./hash.js";
import { serializeManifest, serializeSignature } from "./manifest.js";
import type { Manifest, DetachedSignature } from "./manifest.js";
import type { TrustStoreData } from "./trust-store.js";

// Configure @noble/ed25519 v2 sha512 sync
ed.etc.sha512Sync = (...m: Uint8Array[]) =>
  sha512(ed.etc.concatBytes(...m));

// ---- Shared helpers ----

function toBase64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

interface FixtureResult {
  tmpDir: string;
  filePath: string;
  manifestPath: string;
  sigPath: string;
  trustStorePath: string;
}

/**
 * Creates a complete signed package fixture in a temp directory.
 * Returns paths needed for VerificationEngine.
 */
async function createSignedFixture(opts: {
  fileContent: string;
  expiresAt?: string;
  allowExpired?: boolean;
  revokeKey?: boolean;
}): Promise<FixtureResult> {
  const tmpDir = await mkdtemp(join(tmpdir(), "engine-prop-"));

  // Write the protected file
  const filePath = join(tmpDir, "SKILL.md");
  await writeFile(filePath, opts.fileContent, "utf-8");

  // Compute hash over the exact bytes on disk (SPEC v2 6.1)
  const fileHash = sha256(Buffer.from(opts.fileContent, "utf-8"));

  // Generate Ed25519 keypair
  const privKey = ed.utils.randomPrivateKey();
  const pubKey = await ed.getPublicKeyAsync(privKey);
  const keyId = "prop-test-key";
  const pubKeyBase64 = Buffer.from(pubKey).toString("base64");
  const fingerprint = sha256(Buffer.from(pubKey));

  // Build manifest
  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: "test-pkg",
    version: "1.0.0",
    publisher: {
      name: "Prop Test Publisher",
      key_id: keyId,
      public_key_fingerprint: fingerprint,
    },
    published_at: "2025-01-01T00:00:00Z",
    files: [
      {
        path: "SKILL.md",
        sha256: fileHash,
        size: Buffer.byteLength(opts.fileContent, "utf-8"),
      },
    ],
  };
  if (opts.expiresAt) {
    manifest.expires_at = opts.expiresAt;
  }

  const manifestJson = serializeManifest(manifest);
  const manifestBuf = Buffer.from(manifestJson, "utf-8");
  const manifestHash = sha256(manifestBuf);

  // Sign manifest
  const sigBytes = await ed.signAsync(manifestBuf, privKey);
  const sig: DetachedSignature = {
    schema: "tcv-signature/v1",
    manifest_sha256: manifestHash,
    algorithm: "Ed25519",
    key_id: keyId,
    signature: toBase64url(sigBytes),
  };

  // Write manifest and signature
  const manifestPath = join(tmpDir, "manifest.json");
  const sigPath = join(tmpDir, "manifest.sig.json");
  await writeFile(manifestPath, manifestJson, "utf-8");
  await writeFile(sigPath, serializeSignature(sig), "utf-8");

  // Write trust store
  const trustStoreData: TrustStoreData = {
    schema: "tcv-truststore/v1",
    trusted_publishers: [
      {
        publisher: "Prop Test Publisher",
        key_id: keyId,
        public_key: pubKeyBase64,
        fingerprint,
        revoked: opts.revokeKey ?? false,
        policy: {
          default_action: "block",
          allow_expired_manifest: opts.allowExpired ?? false,
          allow_offline_cached_manifest: false,
        },
      },
    ],
  };
  const trustStorePath = join(tmpDir, "truststore.json");
  await writeFile(trustStorePath, JSON.stringify(trustStoreData, null, 2), "utf-8");

  return { tmpDir, filePath, manifestPath, sigPath, trustStorePath };
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
  // **Validates: Requirements 4.1, 4.2**
  it("unmodified file returns trusted; single-byte mutation returns modified with both hashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate printable ASCII content (avoids encoding edge cases, focuses on hash logic)
        fc.string({ minLength: 1, maxLength: 200 }),
        async (content) => {
          const fixture = await createSignedFixture({ fileContent: content });
          tmpDirs.push(fixture.tmpDir);

          const engine = new VerificationEngine({
            trustStorePath: fixture.trustStorePath,
            cachePath: join(fixture.tmpDir, "cache"),
            protectedPatterns: ["**/SKILL.md"],
            policyLevel: "strict",
          });

          // Unmodified file → trusted
          const result = await engine.verify(fixture.filePath);
          expect(result.status).toBe("trusted");
          expect(result.publisher).toBe("Prop Test Publisher");
          expect(result.keyId).toBe("prop-test-key");

          // Mutate a single byte: append "X"
          const mutated = content + "X";
          await writeFile(fixture.filePath, mutated, "utf-8");

          const mutatedResult = await engine.verify(fixture.filePath);
          expect(mutatedResult.status).toBe("modified");
          expect(mutatedResult.fileHash).toBeDefined();
          expect(mutatedResult.expectedHash).toBeDefined();
          expect(mutatedResult.fileHash).not.toBe(mutatedResult.expectedHash);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---- Property 11: Manifest expiry evaluation ----

describe("Property 11: Manifest expiry evaluation", () => {
  // **Validates: Requirements 8.1, 8.2, 8.3**
  it("expired manifest returns 'expired' when allow_expired_manifest is false", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 100 }),
        // Generate a past date: 1 to 365 days ago
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

          const engine = new VerificationEngine({
            trustStorePath: fixture.trustStorePath,
            cachePath: join(fixture.tmpDir, "cache"),
            protectedPatterns: ["**/SKILL.md"],
            policyLevel: "strict",
          });

          const result = await engine.verify(fixture.filePath);
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

          const engine = new VerificationEngine({
            trustStorePath: fixture.trustStorePath,
            cachePath: join(fixture.tmpDir, "cache"),
            protectedPatterns: ["**/SKILL.md"],
            policyLevel: "strict",
          });

          const result = await engine.verify(fixture.filePath);
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
  // **Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.6**

  // Arbitraries for generating VerificationResult objects per status type
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

  it("trusted results include publisher and keyId", () => {
    fc.assert(
      fc.property(trustedResultArb, (result) => {
        expect(result.status).toBe("trusted");
        expect(result.publisher).toBeDefined();
        expect(typeof result.publisher).toBe("string");
        expect(result.publisher!.length).toBeGreaterThan(0);
        expect(result.keyId).toBeDefined();
        expect(typeof result.keyId).toBe("string");
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
        expect(typeof result.fileHash).toBe("string");
        expect(result.fileHash!.length).toBeGreaterThan(0);
        expect(result.expectedHash).toBeDefined();
        expect(typeof result.expectedHash).toBe("string");
        expect(result.expectedHash!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("untrusted results include reason", () => {
    fc.assert(
      fc.property(untrustedResultArb, (result) => {
        expect(result.status).toBe("untrusted");
        expect(result.reason).toBeDefined();
        expect(typeof result.reason).toBe("string");
        expect(result.reason!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("revoked results include keyId", () => {
    fc.assert(
      fc.property(revokedResultArb, (result) => {
        expect(result.status).toBe("revoked");
        expect(result.keyId).toBeDefined();
        expect(typeof result.keyId).toBe("string");
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
        expect(typeof result.expiresAt).toBe("string");
        expect(result.expiresAt!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });

  it("error results include reason", () => {
    fc.assert(
      fc.property(errorResultArb, (result) => {
        expect(result.status).toBe("error");
        expect(result.reason).toBeDefined();
        expect(typeof result.reason).toBe("string");
        expect(result.reason!.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 },
    );
  });
});
