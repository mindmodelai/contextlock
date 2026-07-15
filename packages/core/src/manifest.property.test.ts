// Feature: contextlock — manifest parser property tests (contextlock/2)
// Property 12: Manifest round-trip
// Property 13: Schema violation rejection (including path abuse, T10/T11)
// Property 3/4 (v2): DSSE envelope sign/verify round-trip and tamper rejection

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { sha512 } from "@noble/hashes/sha2";
import * as ed from "@noble/ed25519";
import {
  parseManifest,
  serializeManifest,
  validateManifest,
  type Manifest,
} from "./manifest.js";
import { signEnvelope, verifyEnvelope, b64Encode, MANIFEST_PAYLOAD_TYPE } from "./dsse.js";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

// ---- Arbitraries ----

const hexHash = fc
  .array(
    fc.constantFrom("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"),
    { minLength: 64, maxLength: 64 },
  )
  .map((chars) => chars.join(""));

const safeSegment = fc
  .stringMatching(/^[A-Za-z0-9_-]{1,12}$/)
  .filter((s) => s !== "." && s !== "..");

const safePath = fc
  .array(safeSegment, { minLength: 1, maxLength: 4 })
  .map((segs) => segs.join("/") + ".md");

const isoDate = fc
  .integer({ min: new Date("2020-01-01").getTime(), max: new Date("2035-01-01").getTime() })
  .map((ms) => new Date(ms).toISOString());

const fileEntryArb = fc.record({
  path: safePath,
  sha256: hexHash,
  length: fc.integer({ min: 0, max: 10_000_000 }),
});

const uniqueFilesArb = fc
  .array(fileEntryArb, { minLength: 1, maxLength: 8 })
  .filter((files) => new Set(files.map((f) => f.path)).size === files.length);

const validManifestArb: fc.Arbitrary<Manifest> = fc
  .record({
    packageName: fc.stringMatching(/^[a-z][a-z0-9-]{1,30}$/),
    version: fc.integer({ min: 1, max: 1_000_000 }),
    publisherName: fc.string({ minLength: 1, maxLength: 30 }),
    keyId: fc.stringMatching(/^[a-z0-9-]{2,20}$/),
    publishedAt: isoDate,
    expiresAt: isoDate,
    files: uniqueFilesArb,
  })
  .map((r) => ({
    spec_version: "contextlock/2" as const,
    package: r.packageName,
    version: r.version,
    publisher: { name: r.publisherName, key_id: r.keyId },
    published_at: r.publishedAt,
    expires_at: r.expiresAt,
    files: r.files,
  }));

// ---- Property 12: Round-trip ----

describe("Property 12: Manifest round-trip", () => {
  it("parseManifest(serializeManifest(m)) deep-equals m for any valid manifest", () => {
    fc.assert(
      fc.property(validManifestArb, (m) => {
        expect(validateManifest(m)).toEqual([]);
        const parsed = parseManifest(serializeManifest(m));
        expect(parsed).toEqual(m);
      }),
      { numRuns: 200 },
    );
  });
});

// ---- Property 13: Schema violation rejection ----

type Mutation = (m: Record<string, unknown>) => Record<string, unknown>;

function mutateFirstFile(
  m: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const files = [...(m.files as Array<Record<string, unknown>>)];
  files[0] = { ...files[0], ...patch };
  return { ...m, files };
}

const mutations: Array<[string, Mutation]> = [
  ["wrong spec_version", (m) => ({ ...m, spec_version: "tcv-manifest/v1" })],
  ["missing package", (m) => { const c = { ...m }; delete c.package; return c; }],
  ["semver string version", (m) => ({ ...m, version: "1.0.0" })],
  ["zero version", (m) => ({ ...m, version: 0 })],
  ["float version", (m) => ({ ...m, version: 1.25 })],
  ["missing expires_at", (m) => { const c = { ...m }; delete c.expires_at; return c; }],
  ["invalid expires_at", (m) => ({ ...m, expires_at: "eventually" })],
  ["missing publisher", (m) => { const c = { ...m }; delete c.publisher; return c; }],
  ["traversal path", (m) => mutateFirstFile(m, { path: "../escape.md" })],
  ["absolute path", (m) => mutateFirstFile(m, { path: "/etc/passwd" })],
  ["backslash path", (m) => mutateFirstFile(m, { path: "dir\\file.md" })],
  ["dot segment path", (m) => mutateFirstFile(m, { path: "./file.md" })],
  ["uppercase sha256", (m) => mutateFirstFile(m, { sha256: "A".repeat(64) })],
  ["short sha256", (m) => mutateFirstFile(m, { sha256: "abc" })],
  ["negative length", (m) => mutateFirstFile(m, { length: -1 })],
  ["duplicate paths", (m) => {
    const files = [...(m.files as Array<Record<string, unknown>>)];
    files.push({ ...files[0] });
    return { ...m, files };
  }],
];

describe("Property 13: Schema violation rejection", () => {
  it("every mutation of a valid manifest is rejected by validateManifest and parseManifest", () => {
    fc.assert(
      fc.property(
        validManifestArb,
        fc.integer({ min: 0, max: mutations.length - 1 }),
        (valid, mutationIdx) => {
          const [name, mutate] = mutations[mutationIdx];
          const broken = mutate(JSON.parse(JSON.stringify(valid)));
          const errors = validateManifest(broken);
          expect(errors.length, `mutation "${name}" should produce errors`).toBeGreaterThan(0);
          expect(() => parseManifest(JSON.stringify(broken))).toThrow();
        },
      ),
      { numRuns: 200 },
    );
  });
});

// ---- Property 3/4: DSSE sign/verify round-trip and tamper rejection ----

describe("Property 3/4: DSSE envelope sign/verify (v2)", () => {
  it("any valid manifest signed into an envelope verifies and returns identical payload bytes", async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);

    await fc.assert(
      fc.asyncProperty(validManifestArb, async (m) => {
        const payload = Buffer.from(serializeManifest(m), "utf-8");
        const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
          { privateKey, keyid: "prop-key" },
        ]);
        const result = await verifyEnvelope(env, [
          { keyid: "prop-key", publicKey, publisher: "P", revoked: false },
        ]);
        expect(result.valid).toBe(true);
        expect(result.payload!.equals(payload)).toBe(true);
        expect(parseManifest(result.payload!)).toEqual(m);
      }),
      { numRuns: 50 },
    );
  });

  it("any single-byte flip in the payload makes verification fail", async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);

    await fc.assert(
      fc.asyncProperty(
        validManifestArb,
        fc.nat(),
        async (m, seed) => {
          const payload = Buffer.from(serializeManifest(m), "utf-8");
          const env = await signEnvelope(payload, MANIFEST_PAYLOAD_TYPE, [
            { privateKey, keyid: "prop-key" },
          ]);

          const flipped = Buffer.from(payload);
          const idx = seed % flipped.length;
          flipped[idx] = flipped[idx] ^ 0x01;
          const tampered = { ...env, payload: b64Encode(flipped) };

          const result = await verifyEnvelope(tampered, [
            { keyid: "prop-key", publicKey, publisher: "P", revoked: false },
          ]);
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 50 },
    );
  });
});
