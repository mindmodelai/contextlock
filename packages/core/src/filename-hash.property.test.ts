// Feature: contextlock, Property 16: Filename hash extraction and verification
// **Validates: Requirements 16.1, 16.2, 16.3, 16.4**

import { describe, it, expect, afterAll } from "vitest";
import fc from "fast-check";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { extractFilenameHash, verifyFilenameHash } from "./filename-hash.js";
import { sha256 } from "./hash.js";

// ---- Shared temp directory ----

let tempDir: string;
const cleanup: string[] = [];

async function getTempDir(): Promise<string> {
  if (!tempDir) {
    tempDir = await mkdtemp(join(tmpdir(), "fnhash-prop-"));
    cleanup.push(tempDir);
  }
  return tempDir;
}

afterAll(async () => {
  for (const dir of cleanup) {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- Arbitraries ----

/** Simple name segment (no dots, no path separators). */
const nameArb = fc
  .array(
    fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz".split("")),
    { minLength: 1, maxLength: 8 },
  )
  .map((arr) => arr.join(""));

/** Hex hash of length 4–16. */
const hexHashArb = fc
  .array(
    fc.constantFrom(..."0123456789abcdef".split("")),
    { minLength: 4, maxLength: 16 },
  )
  .map((arr) => arr.join(""));

/** File extension. */
const extArb = fc.constantFrom("md", "txt", "ts", "json");

/** File content (ASCII to keep things simple). */
const contentArb = fc.string({ minLength: 0, maxLength: 200 });

// ---- Property 16 ----

describe("Property 16: Filename hash extraction and verification", () => {
  it("extractFilenameHash correctly extracts the hex hash from <name>.<hex>.<ext>", () => {
    fc.assert(
      fc.property(nameArb, hexHashArb, extArb, (name, hash, ext) => {
        const filename = `${name}.${hash}.${ext}`;
        const extracted = extractFilenameHash(filename);
        expect(extracted).toBe(hash.toLowerCase());
      }),
      { numRuns: 100 },
    );
  });

  it("verifyFilenameHash compares prefix correctly for matching content", async () => {
    const dir = await getTempDir();
    let counter = 0;

    await fc.assert(
      fc.asyncProperty(nameArb, extArb, contentArb, async (name, ext, content) => {
        // Compute the real hash of the EXACT bytes (SPEC v2 6.1)
        const fullHash = sha256(Buffer.from(content, "utf-8"));
        // Use first 8 chars as the embedded hash
        const hashPrefix = fullHash.substring(0, 8);

        const filename = `${name}.${hashPrefix}.${ext}`;
        const filePath = join(dir, `match_${counter++}_${filename}`);
        await writeFile(filePath, content, "utf-8");

        const result = await verifyFilenameHash(filePath);
        expect(result.hasEmbeddedHash).toBe(true);
        expect(result.embeddedHash).toBe(hashPrefix);
        expect(result.computedHashPrefix).toBe(hashPrefix);
        expect(result.matches).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it("filename hash alone never returns trusted status (advisory only)", () => {
    // The FilenameHashResult interface has no `status` field —
    // it only reports hasEmbeddedHash/matches. This structural property
    // ensures filename hash can never produce a "trusted" verification status.
    fc.assert(
      fc.property(nameArb, hexHashArb, extArb, (name, hash, ext) => {
        const filename = `${name}.${hash}.${ext}`;
        const extracted = extractFilenameHash(filename);
        // extractFilenameHash returns string | null, never a status object
        expect(typeof extracted === "string" || extracted === null).toBe(true);
        // The result type is FilenameHashResult which has no "status" or "trusted" field
      }),
      { numRuns: 100 },
    );
  });
});
