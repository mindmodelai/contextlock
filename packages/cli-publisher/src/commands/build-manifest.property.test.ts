/**
 * Property 14: Manifest building includes all protected files
 * Validates: Requirements 11.1, 11.2, 11.3
 *
 * Generate a temp directory with files matching protected patterns;
 * assert manifest entries correspond exactly to matching files with correct hashes.
 */

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildManifest } from "./build-manifest.js";
import { computeFileHash, DEFAULT_PATTERNS } from "@contextlock/core";

// Protected filenames that match DEFAULT_PATTERNS
const PROTECTED_NAMES = ["SKILL.md", "CLAUDE.md", "RULES.md", "test.prompt.md", "sec.policy.md"];
// Non-protected filenames
const NON_PROTECTED_NAMES = ["README.md", "index.ts", "package.json", "notes.txt"];

describe("Property 14: Manifest building includes all protected files", () => {
  it("manifest entries correspond exactly to matching protected files with correct hashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate a subset of protected files to create
        fc.subarray(PROTECTED_NAMES, { minLength: 1 }),
        // Generate a subset of non-protected files to create
        fc.subarray(NON_PROTECTED_NAMES),
        // Generate content for each file
        fc.array(fc.string({ minLength: 1, maxLength: 200 }), { minLength: 5, maxLength: 10 }),
        async (protectedFiles, nonProtectedFiles, contents) => {
          const tempDir = await mkdtemp(join(tmpdir(), "tcv-prop14-"));
          try {
            // Create protected files
            for (let i = 0; i < protectedFiles.length; i++) {
              const content = contents[i % contents.length] || "content";
              await writeFile(join(tempDir, protectedFiles[i]), content, "utf-8");
            }

            // Create non-protected files
            for (let i = 0; i < nonProtectedFiles.length; i++) {
              const content = contents[(i + protectedFiles.length) % contents.length] || "other";
              await writeFile(join(tempDir, nonProtectedFiles[i]), content, "utf-8");
            }

            // Build manifest (v2: integer version, no fingerprint field)
            const result = await buildManifest({
              directory: tempDir,
              packageName: "test-pkg",
              version: 1,
              publisherName: "tester",
              keyId: "key-1",
              patterns: DEFAULT_PATTERNS,
            });

            // Assert: manifest has exactly the protected files
            expect(result.fileCount).toBe(protectedFiles.length);

            const manifestPaths = result.manifest.files.map((f) => f.path).sort();
            const expectedPaths = protectedFiles.map((p) => p.replace(/\\/g, "/")).sort();
            expect(manifestPaths).toEqual(expectedPaths);

            // Assert: each hash matches computeFileHash
            for (const entry of result.manifest.files) {
              const expectedHash = await computeFileHash(join(tempDir, entry.path));
              expect(entry.sha256).toBe(expectedHash);
            }

            // Assert: no non-protected files in manifest
            for (const np of nonProtectedFiles) {
              expect(manifestPaths).not.toContain(np);
            }
          } finally {
            await rm(tempDir, { recursive: true, force: true });
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
