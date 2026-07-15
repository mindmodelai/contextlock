// Feature: contextlock, Property 15: Protected file pattern matching
// **Validates: Requirements 6.1, 6.3**

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { minimatch } from "minimatch";
import { isProtectedFile, DEFAULT_PATTERNS } from "./detector.js";

// ---- Arbitraries ----

/** Generate a simple filename segment (letters, digits, hyphens). */
const segmentArb = fc
  .array(
    fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-_".split("")),
    { minLength: 1, maxLength: 12 },
  )
  .map((arr) => arr.join(""));

/** Generate a file extension. */
const extArb = fc.constantFrom("md", "txt", "ts", "js", "json", "yaml", "prompt.md", "policy.md");

/** Generate a relative file path with 0–3 directory segments. */
const filePathArb = fc
  .tuple(
    fc.array(segmentArb, { minLength: 0, maxLength: 3 }),
    segmentArb,
    extArb,
  )
  .map(([dirs, name, ext]) => [...dirs, `${name}.${ext}`].join("/"));

/** Generate a glob pattern. */
const globPatternArb = fc.constantFrom(
  "**/SKILL.md",
  "**/CLAUDE.md",
  "**/RULES.md",
  "**/*.prompt.md",
  "**/*.policy.md",
  "**/*.md",
  "**/*.ts",
  "*.md",
  "src/**/*.js",
);

// ---- Property 15 ----

describe("Property 15: Protected file pattern matching", () => {
  it("isProtectedFile returns true iff path matches at least one pattern", () => {
    fc.assert(
      fc.property(
        filePathArb,
        fc.array(globPatternArb, { minLength: 1, maxLength: 5 }),
        (filePath, patterns) => {
          const result = isProtectedFile(filePath, patterns);
          // Ground truth: check with minimatch directly
          const expected = patterns.some((p) =>
            minimatch(filePath.replace(/\\/g, "/"), p, { dot: true }),
          );
          expect(result).toBe(expected);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("default patterns match known protected filenames", () => {
    fc.assert(
      fc.property(
        fc.array(segmentArb, { minLength: 0, maxLength: 3 }),
        fc.constantFrom("SKILL.md", "CLAUDE.md", "RULES.md", "setup.prompt.md", "sec.policy.md"),
        (dirs, filename) => {
          const filePath = [...dirs, filename].join("/");
          expect(isProtectedFile(filePath, DEFAULT_PATTERNS)).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});
