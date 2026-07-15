// Unit tests for Protected File Detector and Filename Hash Extractor
// Requirements: 6.1, 6.2, 16.1, 16.2

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DEFAULT_PATTERNS, isProtectedFile, findProtectedFiles } from "./detector.js";
import { extractFilenameHash } from "./filename-hash.js";

// ---- Default pattern matching (Req 6.1, 6.2) ----

describe("isProtectedFile — default patterns", () => {
  const cases: Array<[string, boolean]> = [
    ["SKILL.md", true],
    ["CLAUDE.md", true],
    ["RULES.md", true],
    ["foo.prompt.md", true],
    ["bar.policy.md", true],
    ["nested/dir/SKILL.md", true],
    ["pkg/sub/CLAUDE.md", true],
    ["deep/path/to/RULES.md", true],
    ["lib/setup.prompt.md", true],
    ["config/security.policy.md", true],
    ["README.md", false],
    ["index.ts", false],
    ["skill.md", false],       // case-sensitive
    ["claude.md", false],
    ["rules.md", false],
    ["foo.prompt.txt", false],
    ["bar.policy.json", false],
  ];

  it.each(cases)("'%s' → %s", (filePath, expected) => {
    expect(isProtectedFile(filePath, DEFAULT_PATTERNS)).toBe(expected);
  });
});

// ---- Custom patterns ----

describe("isProtectedFile — custom patterns", () => {
  it("matches custom glob pattern", () => {
    expect(isProtectedFile("docs/guide.md", ["**/*.md"])).toBe(true);
  });

  it("does not match when no pattern fits", () => {
    expect(isProtectedFile("src/index.ts", ["**/*.md"])).toBe(false);
  });

  it("matches with multiple patterns (any match)", () => {
    expect(isProtectedFile("config.yaml", ["**/*.json", "**/*.yaml"])).toBe(true);
  });

  it("normalizes backslashes for Windows paths", () => {
    expect(isProtectedFile("pkg\\sub\\SKILL.md", DEFAULT_PATTERNS)).toBe(true);
  });
});

// ---- findProtectedFiles (Req 6.1, 6.3) ----

describe("findProtectedFiles", () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "detector-test-"));
    // Create test file structure
    await writeFile(join(tempDir, "SKILL.md"), "skill content");
    await writeFile(join(tempDir, "README.md"), "readme");
    await mkdir(join(tempDir, "sub"), { recursive: true });
    await writeFile(join(tempDir, "sub", "CLAUDE.md"), "claude content");
    await writeFile(join(tempDir, "sub", "setup.prompt.md"), "prompt");
    await writeFile(join(tempDir, "sub", "index.ts"), "code");
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("finds all protected files recursively", async () => {
    const files = await findProtectedFiles(tempDir, DEFAULT_PATTERNS);
    const normalized = files.map((f) => f.replace(/\\/g, "/"));
    expect(normalized).toContain("SKILL.md");
    expect(normalized).toContain("sub/CLAUDE.md");
    expect(normalized).toContain("sub/setup.prompt.md");
    expect(normalized).not.toContain("README.md");
    expect(normalized).not.toContain("sub/index.ts");
  });

  it("returns sorted results", async () => {
    const files = await findProtectedFiles(tempDir, DEFAULT_PATTERNS);
    const sorted = [...files].sort();
    expect(files).toEqual(sorted);
  });
});

// ---- extractFilenameHash edge cases (Req 16.1, 16.2) ----

describe("extractFilenameHash", () => {
  it("extracts hash from valid pattern", () => {
    expect(extractFilenameHash("SKILL.a1b2c3d4.md")).toBe("a1b2c3d4");
  });

  it("extracts hash with uppercase hex (lowercased)", () => {
    expect(extractFilenameHash("RULES.AABB1122.md")).toBe("aabb1122");
  });

  it("extracts long hash", () => {
    const hash = "a".repeat(64);
    expect(extractFilenameHash(`file.${hash}.txt`)).toBe(hash);
  });

  it("returns null for no embedded hash", () => {
    expect(extractFilenameHash("SKILL.md")).toBeNull();
  });

  it("returns null for too-short hex segment", () => {
    // 3 hex chars is below the 4-char minimum
    expect(extractFilenameHash("file.abc.md")).toBeNull();
  });

  it("returns null for non-hex middle segment", () => {
    expect(extractFilenameHash("file.ghijkl.md")).toBeNull();
  });

  it("handles path with directories (uses basename)", () => {
    expect(extractFilenameHash("path/to/SKILL.abcd1234.md")).toBe("abcd1234");
  });

  it("returns null for empty string", () => {
    expect(extractFilenameHash("")).toBeNull();
  });
});
