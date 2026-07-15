import { describe, it, expect } from "vitest";
import {
  parseManifest,
  serializeManifest,
  validateManifest,
  manifestPathError,
  MAX_MANIFEST_FILES,
  type Manifest,
} from "./manifest.js";

// ---- Helpers ----

function validManifest(): Manifest {
  return {
    spec_version: "contextlock/2",
    package: "my-package",
    version: 7,
    display_version: "1.2.0",
    publisher: {
      name: "Alice",
      key_id: "cl-alice-2026",
    },
    published_at: "2026-01-15T12:00:00Z",
    expires_at: "2027-01-15T12:00:00Z",
    files: [{ path: "SKILL.md", sha256: "a".repeat(64), length: 128 }],
    lints: { unicode_tags: "absent", zero_width: "absent", bidi_controls: "absent" },
  };
}

// ---- Manifest validation ----

describe("validateManifest (contextlock/2)", () => {
  it("returns no errors for a valid manifest", () => {
    expect(validateManifest(validManifest())).toEqual([]);
  });

  it("rejects wrong spec_version (including v1)", () => {
    for (const bad of ["wrong/v1", "tcv-manifest/v1", "contextlock/1"]) {
      const m = { ...validManifest(), spec_version: bad };
      const errors = validateManifest(m);
      expect(errors.some((e) => e.field === "spec_version")).toBe(true);
    }
  });

  it("rejects missing package", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.package;
    expect(validateManifest(m).some((e) => e.field === "package")).toBe(true);
  });

  it("rejects non-integer versions (semver strings, floats, zero, negatives)", () => {
    for (const bad of ["1.0.0", 1.5, 0, -3, undefined, null]) {
      const m = { ...validManifest(), version: bad };
      expect(validateManifest(m).some((e) => e.field === "version")).toBe(true);
    }
  });

  it("accepts a manifest without display_version", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.display_version;
    expect(validateManifest(m)).toEqual([]);
  });

  it("rejects missing publisher / publisher.name / publisher.key_id", () => {
    const noPub = { ...validManifest() } as Record<string, unknown>;
    delete noPub.publisher;
    expect(validateManifest(noPub).some((e) => e.field === "publisher")).toBe(true);

    const m1 = validManifest();
    (m1.publisher as Record<string, unknown>).name = "";
    expect(validateManifest(m1).some((e) => e.field === "publisher.name")).toBe(true);

    const m2 = validManifest();
    (m2.publisher as Record<string, unknown>).key_id = "";
    expect(validateManifest(m2).some((e) => e.field === "publisher.key_id")).toBe(true);
  });

  it("rejects missing or invalid published_at", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.published_at;
    expect(validateManifest(m).some((e) => e.field === "published_at")).toBe(true);

    const m2 = { ...validManifest(), published_at: "not-a-date" };
    expect(
      validateManifest(m2).some((e) => e.field === "published_at" && e.message.includes("ISO 8601")),
    ).toBe(true);
  });

  it("REQUIRES expires_at (T8 freeze defense)", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.expires_at;
    expect(validateManifest(m).some((e) => e.field === "expires_at")).toBe(true);
  });

  it("rejects invalid expires_at", () => {
    const m = { ...validManifest(), expires_at: "bad-date" };
    expect(
      validateManifest(m).some((e) => e.field === "expires_at" && e.message.includes("ISO 8601")),
    ).toBe(true);
  });

  it("rejects files not being an array", () => {
    const m = { ...validManifest(), files: "not-array" } as unknown;
    expect(validateManifest(m).some((e) => e.field === "files")).toBe(true);
  });

  it("rejects file entry with malformed sha256", () => {
    for (const bad of ["", "xyz", "A".repeat(64), "a".repeat(63)]) {
      const m = validManifest();
      (m.files[0] as unknown as Record<string, unknown>).sha256 = bad;
      expect(validateManifest(m).some((e) => e.field.includes("sha256"))).toBe(true);
    }
  });

  it("rejects file entry with missing or negative length", () => {
    for (const bad of ["not-a-number", -1, 1.5, undefined]) {
      const m = validManifest();
      (m.files[0] as unknown as Record<string, unknown>).length = bad;
      expect(validateManifest(m).some((e) => e.field.includes("length"))).toBe(true);
    }
  });

  it("detects duplicate file paths (T11)", () => {
    const m = validManifest();
    m.files.push({ path: "SKILL.md", sha256: "b".repeat(64), length: 256 });
    expect(validateManifest(m).some((e) => e.message.includes("Duplicate"))).toBe(true);
  });

  it("rejects oversize files arrays (T11)", () => {
    const m = validManifest();
    m.files = Array.from({ length: MAX_MANIFEST_FILES + 1 }, (_, i) => ({
      path: `f${i}.prompt.md`,
      sha256: "a".repeat(64),
      length: 1,
    }));
    expect(validateManifest(m).some((e) => e.field === "files" && e.message.includes("maximum"))).toBe(
      true,
    );
  });

  it("ignores unknown fields (forward compatibility)", () => {
    const m = { ...validManifest(), future_field: { anything: true } };
    expect(validateManifest(m)).toEqual([]);
  });

  it("rejects null manifest", () => {
    expect(validateManifest(null).length).toBeGreaterThan(0);
  });

  it("rejects non-object lints", () => {
    const m = { ...validManifest(), lints: ["absent"] } as unknown;
    expect(validateManifest(m).some((e) => e.field === "lints")).toBe(true);
  });
});

// ---- Path abuse (T10, T11) ----

describe("manifestPathError", () => {
  it("accepts normal relative paths", () => {
    expect(manifestPathError("SKILL.md")).toBeUndefined();
    expect(manifestPathError("nested/dir/RULES.md")).toBeUndefined();
  });

  it("rejects traversal, absolute, backslash, and degenerate paths", () => {
    const bad = [
      "../escape.md",
      "a/../../b.md",
      "/etc/passwd",
      "C:/windows/system32.md",
      "c:\\windows\\evil.md",
      "dir\\file.md",
      "a//b.md",
      "./file.md",
      "a/./b.md",
      "",
      "a\0b.md",
      "x".repeat(2000),
    ];
    for (const p of bad) {
      expect(manifestPathError(p), `expected rejection for ${JSON.stringify(p)}`).toBeDefined();
    }
  });

  it("path abuse is a hard validation failure", () => {
    const m = validManifest();
    m.files[0].path = "../outside.md";
    expect(validateManifest(m).some((e) => e.field.includes("path"))).toBe(true);
  });
});

// ---- parseManifest / serializeManifest ----

describe("parseManifest", () => {
  it("parses valid JSON into a Manifest", () => {
    const m = validManifest();
    const parsed = parseManifest(JSON.stringify(m));
    expect(parsed).toEqual(m);
  });

  it("accepts Buffer input (verify-then-parse payload bytes)", () => {
    const m = validManifest();
    const parsed = parseManifest(Buffer.from(JSON.stringify(m), "utf-8"));
    expect(parsed).toEqual(m);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseManifest("{bad")).toThrow("Invalid JSON");
  });

  it("throws on schema violation", () => {
    expect(() => parseManifest(JSON.stringify({ spec_version: "wrong" }))).toThrow(
      "Invalid manifest",
    );
  });

  it("throws on oversize manifests (T11)", () => {
    const m = validManifest() as unknown as Record<string, unknown>;
    m.padding = "x".repeat(1024 * 1024 + 1);
    expect(() => parseManifest(JSON.stringify(m))).toThrow("maximum size");
  });
});

describe("serializeManifest", () => {
  it("produces pretty-printed JSON (2-space indent)", () => {
    const m = validManifest();
    expect(serializeManifest(m)).toBe(JSON.stringify(m, null, 2));
  });

  it("round-trips with parseManifest", () => {
    const m = validManifest();
    expect(parseManifest(serializeManifest(m))).toEqual(m);
  });
});
