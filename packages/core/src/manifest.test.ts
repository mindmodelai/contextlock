import { describe, it, expect } from "vitest";
import {
  parseManifest,
  serializeManifest,
  parseSignature,
  serializeSignature,
  validateManifest,
  validateSignature,
  type Manifest,
  type DetachedSignature,
} from "./manifest.js";

// ---- Helpers ----

function validManifest(): Manifest {
  return {
    schema: "tcv-manifest/v1",
    package: "my-package",
    version: "1.0.0",
    publisher: {
      name: "Alice",
      key_id: "key-001",
      public_key_fingerprint: "abcdef1234567890",
    },
    published_at: "2025-01-15T12:00:00Z",
    files: [
      { path: "SKILL.md", sha256: "a".repeat(64), size: 128 },
    ],
  };
}

function validSignature(): DetachedSignature {
  return {
    schema: "tcv-signature/v1",
    manifest_sha256: "b".repeat(64),
    algorithm: "Ed25519",
    key_id: "key-001",
    signature: "c3VwZXJzZWNyZXQ",
  };
}

// ---- Manifest validation ----

describe("validateManifest", () => {
  it("returns no errors for a valid manifest", () => {
    expect(validateManifest(validManifest())).toEqual([]);
  });

  it("rejects wrong schema", () => {
    const m = { ...validManifest(), schema: "wrong/v1" };
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "schema")).toBe(true);
  });

  it("rejects missing package", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.package;
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "package")).toBe(true);
  });

  it("rejects missing version", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.version;
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "version")).toBe(true);
  });

  it("rejects missing publisher", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.publisher;
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "publisher")).toBe(true);
  });

  it("rejects missing publisher.name", () => {
    const m = validManifest();
    (m.publisher as Record<string, unknown>).name = "";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "publisher.name")).toBe(true);
  });

  it("rejects missing publisher.key_id", () => {
    const m = validManifest();
    (m.publisher as Record<string, unknown>).key_id = "";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "publisher.key_id")).toBe(true);
  });

  it("rejects missing publisher.public_key_fingerprint", () => {
    const m = validManifest();
    (m.publisher as Record<string, unknown>).public_key_fingerprint = "";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "publisher.public_key_fingerprint")).toBe(true);
  });

  it("rejects missing published_at", () => {
    const m = { ...validManifest() } as Record<string, unknown>;
    delete m.published_at;
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "published_at")).toBe(true);
  });

  it("rejects invalid published_at", () => {
    const m = { ...validManifest(), published_at: "not-a-date" };
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "published_at" && e.message.includes("ISO 8601"))).toBe(true);
  });

  it("rejects invalid expires_at", () => {
    const m = { ...validManifest(), expires_at: "bad-date" };
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "expires_at" && e.message.includes("ISO 8601"))).toBe(true);
  });

  it("accepts valid expires_at", () => {
    const m = { ...validManifest(), expires_at: "2026-06-01T00:00:00Z" };
    expect(validateManifest(m)).toEqual([]);
  });

  it("rejects files not being an array", () => {
    const m = { ...validManifest(), files: "not-array" } as unknown;
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field === "files")).toBe(true);
  });

  it("rejects file entry missing path", () => {
    const m = validManifest();
    (m.files[0] as unknown as Record<string, unknown>).path = "";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field.includes("path"))).toBe(true);
  });

  it("rejects file entry missing sha256", () => {
    const m = validManifest();
    (m.files[0] as unknown as Record<string, unknown>).sha256 = "";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field.includes("sha256"))).toBe(true);
  });

  it("rejects file entry missing size", () => {
    const m = validManifest();
    (m.files[0] as unknown as Record<string, unknown>).size = "not-a-number";
    const errors = validateManifest(m);
    expect(errors.some((e) => e.field.includes("size"))).toBe(true);
  });

  it("detects duplicate file paths", () => {
    const m = validManifest();
    m.files.push({ path: "SKILL.md", sha256: "b".repeat(64), size: 256 });
    const errors = validateManifest(m);
    expect(errors.some((e) => e.message.includes("Duplicate"))).toBe(true);
  });

  it("rejects null manifest", () => {
    const errors = validateManifest(null);
    expect(errors.length).toBeGreaterThan(0);
  });
});

// ---- Signature validation ----

describe("validateSignature", () => {
  it("returns no errors for a valid signature", () => {
    expect(validateSignature(validSignature())).toEqual([]);
  });

  it("rejects wrong schema", () => {
    const s = { ...validSignature(), schema: "wrong" };
    const errors = validateSignature(s);
    expect(errors.some((e) => e.field === "schema")).toBe(true);
  });

  it("rejects missing manifest_sha256", () => {
    const s = { ...validSignature() } as Record<string, unknown>;
    delete s.manifest_sha256;
    const errors = validateSignature(s);
    expect(errors.some((e) => e.field === "manifest_sha256")).toBe(true);
  });

  it("rejects wrong algorithm", () => {
    const s = { ...validSignature(), algorithm: "RSA" };
    const errors = validateSignature(s);
    expect(errors.some((e) => e.field === "algorithm")).toBe(true);
  });

  it("rejects missing key_id", () => {
    const s = { ...validSignature() } as Record<string, unknown>;
    delete s.key_id;
    const errors = validateSignature(s);
    expect(errors.some((e) => e.field === "key_id")).toBe(true);
  });

  it("rejects missing signature", () => {
    const s = { ...validSignature() } as Record<string, unknown>;
    delete s.signature;
    const errors = validateSignature(s);
    expect(errors.some((e) => e.field === "signature")).toBe(true);
  });

  it("rejects null signature", () => {
    const errors = validateSignature(null);
    expect(errors.length).toBeGreaterThan(0);
  });
});

// ---- parseManifest / serializeManifest ----

describe("parseManifest", () => {
  it("parses valid JSON into a Manifest", () => {
    const m = validManifest();
    const json = JSON.stringify(m);
    const parsed = parseManifest(json);
    expect(parsed).toEqual(m);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseManifest("{bad")).toThrow("Invalid JSON");
  });

  it("throws on schema violation", () => {
    expect(() => parseManifest(JSON.stringify({ schema: "wrong" }))).toThrow("Invalid manifest");
  });
});

describe("serializeManifest", () => {
  it("produces pretty-printed JSON (2-space indent)", () => {
    const m = validManifest();
    const json = serializeManifest(m);
    expect(json).toBe(JSON.stringify(m, null, 2));
  });

  it("round-trips with parseManifest", () => {
    const m = validManifest();
    const roundTripped = parseManifest(serializeManifest(m));
    expect(roundTripped).toEqual(m);
  });
});

// ---- parseSignature / serializeSignature ----

describe("parseSignature", () => {
  it("parses valid JSON into a DetachedSignature", () => {
    const s = validSignature();
    const json = JSON.stringify(s);
    const parsed = parseSignature(json);
    expect(parsed).toEqual(s);
  });

  it("throws on invalid JSON", () => {
    expect(() => parseSignature("nope")).toThrow("Invalid JSON");
  });

  it("throws on schema violation", () => {
    expect(() => parseSignature(JSON.stringify({ schema: "wrong" }))).toThrow("Invalid signature");
  });
});

describe("serializeSignature", () => {
  it("produces pretty-printed JSON (2-space indent)", () => {
    const s = validSignature();
    const json = serializeSignature(s);
    expect(json).toBe(JSON.stringify(s, null, 2));
  });

  it("round-trips with parseSignature", () => {
    const s = validSignature();
    const roundTripped = parseSignature(serializeSignature(s));
    expect(roundTripped).toEqual(s);
  });
});
