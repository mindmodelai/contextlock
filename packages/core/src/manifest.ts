/**
 * contextlock/2 manifest (SPEC v2 6.3).
 *
 * One signed manifest per trust boundary, fusing TUF's targets and snapshot
 * roles so intra-package mix-and-match (T9) is structurally impossible. The
 * manifest is the DSSE envelope's payload; it is never consumed from a sidecar
 * file (verify-then-parse, SPEC v2 6.2).
 *
 * All validation rules here are hard failures. Unknown fields are ignored
 * (DSSE consumer rule) for forward compatibility.
 */

// ---- Interfaces ----

export const MANIFEST_SPEC_VERSION = "contextlock/2";

/** Oversize defense (T11): refuse manifests beyond these bounds. */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_MANIFEST_FILES = 4096;
export const MAX_PATH_LENGTH = 1024;

export interface ManifestFileEntry {
  /** Relative, forward-slash path inside the manifest's directory. */
  path: string;
  /** SHA-256 (lowercase hex) over the exact bytes on disk. */
  sha256: string;
  /** Byte length, enforced before hashing (endless-data defense). */
  length: number;
}

export interface ManifestPublisher {
  name: string;
  /** Short key label (e.g. "cl-acme-2026"). Informational; trust resolution pins keys. */
  key_id: string;
}

export interface Manifest {
  spec_version: typeof MANIFEST_SPEC_VERSION;
  package: string;
  /** Monotonic integer for anti-rollback (T7). NOT semver. */
  version: number;
  /** Human-facing version string. Informational only. */
  display_version?: string;
  publisher: ManifestPublisher;
  published_at: string;
  /** Required (T8 freeze defense). */
  expires_at: string;
  files: ManifestFileEntry[];
  /** Sign-time content-lint attestations, e.g. { unicode_tags: "absent" }. */
  lints?: Record<string, string>;
}

export interface ValidationError {
  field: string;
  message: string;
}

// ---- Validation helpers ----

const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/;

function isValidIso8601(value: string): boolean {
  if (!ISO_8601_RE.test(value)) return false;
  const d = new Date(value);
  return !isNaN(d.getTime());
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

/**
 * Path rules (T10, T11), all hard failures:
 * relative, forward slashes only, no ".." or "." segments, no absolute paths
 * (POSIX or Windows drive/UNC), no empty segments, no NUL, bounded length.
 * Returns an error message or undefined if the path is acceptable.
 */
export function manifestPathError(path: string): string | undefined {
  if (path.length === 0) return "path must be non-empty";
  if (path.length > MAX_PATH_LENGTH) return `path exceeds ${MAX_PATH_LENGTH} characters`;
  if (path.includes("\0")) return "path must not contain NUL";
  if (path.includes("\\")) return "path must use forward slashes";
  if (path.startsWith("/")) return "path must be relative (no leading /)";
  if (/^[A-Za-z]:/.test(path)) return "path must be relative (no drive letter)";
  const segments = path.split("/");
  for (const seg of segments) {
    if (seg === "") return "path must not contain empty segments";
    if (seg === "..") return 'path must not contain ".." segments';
    if (seg === ".") return 'path must not contain "." segments';
  }
  return undefined;
}

// ---- validateManifest ----

export function validateManifest(manifest: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (manifest == null || typeof manifest !== "object") {
    errors.push({ field: "manifest", message: "Manifest must be a non-null object" });
    return errors;
  }

  const m = manifest as Record<string, unknown>;

  // spec_version
  if (m.spec_version !== MANIFEST_SPEC_VERSION) {
    errors.push({ field: "spec_version", message: `spec_version must be "${MANIFEST_SPEC_VERSION}"` });
  }

  // package
  if (!isNonEmptyString(m.package)) {
    errors.push({ field: "package", message: "package is required and must be a non-empty string" });
  }

  // version: monotonic integer, not semver
  if (typeof m.version !== "number" || !Number.isSafeInteger(m.version) || m.version < 1) {
    errors.push({ field: "version", message: "version is required and must be a positive integer" });
  }

  // display_version (optional, informational)
  if (m.display_version !== undefined && !isNonEmptyString(m.display_version)) {
    errors.push({ field: "display_version", message: "display_version must be a non-empty string if present" });
  }

  // publisher
  if (m.publisher == null || typeof m.publisher !== "object") {
    errors.push({ field: "publisher", message: "publisher is required and must be an object" });
  } else {
    const pub = m.publisher as Record<string, unknown>;
    if (!isNonEmptyString(pub.name)) {
      errors.push({ field: "publisher.name", message: "publisher.name is required and must be a non-empty string" });
    }
    if (!isNonEmptyString(pub.key_id)) {
      errors.push({ field: "publisher.key_id", message: "publisher.key_id is required and must be a non-empty string" });
    }
  }

  // published_at
  if (!isNonEmptyString(m.published_at)) {
    errors.push({ field: "published_at", message: "published_at is required and must be a non-empty string" });
  } else if (!isValidIso8601(m.published_at as string)) {
    errors.push({ field: "published_at", message: "published_at must be a valid ISO 8601 date-time" });
  }

  // expires_at: REQUIRED (T8)
  if (!isNonEmptyString(m.expires_at)) {
    errors.push({ field: "expires_at", message: "expires_at is required and must be a non-empty string" });
  } else if (!isValidIso8601(m.expires_at as string)) {
    errors.push({ field: "expires_at", message: "expires_at must be a valid ISO 8601 date-time" });
  }

  // files
  if (!Array.isArray(m.files)) {
    errors.push({ field: "files", message: "files is required and must be an array" });
  } else {
    if (m.files.length > MAX_MANIFEST_FILES) {
      errors.push({ field: "files", message: `files exceeds maximum of ${MAX_MANIFEST_FILES} entries` });
    }
    const seenPaths = new Set<string>();
    for (let i = 0; i < m.files.length; i++) {
      const entry = m.files[i] as Record<string, unknown> | null;
      const prefix = `files[${i}]`;
      if (entry == null || typeof entry !== "object") {
        errors.push({ field: prefix, message: `${prefix} must be an object` });
        continue;
      }
      if (!isNonEmptyString(entry.path)) {
        errors.push({ field: `${prefix}.path`, message: `${prefix}.path is required and must be a non-empty string` });
      } else {
        const pathErr = manifestPathError(entry.path as string);
        if (pathErr) {
          errors.push({ field: `${prefix}.path`, message: `${prefix}.path: ${pathErr}` });
        }
        if (seenPaths.has(entry.path as string)) {
          errors.push({ field: `${prefix}.path`, message: `Duplicate file path: ${entry.path}` });
        }
        seenPaths.add(entry.path as string);
      }
      if (!isNonEmptyString(entry.sha256) || !SHA256_HEX_RE.test(entry.sha256 as string)) {
        errors.push({ field: `${prefix}.sha256`, message: `${prefix}.sha256 is required and must be 64 lowercase hex characters` });
      }
      if (
        typeof entry.length !== "number" ||
        !Number.isSafeInteger(entry.length) ||
        entry.length < 0
      ) {
        errors.push({ field: `${prefix}.length`, message: `${prefix}.length is required and must be a non-negative integer` });
      }
    }
  }

  // lints (optional)
  if (m.lints !== undefined) {
    if (m.lints == null || typeof m.lints !== "object" || Array.isArray(m.lints)) {
      errors.push({ field: "lints", message: "lints must be an object if present" });
    } else {
      for (const [rule, value] of Object.entries(m.lints as Record<string, unknown>)) {
        if (typeof value !== "string") {
          errors.push({ field: `lints.${rule}`, message: `lints.${rule} must be a string` });
        }
      }
    }
  }

  return errors;
}

// ---- Parse / Serialize ----

export function parseManifest(json: string | Buffer): Manifest {
  const text = typeof json === "string" ? json : json.toString("utf-8");
  if (Buffer.byteLength(text) > MAX_MANIFEST_BYTES) {
    throw new Error(`manifest exceeds maximum size (${MAX_MANIFEST_BYTES} bytes)`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }

  const errors = validateManifest(parsed);
  if (errors.length > 0) {
    throw new Error(`Invalid manifest: ${errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`);
  }

  return parsed as Manifest;
}

export function serializeManifest(manifest: Manifest): string {
  return JSON.stringify(manifest, null, 2);
}
