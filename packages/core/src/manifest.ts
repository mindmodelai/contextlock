// ---- Interfaces ----

export interface ManifestFileEntry {
  path: string;
  sha256: string;
  size: number;
  media_type?: string;
}

export interface Manifest {
  schema: "tcv-manifest/v1";
  package: string;
  version: string;
  publisher: {
    name: string;
    key_id: string;
    public_key_fingerprint: string;
  };
  published_at: string;
  expires_at?: string;
  source?: {
    repository?: string;
    release?: string;
  };
  files: ManifestFileEntry[];
  revocation?: {
    status: string;
    url?: string;
  };
}

export interface DetachedSignature {
  schema: "tcv-signature/v1";
  manifest_sha256: string;
  algorithm: "Ed25519";
  key_id: string;
  signature: string; // base64url
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

// ---- validateManifest ----

export function validateManifest(manifest: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (manifest == null || typeof manifest !== "object") {
    errors.push({ field: "manifest", message: "Manifest must be a non-null object" });
    return errors;
  }

  const m = manifest as Record<string, unknown>;

  // schema
  if (m.schema !== "tcv-manifest/v1") {
    errors.push({ field: "schema", message: 'schema must be "tcv-manifest/v1"' });
  }

  // required top-level strings
  if (!isNonEmptyString(m.package)) {
    errors.push({ field: "package", message: "package is required and must be a non-empty string" });
  }
  if (!isNonEmptyString(m.version)) {
    errors.push({ field: "version", message: "version is required and must be a non-empty string" });
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
    if (!isNonEmptyString(pub.public_key_fingerprint)) {
      errors.push({
        field: "publisher.public_key_fingerprint",
        message: "publisher.public_key_fingerprint is required and must be a non-empty string",
      });
    }
  }

  // published_at
  if (!isNonEmptyString(m.published_at)) {
    errors.push({ field: "published_at", message: "published_at is required and must be a non-empty string" });
  } else if (!isValidIso8601(m.published_at as string)) {
    errors.push({ field: "published_at", message: "published_at must be a valid ISO 8601 date-time" });
  }

  // expires_at (optional)
  if (m.expires_at !== undefined) {
    if (!isNonEmptyString(m.expires_at)) {
      errors.push({ field: "expires_at", message: "expires_at must be a non-empty string if present" });
    } else if (!isValidIso8601(m.expires_at as string)) {
      errors.push({ field: "expires_at", message: "expires_at must be a valid ISO 8601 date-time" });
    }
  }

  // files
  if (!Array.isArray(m.files)) {
    errors.push({ field: "files", message: "files is required and must be an array" });
  } else {
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
        if (seenPaths.has(entry.path as string)) {
          errors.push({ field: `${prefix}.path`, message: `Duplicate file path: ${entry.path}` });
        }
        seenPaths.add(entry.path as string);
      }
      if (!isNonEmptyString(entry.sha256)) {
        errors.push({ field: `${prefix}.sha256`, message: `${prefix}.sha256 is required and must be a non-empty string` });
      }
      if (typeof entry.size !== "number" || !Number.isFinite(entry.size)) {
        errors.push({ field: `${prefix}.size`, message: `${prefix}.size is required and must be a finite number` });
      }
    }
  }

  return errors;
}

// ---- validateSignature ----

export function validateSignature(sig: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  if (sig == null || typeof sig !== "object") {
    errors.push({ field: "signature", message: "Signature must be a non-null object" });
    return errors;
  }

  const s = sig as Record<string, unknown>;

  if (s.schema !== "tcv-signature/v1") {
    errors.push({ field: "schema", message: 'schema must be "tcv-signature/v1"' });
  }
  if (!isNonEmptyString(s.manifest_sha256)) {
    errors.push({ field: "manifest_sha256", message: "manifest_sha256 is required and must be a non-empty string" });
  }
  if (s.algorithm !== "Ed25519") {
    errors.push({ field: "algorithm", message: 'algorithm must be "Ed25519"' });
  }
  if (!isNonEmptyString(s.key_id)) {
    errors.push({ field: "key_id", message: "key_id is required and must be a non-empty string" });
  }
  if (!isNonEmptyString(s.signature)) {
    errors.push({ field: "signature", message: "signature is required and must be a non-empty string" });
  }

  return errors;
}

// ---- Parse / Serialize ----

export function parseManifest(json: string): Manifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
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

export function parseSignature(json: string): DetachedSignature {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }

  const errors = validateSignature(parsed);
  if (errors.length > 0) {
    throw new Error(`Invalid signature: ${errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`);
  }

  return parsed as DetachedSignature;
}

export function serializeSignature(sig: DetachedSignature): string {
  return JSON.stringify(sig, null, 2);
}
