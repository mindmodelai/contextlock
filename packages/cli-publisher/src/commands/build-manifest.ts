/**
 * build-manifest command - Scan a directory and build a contextlock/2 manifest.
 *
 * SPEC v2 6.1: each covered file is normalized ON DISK (UTF-8, LF, no BOM) at
 * sign time, then hashed over the resulting exact bytes.
 * SPEC v2 6.7: every covered file is scanned by the content lints; a hit
 * BLOCKS the build unless the rule is explicitly allowed, and the resulting
 * attestation is recorded in the manifest's `lints` field.
 */

import { readFile, writeFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  findProtectedFiles,
  computeFileHash,
  normalizeFileOnDisk,
  lintContent,
  buildLintAttestation,
  DEFAULT_PATTERNS,
  serializeManifest,
  MANIFEST_SPEC_VERSION,
} from "@contextlock/core";
import type { Manifest, ManifestFileEntry, LintRule, LintHit } from "@contextlock/core";

/** Unsigned intermediate artifact; the shipped file is contextlock.dsse.json. */
export const UNSIGNED_MANIFEST_FILENAME = "contextlock.manifest.json";

const DEFAULT_VALIDITY_DAYS = 365;

export interface BuildManifestOptions {
  directory: string;
  packageName: string;
  /** Monotonic integer version (anti-rollback counter, NOT semver). */
  version: number;
  /** Human-facing version string (informational only). */
  displayVersion?: string;
  publisherName: string;
  /** Short key label (e.g. "cl-acme-2026") recorded in publisher.key_id. */
  keyId: string;
  /** ISO 8601 expiry. Defaults to now + expiresDays. */
  expiresAt?: string;
  /** Validity window in days when expiresAt is not given (default 365). */
  expiresDays?: number;
  /** Lint rules explicitly allowed despite hits (recorded in the manifest). */
  allowLints?: LintRule[];
  patterns?: string[];
  outputPath?: string;
  /** When false, the manifest is returned but not written to disk. */
  write?: boolean;
}

export interface BuildManifestResult {
  manifest: Manifest;
  /** Serialized manifest bytes - EXACTLY what should be signed. */
  manifestJson: string;
  manifestPath: string;
  fileCount: number;
  filePaths: string[];
  warning?: string;
}

/**
 * Scans a directory for protected files, normalizes and hashes them, runs the
 * content lints, and generates a contextlock/2 manifest.
 */
export async function buildManifest(options: BuildManifestOptions): Promise<BuildManifestResult> {
  const {
    directory,
    packageName,
    version,
    displayVersion,
    publisherName,
    keyId,
    patterns = DEFAULT_PATTERNS,
    outputPath,
    write = true,
  } = options;

  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error(`version must be a positive integer (anti-rollback counter), got: ${version}`);
  }

  // Find protected files
  const protectedFiles = await findProtectedFiles(directory, patterns);

  if (protectedFiles.length === 0) {
    return {
      manifest: null as unknown as Manifest,
      manifestJson: "",
      manifestPath: "",
      fileCount: 0,
      filePaths: [],
      warning: "No files matching protected patterns found in directory",
    };
  }

  // Build file entries. SPEC v2 6.1: normalize each file on disk (UTF-8, LF,
  // no BOM) at sign time, THEN hash the resulting exact bytes.
  const files: ManifestFileEntry[] = [];
  const rewritten: string[] = [];
  const hitsByFile = new Map<string, LintHit[]>();
  for (const relPath of protectedFiles) {
    const fullPath = join(directory, relPath);
    const normalizedPath = relPath.replace(/\\/g, "/");
    if (await normalizeFileOnDisk(fullPath)) {
      rewritten.push(normalizedPath);
    }
    const content = await readFile(fullPath);
    const hits = lintContent(content);
    if (hits.length > 0) {
      hitsByFile.set(normalizedPath, hits);
    }
    const hash = await computeFileHash(fullPath);
    const fileStat = await stat(fullPath);
    files.push({
      path: normalizedPath,
      sha256: hash,
      length: fileStat.size,
    });
  }

  // SPEC v2 6.7: block on lint hits unless explicitly allowed; always attest.
  const lints = buildLintAttestation(hitsByFile, new Set(options.allowLints ?? []));

  const warnings: string[] = [];
  if (rewritten.length > 0) {
    warnings.push(`Normalized to UTF-8/LF/no-BOM before hashing: ${rewritten.join(", ")}`);
  }
  if (!existsSync(join(directory, ".gitattributes"))) {
    warnings.push(
      'No .gitattributes found - add "*.md text eol=lf" so git checkout does not undo LF normalization (SPEC v2 6.1)',
    );
  }
  for (const w of warnings) {
    console.warn(`[ContextLock] ${w}`);
  }

  const expiresAt =
    options.expiresAt ??
    new Date(Date.now() + (options.expiresDays ?? DEFAULT_VALIDITY_DAYS) * 24 * 60 * 60 * 1000).toISOString();

  const manifest: Manifest = {
    spec_version: MANIFEST_SPEC_VERSION,
    package: packageName,
    version,
    ...(displayVersion ? { display_version: displayVersion } : {}),
    publisher: {
      name: publisherName,
      key_id: keyId,
    },
    published_at: new Date().toISOString(),
    expires_at: expiresAt,
    files,
    lints,
  };

  const manifestJson = serializeManifest(manifest);
  const manifestPath = outputPath ?? join(directory, UNSIGNED_MANIFEST_FILENAME);
  if (write) {
    await writeFile(manifestPath, manifestJson, "utf-8");
  }

  return {
    manifest,
    manifestJson,
    manifestPath: write ? manifestPath : "",
    fileCount: files.length,
    filePaths: protectedFiles.map((p) => p.replace(/\\/g, "/")),
    warning: warnings.length > 0 ? warnings.join("; ") : undefined,
  };
}
