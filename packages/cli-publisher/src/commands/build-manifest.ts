/**
 * build-manifest command - Scan directory and build manifest.json.
 * Requirements: 11.1, 11.2, 11.3, 11.4, 11.5
 */

import { writeFile, stat } from "node:fs/promises";
import { join } from "node:path";
import {
  findProtectedFiles,
  computeFileHash,
  normalizeFileOnDisk,
  DEFAULT_PATTERNS,
  serializeManifest,
} from "@contextlock/core";
import type { Manifest, ManifestFileEntry } from "@contextlock/core";

export interface BuildManifestOptions {
  directory: string;
  packageName: string;
  version: string;
  publisherName: string;
  keyId: string;
  fingerprint: string;
  patterns?: string[];
  outputPath?: string;
}

export interface BuildManifestResult {
  manifest: Manifest;
  manifestPath: string;
  fileCount: number;
  filePaths: string[];
  warning?: string;
}

/**
 * Scans a directory for protected files, computes hashes, and generates manifest.json.
 */
export async function buildManifest(options: BuildManifestOptions): Promise<BuildManifestResult> {
  const {
    directory,
    packageName,
    version,
    publisherName,
    keyId,
    fingerprint,
    patterns = DEFAULT_PATTERNS,
    outputPath,
  } = options;

  // Find protected files
  const protectedFiles = await findProtectedFiles(directory, patterns);

  if (protectedFiles.length === 0) {
    return {
      manifest: null as unknown as Manifest,
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
  for (const relPath of protectedFiles) {
    const fullPath = join(directory, relPath);
    const normalizedPath = relPath.replace(/\\/g, "/");
    if (await normalizeFileOnDisk(fullPath)) {
      rewritten.push(normalizedPath);
    }
    const hash = await computeFileHash(fullPath);
    const fileStat = await stat(fullPath);
    files.push({
      path: normalizedPath,
      sha256: hash,
      size: fileStat.size,
    });
  }

  let normalizationWarning: string | undefined;
  if (rewritten.length > 0) {
    normalizationWarning =
      `Normalized to UTF-8/LF/no-BOM before hashing: ${rewritten.join(", ")}`;
    console.warn(`[ContextLock] ${normalizationWarning}`);
  }

  const manifest: Manifest = {
    schema: "tcv-manifest/v1",
    package: packageName,
    version,
    publisher: {
      name: publisherName,
      key_id: keyId,
      public_key_fingerprint: fingerprint,
    },
    published_at: new Date().toISOString(),
    files,
  };

  const manifestPath = outputPath ?? join(directory, "manifest.json");
  const json = serializeManifest(manifest);
  await writeFile(manifestPath, json, "utf-8");

  return {
    manifest,
    manifestPath,
    fileCount: files.length,
    filePaths: protectedFiles.map((p) => p.replace(/\\/g, "/")),
    warning: normalizationWarning,
  };
}
