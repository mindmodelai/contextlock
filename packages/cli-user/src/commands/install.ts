/**
 * install command — Layer 1 enforcement (SPEC v2 7.2): verify a package
 * BEFORE placing its files into a destination directory.
 *
 * The whole package is verified first (envelope signature against the trust
 * store, contextlock/2 schema, anti-rollback, expiry, every listed file's
 * length and hash). Only if EVERYTHING passes are the listed files plus the
 * envelope copied into the destination. On any failure nothing is written.
 *
 * This closes the TOCTOU gap that verify-at-load alone leaves open:
 * verify-at-install plus write-deny (Layer 3) covers the window between.
 */

import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import {
  VerificationEngine,
  DEFAULT_PATTERNS,
  ENVELOPE_FILENAME,
} from "@contextlock/core";
import type { PackageVerificationResult, PolicyLevel } from "@contextlock/core";

export interface InstallOptions {
  /** Source package directory (must contain contextlock.dsse.json). */
  source: string;
  /** Destination directory. Created if missing. */
  dest: string;
  trustStorePath: string;
  stateStorePath?: string;
  policyLevel?: PolicyLevel;
}

export interface InstallResult {
  installed: boolean;
  verification: PackageVerificationResult;
  /** Destination-relative paths written (files + envelope), when installed. */
  written: string[];
}

export async function install(options: InstallOptions): Promise<InstallResult> {
  const source = resolve(options.source);
  const dest = resolve(options.dest);

  const engine = new VerificationEngine({
    trustStorePath: options.trustStorePath,
    cachePath: "",
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel: options.policyLevel ?? "strict",
    stateStorePath: options.stateStorePath,
  });

  // Verify EVERYTHING before writing anything (Layer 1).
  const verification = await engine.verifyPackage(source);
  if (!verification.ok) {
    return { installed: false, verification, written: [] };
  }

  const written: string[] = [];
  await mkdir(dest, { recursive: true });
  for (const entry of verification.manifest!.files) {
    const from = join(source, entry.path);
    const to = join(dest, entry.path);
    await mkdir(dirname(to), { recursive: true });
    await copyFile(from, to);
    written.push(entry.path);
  }
  await copyFile(join(source, ENVELOPE_FILENAME), join(dest, ENVELOPE_FILENAME));
  written.push(ENVELOPE_FILENAME);

  return { installed: true, verification, written };
}
