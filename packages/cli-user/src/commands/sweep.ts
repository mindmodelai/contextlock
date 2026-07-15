/**
 * sweep command - SPEC v2 Layer 2 (session-start sweep).
 *
 * `contextlock sweep [--root <dir>] [--json] [--quarantine]`
 *
 * Verifies every protected-class file under root AND the user-scope file
 * ~/.claude/CLAUDE.md if it exists. A "violation" is any file whose verdict
 * blocks under the balanced policy (modified, revoked, error,
 * seal-store-unavailable). With --quarantine, each violating file is moved to
 * `~/.contextlock/quarantine/<timestamp>/<name>` and a plain-text placeholder is
 * written in its place. Exit 3 if any violation (handled by the CLI entry).
 */

import { resolve, join, basename } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";
import { mkdir, rename, writeFile } from "node:fs/promises";
import {
  VerificationEngine,
  DEFAULT_PATTERNS,
  findProtectedFiles,
  isProtectedFile,
  evaluatePolicy,
  contextlockHome,
} from "@contextlock/core";
import type { VerificationResult } from "@contextlock/core";

export interface SweepOptions {
  root?: string;
  trustStorePath?: string;
  quarantine?: boolean;
  policyLevel?: "strict" | "balanced" | "audit";
}

export interface SweepFileResult {
  file: string; // absolute path
  status: string;
  reason?: string;
  quarantinedTo?: string;
}

export interface SweepResult {
  root: string;
  results: SweepFileResult[];
  /** Files that verified positively (sealed, sealed+trusted, or trusted). */
  verified: number;
  violations: number;
  violationFiles: SweepFileResult[];
}

const VERIFIED_STATUSES: ReadonlySet<string> = new Set([
  "sealed",
  "sealed+trusted",
  "trusted",
]);

/** Default trust store lives in the ContextLock home (SPEC v2 8). */
export function defaultTrustStorePath(): string {
  return join(contextlockHome(), "truststore.json");
}

/** A violation is anything the balanced policy would block. */
function isViolation(status: VerificationResult["status"]): boolean {
  return evaluatePolicy({ level: "balanced", verificationResult: { status } }) === "block";
}

function quarantinePlaceholder(quarantinedTo: string, time: string): string {
  return (
    `[ContextLock] This file failed integrity verification and was quarantined to ` +
    `${quarantinedTo} at ${time}. Run contextlock status for details.\n`
  );
}

export async function sweepCommand(options: SweepOptions = {}): Promise<SweepResult> {
  const root = resolve(options.root ?? process.cwd());
  const trustStorePath = options.trustStorePath ?? defaultTrustStorePath();
  const policyLevel = options.policyLevel ?? "balanced";

  const engine = new VerificationEngine({
    trustStorePath,
    cachePath: "",
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel,
  });

  // Collect targets: protected files under root + the user-scope CLAUDE.md.
  const rel = await findProtectedFiles(root, DEFAULT_PATTERNS);
  const targets = new Set(rel.map((r) => resolve(join(root, r))));

  const userClaude = join(homedir(), ".claude", "CLAUDE.md");
  if (existsSync(userClaude) && isProtectedFile(userClaude, DEFAULT_PATTERNS)) {
    targets.add(resolve(userClaude));
  }

  const results: SweepFileResult[] = [];
  const violationFiles: SweepFileResult[] = [];
  let verified = 0;

  for (const abs of targets) {
    const verdict = await engine.verify(abs);
    const row: SweepFileResult = { file: abs, status: verdict.status, reason: verdict.reason };

    if (isViolation(verdict.status)) {
      if (options.quarantine) {
        try {
          row.quarantinedTo = await quarantineFile(abs);
        } catch (e) {
          row.reason = `${row.reason ?? verdict.status}; quarantine failed: ${(e as Error).message}`;
        }
      }
      violationFiles.push(row);
    } else if (VERIFIED_STATUSES.has(verdict.status)) {
      verified++;
    }

    results.push(row);
  }

  return {
    root,
    results,
    verified,
    violations: violationFiles.length,
    violationFiles,
  };
}

/**
 * Moves a violating file to ~/.contextlock/quarantine/<timestamp>/<name> and
 * writes a plain-text placeholder in its place. Returns the quarantine path.
 * The timestamp directory sanitizes ':' and '.' so it is filesystem-safe on
 * Windows while remaining an ISO-derived, human-readable stamp.
 */
async function quarantineFile(filePath: string): Promise<string> {
  const now = new Date();
  const iso = now.toISOString();
  const stamp = iso.replace(/[:.]/g, "-");
  const dir = join(contextlockHome(), "quarantine", stamp);
  await mkdir(dir, { recursive: true });
  const dest = join(dir, basename(filePath));
  await rename(filePath, dest);
  await writeFile(filePath, quarantinePlaceholder(dest, iso), "utf-8");
  return dest;
}
