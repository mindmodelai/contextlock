/**
 * Protected File Detector - matches file paths against glob patterns.
 * Requirements: 6.1, 6.2, 6.3, 6.4
 */

import { minimatch } from "minimatch";
import { readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";

/**
 * Default glob patterns for protected files (SPEC v2 section 10 file classes).
 */
export const DEFAULT_PATTERNS: string[] = [
  "**/SKILL.md",
  "**/CLAUDE.md",
  "**/AGENTS.md",
  "**/RULES.md",
  "**/.claude/rules/*.md",
  "**/*.prompt.md",
  "**/*.policy.md",
];

/**
 * Returns true if the given file path matches at least one of the glob patterns.
 */
export function isProtectedFile(filePath: string, patterns: string[]): boolean {
  // Normalize backslashes to forward slashes for cross-platform matching
  const normalized = filePath.replace(/\\/g, "/");
  return patterns.some((pattern) => minimatch(normalized, pattern, { dot: true }));
}

/**
 * Recursively scans a directory and returns relative paths of files
 * that match at least one of the given glob patterns.
 */
export async function findProtectedFiles(
  directory: string,
  patterns: string[],
): Promise<string[]> {
  const results: string[] = [];
  await walk(directory, directory, patterns, results);
  return results.sort();
}

async function walk(
  root: string,
  current: string,
  patterns: string[],
  results: string[],
): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(current, entry.name);
    if (entry.isDirectory()) {
      await walk(root, fullPath, patterns, results);
    } else if (entry.isFile()) {
      const rel = relative(root, fullPath);
      if (isProtectedFile(rel, patterns)) {
        results.push(rel);
      }
    }
  }
}
