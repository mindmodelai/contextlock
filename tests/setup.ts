/**
 * Vitest global setup (runs once per test file / worker).
 *
 * Guarantees no test ever touches the real `~/.contextlock`: if a test file has
 * not set CONTEXTLOCK_HOME itself, point it at a unique temp directory. Also
 * skip the best-effort OS ACL tightening so tests stay fast and deterministic.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

if (!process.env.CONTEXTLOCK_HOME) {
  process.env.CONTEXTLOCK_HOME = mkdtempSync(join(tmpdir(), "cl-home-"));
}

// Do not spawn icacls / chmod during tests.
process.env.CONTEXTLOCK_SKIP_ACL = "1";
