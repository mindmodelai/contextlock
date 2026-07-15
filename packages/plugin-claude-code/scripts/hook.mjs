#!/usr/bin/env node
// ContextLock - Claude Code hook wrapper.
//
// This is a thin, dependency-free (node builtins only) shim. It:
//   1. reads the Claude Code hook JSON from stdin,
//   2. resolves the ContextLock user CLI (@contextlock/cli-user),
//   3. spawns it as `node <binpath> hook <event>`, piping stdin through,
//   4. forwards the CLI's stdout and exit code verbatim.
//
// Windows-safe: the CLI is always launched with the current node executable
// (process.execPath). We never rely on shebangs, .cmd shims, or a shell.
//
// Fail-open by default: if the CLI cannot be resolved or fails to spawn, the
// hook exits 0 and prints a single diagnostic line to stderr, so a broken or
// unbuilt install never blocks the user. Set CONTEXTLOCK_STRICT=1 to fail
// closed instead (deny on pre-tool-use, warn via additionalContext on
// session-start).

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, realpathSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, delimiter } from "node:path";

const MARKER =
  "[ContextLock] hook could not run (CLI not found or not built - run npm install && npm run build):";

const event = process.argv[2] || "";
const strict = process.env.CONTEXTLOCK_STRICT === "1";

// ---------------------------------------------------------------------------
// Read stdin fully (synchronous, no stream plumbing, no dependencies).
// ---------------------------------------------------------------------------
function readStdin() {
  try {
    return readFileSync(0);
  } catch {
    return Buffer.alloc(0);
  }
}

// ---------------------------------------------------------------------------
// Resolve the ContextLock CLI to a JS entry file we can run with node.
// Order: (a) CONTEXTLOCK_CLI env, (b) @contextlock/cli-user via node_modules
// resolution from the plugin dir, (c) a contextlock JS entry on PATH.
// Returns an absolute path string, or null if nothing resolved.
// ---------------------------------------------------------------------------
function resolveCliBinPath() {
  // (a) explicit override - a path to a JS bin file.
  const override = process.env.CONTEXTLOCK_CLI;
  if (override && override.trim()) {
    return override;
  }

  // (b) resolve @contextlock/cli-user by walking up node_modules from the
  //     plugin root. Works in-workspace (npm workspaces symlink) and when the
  //     package is installed alongside the plugin.
  const base =
    process.env.CLAUDE_PLUGIN_ROOT || dirname(fileURLToPath(import.meta.url));
  try {
    const req = createRequire(join(base, "package.json"));
    const pkgJsonPath = req.resolve("@contextlock/cli-user/package.json");
    const pkgDir = dirname(pkgJsonPath);
    const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));

    let rel;
    if (typeof pkg.bin === "string") {
      rel = pkg.bin;
    } else if (pkg.bin && typeof pkg.bin === "object") {
      rel = pkg.bin.contextlock || Object.values(pkg.bin)[0];
    }

    const candidates = [];
    if (rel) candidates.push(resolve(pkgDir, rel));
    // Contract fallbacks in case the bin field is not declared yet.
    candidates.push(resolve(pkgDir, "bin/contextlock.mjs"));
    candidates.push(resolve(pkgDir, "dist/index.js"));

    for (const candidate of candidates) {
      if (existsSync(candidate)) return candidate;
    }
  } catch {
    // Not resolvable - fall through to PATH.
  }

  // (c) a contextlock JS entry on PATH (last resort).
  const onPath = findContextlockOnPath();
  if (onPath) return onPath;

  return null;
}

function findContextlockOnPath() {
  const pathVar = process.env.PATH || process.env.Path || "";
  if (!pathVar) return null;
  // We deliberately look only for JS entries (or POSIX symlinks to them), not
  // .cmd/.ps1/.exe shims, because we always launch via `node <binpath>`.
  const names = ["contextlock.mjs", "contextlock.js", "contextlock.cjs", "contextlock"];
  for (const dir of pathVar.split(delimiter)) {
    if (!dir) continue;
    for (const name of names) {
      const p = join(dir, name);
      try {
        if (!statSync(p).isFile()) continue;
      } catch {
        continue;
      }
      let real = p;
      try {
        real = realpathSync(p);
      } catch {
        // keep p
      }
      if (/\.(mjs|js|cjs)$/i.test(real)) return real;
      // Extension-less: accept only a node-shebang script.
      try {
        const head = readFileSync(real, "utf8").slice(0, 128);
        const firstLine = head.split("\n")[0];
        if (firstLine.startsWith("#!") && /node/.test(firstLine)) return real;
      } catch {
        // unreadable - skip
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Strict-mode fallbacks when the CLI is unavailable.
// ---------------------------------------------------------------------------
function emitStrictAndExit(detail) {
  if (event === "pre-tool-use") {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason:
            "ContextLock verification is unavailable and strict mode is enabled (CONTEXTLOCK_STRICT=1): " +
            detail,
        },
      }),
    );
  } else {
    // session-start (and anything else): warn, never block.
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "SessionStart",
          additionalContext:
            "[ContextLock] WARNING: verification is unavailable and strict mode is enabled. " +
            "Protected instruction files were NOT verified this session: " +
            detail,
        },
      }),
    );
  }
  process.exit(0);
}

function failOpenAndExit(detail) {
  process.stderr.write(MARKER + " " + detail + "\n");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
const stdin = readStdin();
const binPath = resolveCliBinPath();

if (!binPath) {
  const detail =
    "could not resolve @contextlock/cli-user or a contextlock binary on PATH";
  if (strict) emitStrictAndExit(detail);
  failOpenAndExit(detail);
}

const result = spawnSync(process.execPath, [binPath, "hook", event], {
  input: stdin,
  stdio: ["pipe", "inherit", "inherit"],
  windowsHide: true,
});

if (result.error) {
  const detail = String((result.error && result.error.message) || result.error);
  if (strict) emitStrictAndExit(detail);
  failOpenAndExit(detail);
}

process.exit(result.status == null ? 0 : result.status);
