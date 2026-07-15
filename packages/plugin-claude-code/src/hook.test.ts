// Tests for scripts/hook.mjs - the ContextLock Claude Code hook wrapper.
//
// These exercise the wrapper as a real child process with fixture stdin JSON.
// They deliberately do NOT import or build @contextlock/cli-user: resolution is
// forced to fail (via an isolated CLAUDE_PLUGIN_ROOT and an empty PATH) or
// short-circuited with CONTEXTLOCK_CLI pointing at a tiny fake CLI we write at
// runtime. Nothing here depends on the cli-user dist build.
//
// This file lives under src/ so the root vitest include glob
// ("packages/*/src/**/*.test.ts") picks it up without editing vitest.config.ts.

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const HOOK = join(here, "..", "scripts", "hook.mjs");

// A tiny fake CLI. It reads stdin, echoes the tool_name back inside a canned
// PreToolUse deny response, and exits with FIXTURE_EXIT (default 0). This lets
// us assert that the wrapper (a) piped stdin through and (b) forwarded stdout
// and the exit code verbatim.
const FAKE_CLI = `import { readFileSync } from "node:fs";
let input = "";
try { input = readFileSync(0, "utf8"); } catch {}
let toolName = "";
try { toolName = JSON.parse(input).tool_name || ""; } catch {}
process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "FAKE-CLI denied " + toolName,
  },
}));
process.exit(Number(process.env.FIXTURE_EXIT || "0"));
`;

let workDir: string;
let isolatedPluginRoot: string;
let fakeCliPath: string;

beforeAll(() => {
  workDir = mkdtempSync(join(tmpdir(), "contextlock-hooktest-"));
  // An isolated dir with no node_modules anywhere above it, used as
  // CLAUDE_PLUGIN_ROOT so @contextlock/cli-user resolution fails deterministically.
  isolatedPluginRoot = mkdtempSync(join(tmpdir(), "contextlock-iso-"));
  fakeCliPath = join(workDir, "fake-cli.mjs");
  writeFileSync(fakeCliPath, FAKE_CLI, "utf8");
});

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
  rmSync(isolatedPluginRoot, { recursive: true, force: true });
});

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runHook(
  event: string,
  opts: { input?: string; env?: Record<string, string | undefined> } = {},
): RunResult {
  // Build an env where the CLI is unresolvable unless the test opts in.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) env[k] = v;
  }
  delete env.CONTEXTLOCK_CLI;
  delete env.CONTEXTLOCK_STRICT;
  // Isolate CLI resolution by default.
  env.CLAUDE_PLUGIN_ROOT = isolatedPluginRoot;
  env.PATH = "";
  env.Path = "";
  env.NODE_PATH = "";
  // Apply per-test overrides (may re-enable resolution).
  if (opts.env) {
    for (const [k, v] of Object.entries(opts.env)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
  }

  const res = spawnSync(process.execPath, [HOOK, event], {
    input: opts.input ?? "",
    encoding: "utf8",
    env,
  });
  return { status: res.status, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

describe("hook.mjs wrapper", () => {
  it("(a) fails open with exit 0 and the stderr marker when the CLI cannot be found", () => {
    const res = runHook("pre-tool-use", {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Read" }),
    });
    expect(res.status).toBe(0);
    expect(res.stderr).toContain("[ContextLock] hook could not run");
    expect(res.stderr).toContain("npm install && npm run build");
    // Fail-open must NOT emit a permission decision.
    expect(res.stdout).toBe("");
  });

  it("(b) with CONTEXTLOCK_STRICT=1 and no CLI, pre-tool-use emits a deny JSON on stdout (exit 0)", () => {
    const res = runHook("pre-tool-use", {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Edit" }),
      env: { CONTEXTLOCK_STRICT: "1" },
    });
    expect(res.status).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(parsed.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(parsed.hookSpecificOutput.permissionDecisionReason).toContain(
      "strict mode",
    );
  });

  it("(b2) with CONTEXTLOCK_STRICT=1 and no CLI, session-start warns via additionalContext (no block)", () => {
    const res = runHook("session-start", {
      input: JSON.stringify({ hook_event_name: "SessionStart", source: "startup" }),
      env: { CONTEXTLOCK_STRICT: "1" },
    });
    expect(res.status).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(parsed.hookSpecificOutput.additionalContext).toContain("WARNING");
    expect(parsed.hookSpecificOutput.permissionDecision).toBeUndefined();
  });

  it("(c) forwards the resolved CLI's stdout and exit code verbatim, piping stdin through", () => {
    const res = runHook("pre-tool-use", {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Skill" }),
      env: { CONTEXTLOCK_CLI: fakeCliPath, FIXTURE_EXIT: "2" },
    });
    // Exit code forwarded verbatim (fixture exits 2).
    expect(res.status).toBe(2);
    // stdout forwarded verbatim, and tool_name proves stdin was piped through.
    const expected = JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: "FAKE-CLI denied Skill",
      },
    });
    expect(res.stdout).toBe(expected);
  });
});
