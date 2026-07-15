/**
 * Claude Code hook entry points - SPEC v2 Layer 2 & 3.
 *
 * `contextlock hook session-start`   (SessionStart: sweep + additionalContext)
 * `contextlock hook pre-tool-use`    (PreToolUse: deny reads/edits of tampered
 *                                     protected files, and self-protect state)
 *
 * Field names verified against the Claude Code hooks docs (code.claude.com,
 * 2026-07-14): input carries `cwd`, `tool_name`, `tool_input`; SessionStart
 * output is `{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext}}`;
 * PreToolUse output is `{hookSpecificOutput:{hookEventName:"PreToolUse",
 * permissionDecision,permissionDecisionReason}}`.
 *
 * Error policy: if the hook logic throws, fail OPEN (allow) with a loud stderr
 * warning, UNLESS env CONTEXTLOCK_STRICT=1, in which case fail CLOSED (deny).
 */

import { resolve, basename, join, sep } from "node:path";
import { existsSync, statSync } from "node:fs";
import {
  VerificationEngine,
  DEFAULT_PATTERNS,
  isProtectedFile,
  contextlockHome,
} from "@contextlock/core";
import { sweepCommand, defaultTrustStorePath } from "./sweep.js";

// ---- SessionStart ----

export interface SessionStartInput {
  cwd?: string;
  hook_event_name?: string;
  source?: string;
  [k: string]: unknown;
}

export interface SessionStartHookResult {
  hookSpecificOutput: {
    hookEventName: "SessionStart";
    additionalContext: string;
  };
  report: { verified: number; modified: string[]; unsealed: number };
}

export async function hookSessionStart(
  input: SessionStartInput,
): Promise<SessionStartHookResult> {
  try {
    const root = input.cwd ? resolve(input.cwd) : process.cwd();
    const sweep = await sweepCommand({ root });

    const modified = sweep.results.filter((r) => r.status === "modified");
    const unsealed = sweep.results.filter((r) => r.status === "untrusted");
    const verified = sweep.results.filter((r) =>
      ["sealed", "sealed+trusted", "trusted"].includes(r.status),
    );

    const modifiedList =
      modified.length > 0
        ? ` (${modified.map((m) => basename(m.file)).join(", ")})`
        : "";
    const additionalContext =
      `ContextLock integrity report: ${verified.length} verified, ` +
      `${modified.length} modified${modifiedList}, ` +
      `${unsealed.length} unsealed protected files under ${root}.`;

    return {
      hookSpecificOutput: { hookEventName: "SessionStart", additionalContext },
      report: {
        verified: verified.length,
        modified: modified.map((m) => m.file),
        unsealed: unsealed.length,
      },
    };
  } catch (e) {
    // SessionStart never blocks; report the failure as context.
    const msg = `ContextLock sweep could not complete: ${(e as Error).message}`;
    console.error(`[ContextLock] ${msg}`);
    return {
      hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: msg },
      report: { verified: 0, modified: [], unsealed: 0 },
    };
  }
}

// ---- PreToolUse ----

export interface PreToolUseInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
  [k: string]: unknown;
}

export interface PreToolUseHookResult {
  decision: "allow" | "deny";
  reason?: string;
  /** Present only on deny. An explicit "allow" decision would auto-approve the
   * tool call and bypass Claude Code's normal permission prompt; a verification
   * layer must never widen permissions, so on allow the hook emits nothing and
   * the standard permission flow proceeds. */
  hookOutput?: {
    hookSpecificOutput: {
      hookEventName: "PreToolUse";
      permissionDecision: "deny";
      permissionDecisionReason?: string;
    };
  };
}

function preToolResult(
  decision: "allow" | "deny",
  reason?: string,
): PreToolUseHookResult {
  if (decision === "deny") {
    return {
      decision,
      reason,
      hookOutput: {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: reason,
        },
      },
    };
  }
  return { decision, reason };
}

/** True if `target` resolves to a path inside the ContextLock home directory.
 * Windows paths are case-insensitive, so compare lowercased on win32. */
function isUnderContextlockHome(target: string): boolean {
  let home = resolve(contextlockHome());
  let abs = resolve(target);
  if (process.platform === "win32") {
    home = home.toLowerCase();
    abs = abs.toLowerCase();
  }
  return abs === home || abs.startsWith(home + sep);
}

/** Extract a candidate file path from a Skill tool_input, if resolvable. */
function extractSkillPath(toolInput: Record<string, unknown>): string | undefined {
  for (const key of ["skill_path", "path", "file_path", "skill", "name", "command"]) {
    const v = toolInput[key];
    if (typeof v === "string" && v.length > 0) {
      const abs = resolve(v);
      // Only treat as resolvable if it actually points at a file on disk.
      try {
        if (existsSync(abs) && statSync(abs).isFile()) {
          return abs;
        }
      } catch {
        /* not resolvable */
      }
    }
  }
  return undefined;
}

/** Test seam: lets tests inject a verifier that throws, to exercise the
 * fail-open (default) vs fail-closed (CONTEXTLOCK_STRICT=1) error policy. */
export interface PreToolUseDeps {
  verifyFile?: (path: string) => Promise<{ status: string; reason?: string }>;
}

export async function hookPreToolUse(
  input: PreToolUseInput,
  deps: PreToolUseDeps = {},
): Promise<PreToolUseHookResult> {
  try {
    const toolName = input.tool_name ?? "";
    const toolInput = input.tool_input ?? {};

    const engine = new VerificationEngine({
      trustStorePath: defaultTrustStorePath(),
      cachePath: "",
      protectedPatterns: DEFAULT_PATTERNS,
      policyLevel: "strict",
    });
    const verifyFile =
      deps.verifyFile ?? ((path: string) => engine.verify(path));

    // Determine the file this tool call targets.
    let targetPath: string | undefined;
    if (toolName === "Read" || toolName === "Edit" || toolName === "Write") {
      const fp = toolInput.file_path;
      if (typeof fp === "string" && fp.length > 0) {
        targetPath = resolve(fp);
      }
    } else if (toolName === "Skill") {
      targetPath = extractSkillPath(toolInput);
    }

    if (!targetPath) {
      // Nothing resolvable to check -> allow.
      return preToolResult("allow", "ContextLock: no verifiable target");
    }

    // (b) Self-protection: block edits/writes to ContextLock's own state.
    if (
      (toolName === "Edit" || toolName === "Write") &&
      isUnderContextlockHome(targetPath)
    ) {
      return preToolResult(
        "deny",
        `ContextLock self-protection: writing to ${contextlockHome()} is not allowed.`,
      );
    }

    // (a) Block tampered protected-class files.
    if (isProtectedFile(targetPath, DEFAULT_PATTERNS)) {
      const result = await verifyFile(targetPath);
      if (
        result.status === "modified" ||
        result.status === "seal-modified" ||
        result.status === "seal-store-unavailable"
      ) {
        return preToolResult(
          "deny",
          `ContextLock blocked ${basename(targetPath)}: ${result.status}` +
            (result.reason ? ` - ${result.reason}` : ""),
        );
      }
    }

    return preToolResult("allow", "ContextLock: verification passed");
  } catch (e) {
    const strict = process.env.CONTEXTLOCK_STRICT === "1";
    console.error(
      `[ContextLock] pre-tool-use hook error: ${(e as Error).message}. ` +
        `Failing ${strict ? "CLOSED (deny)" : "OPEN (allow)"}.`,
    );
    if (strict) {
      return preToolResult(
        "deny",
        "ContextLock hook error; failing closed (CONTEXTLOCK_STRICT=1).",
      );
    }
    return preToolResult("allow", "ContextLock hook error; failing open.");
  }
}
