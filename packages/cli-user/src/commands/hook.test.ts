// Claude Code hook entry points (SPEC v2 7.2 Layers 2-3).
//
// Field names asserted here match the Claude Code hooks docs (verified
// 2026-07-14): SessionStart returns hookSpecificOutput.additionalContext;
// PreToolUse returns hookSpecificOutput.permissionDecision ("allow"/"deny")
// plus permissionDecisionReason; input carries tool_name/tool_input/cwd.
//
// Covers: deny and allow cases, Skill-tool handling, self-protection of
// CONTEXTLOCK_HOME, the fail-open default and CONTEXTLOCK_STRICT=1 fail-closed
// error policy, and the stdin-JSON-driven `hook` subcommand through runCli.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Readable } from "node:stream";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { contextlockHome } from "@contextlock/core";
import { sealCommand } from "./seal.js";
import { hookSessionStart, hookPreToolUse } from "./hook.js";
import { runCli } from "../index.js";

let homeDir: string;
let osHome: string;
let rootDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(async () => {
  savedEnv = {
    CONTEXTLOCK_HOME: process.env.CONTEXTLOCK_HOME,
    CONTEXTLOCK_STRICT: process.env.CONTEXTLOCK_STRICT,
    USERPROFILE: process.env.USERPROFILE,
    HOME: process.env.HOME,
  };
  homeDir = await mkdtemp(join(tmpdir(), "cl-hook-home-"));
  osHome = await mkdtemp(join(tmpdir(), "cl-hook-oshome-"));
  rootDir = await mkdtemp(join(tmpdir(), "cl-hook-root-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
  process.env.USERPROFILE = osHome;
  process.env.HOME = osHome;
  delete process.env.CONTEXTLOCK_STRICT;
});

afterEach(async () => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const d of [homeDir, osHome, rootDir]) {
    await rm(d, { recursive: true, force: true }).catch(() => {});
  }
});

describe("hook session-start", () => {
  it("emits SessionStart additionalContext with verified/modified/unsealed counts", async () => {
    const okPath = join(rootDir, "CLAUDE.md");
    const badPath = join(rootDir, "SKILL.md");
    await writeFile(okPath, "# fine\n", "utf-8");
    await writeFile(badPath, "# was reviewed\n", "utf-8");
    await sealCommand({ paths: [okPath, badPath] });
    await writeFile(badPath, "# was reviewed\nINJECTED LINE\n", "utf-8");
    await writeFile(join(rootDir, "AGENTS.md"), "# never sealed\n", "utf-8");

    const result = await hookSessionStart({ cwd: rootDir, hook_event_name: "SessionStart" });

    expect(result.hookSpecificOutput.hookEventName).toBe("SessionStart");
    const ctx = result.hookSpecificOutput.additionalContext;
    expect(ctx).toContain("1 verified");
    expect(ctx).toContain("1 modified");
    expect(ctx).toContain("SKILL.md");
    expect(ctx).toContain("1 unsealed");
    expect(result.report.modified).toHaveLength(1);
  });

  it("never throws: internal failure is reported as context", async () => {
    // A nonexistent cwd makes findProtectedFiles fail inside the sweep.
    const result = await hookSessionStart({ cwd: join(rootDir, "does-not-exist") });
    expect(result.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(result.hookSpecificOutput.additionalContext).toContain("could not complete");
  });
});

describe("hook pre-tool-use", () => {
  it("denies Read of a tampered sealed protected file", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# reviewed\n", "utf-8");
    await sealCommand({ paths: [filePath] });
    await writeFile(filePath, "# reviewed\nEVIL\n", "utf-8");

    const result = await hookPreToolUse({
      tool_name: "Read",
      tool_input: { file_path: filePath },
    });
    expect(result.decision).toBe("deny");
    expect(result.hookOutput.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(result.hookOutput.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(result.hookOutput.hookSpecificOutput.permissionDecisionReason).toContain("modified");
  });

  it("allows Read of an intact sealed protected file", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# reviewed\n", "utf-8");
    await sealCommand({ paths: [filePath] });

    const result = await hookPreToolUse({
      tool_name: "Read",
      tool_input: { file_path: filePath },
    });
    expect(result.decision).toBe("allow");
    expect(result.hookOutput).toBeUndefined();
  });

  it("allows non-protected files without verification", async () => {
    const filePath = join(rootDir, "notes.txt");
    await writeFile(filePath, "anything\n", "utf-8");
    const result = await hookPreToolUse({
      tool_name: "Edit",
      tool_input: { file_path: filePath },
    });
    expect(result.decision).toBe("allow");
  });

  it("denies Edit/Write under CONTEXTLOCK_HOME (self-protection) but allows Read", async () => {
    const target = join(contextlockHome(), "seals.json");
    await writeFile(target, "{}", "utf-8");

    for (const tool of ["Edit", "Write"]) {
      const result = await hookPreToolUse({
        tool_name: tool,
        tool_input: { file_path: target },
      });
      expect(result.decision).toBe("deny");
      expect(result.hookOutput.hookSpecificOutput.permissionDecisionReason).toContain(
        "self-protection",
      );
    }

    const read = await hookPreToolUse({
      tool_name: "Read",
      tool_input: { file_path: target },
    });
    expect(read.decision).toBe("allow");
  });

  it("denies Skill invocation when the resolvable skill file is tampered", async () => {
    const skillDir = join(rootDir, "skills", "demo");
    await mkdir(skillDir, { recursive: true });
    const skillPath = join(skillDir, "SKILL.md");
    await writeFile(skillPath, "# demo skill\n", "utf-8");
    await sealCommand({ paths: [skillPath] });
    await writeFile(skillPath, "# demo skill\nrm -rf everything\n", "utf-8");

    const result = await hookPreToolUse({
      tool_name: "Skill",
      tool_input: { skill_path: skillPath },
    });
    expect(result.decision).toBe("deny");
  });

  it("allows Skill invocation when the skill reference is not resolvable to a file", async () => {
    const result = await hookPreToolUse({
      tool_name: "Skill",
      tool_input: { name: "some-registry-skill" },
    });
    expect(result.decision).toBe("allow");
  });

  it("denies when the seal store is tampered (store-unavailable)", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# reviewed\n", "utf-8");
    await sealCommand({ paths: [filePath] });
    // Corrupt the seal store.
    await writeFile(join(contextlockHome(), "seals.json"), "{oops", "utf-8");

    const result = await hookPreToolUse({
      tool_name: "Read",
      tool_input: { file_path: filePath },
    });
    expect(result.decision).toBe("deny");
    expect(result.hookOutput.hookSpecificOutput.permissionDecisionReason).toContain(
      "seal-store-unavailable",
    );
  });

  it("fails OPEN (allow) on internal error by default, with a loud stderr warning", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# x\n", "utf-8");

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await hookPreToolUse(
        { tool_name: "Read", tool_input: { file_path: filePath } },
        { verifyFile: async () => { throw new Error("boom"); } },
      );
      expect(result.decision).toBe("allow");
      expect(result.hookOutput).toBeUndefined();
      expect(
        errSpy.mock.calls.some((c) => String(c[0]).includes("Failing OPEN")),
      ).toBe(true);
    } finally {
      errSpy.mockRestore();
    }
  });

  it("fails CLOSED (deny) on internal error when CONTEXTLOCK_STRICT=1", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# x\n", "utf-8");
    process.env.CONTEXTLOCK_STRICT = "1";

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await hookPreToolUse(
        { tool_name: "Read", tool_input: { file_path: filePath } },
        { verifyFile: async () => { throw new Error("boom"); } },
      );
      expect(result.decision).toBe("deny");
      expect(result.hookOutput.hookSpecificOutput.permissionDecisionReason).toContain(
        "failing closed",
      );
    } finally {
      errSpy.mockRestore();
    }
  });
});

describe("hook subcommand via runCli with fixture stdin JSON", () => {
  function withStdin(json: string): () => void {
    const original = Object.getOwnPropertyDescriptor(process, "stdin")!;
    const fake = Readable.from([json]) as unknown as NodeJS.ReadStream;
    Object.defineProperty(process, "stdin", { value: fake, configurable: true });
    return () => Object.defineProperty(process, "stdin", original);
  }

  it("hook pre-tool-use reads stdin, prints deny JSON, exits 0", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# sealed\n", "utf-8");
    await sealCommand({ paths: [filePath] });
    await writeFile(filePath, "# sealed\nTAMPER\n", "utf-8");

    const fixture = JSON.stringify({
      session_id: "s1",
      cwd: rootDir,
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: filePath },
    });

    const lines: string[] = [];
    const logSpy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });
    const restore = withStdin(fixture);
    try {
      const code = await runCli(["hook", "pre-tool-use"]);
      expect(code).toBe(0);
      const out = JSON.parse(lines.join("\n"));
      expect(out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
      expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    } finally {
      restore();
      logSpy.mockRestore();
    }
  });

  it("hook session-start reads stdin, prints additionalContext JSON, exits 0", async () => {
    await writeFile(join(rootDir, "CLAUDE.md"), "# fine\n", "utf-8");
    await sealCommand({ paths: [join(rootDir, "CLAUDE.md")] });

    const fixture = JSON.stringify({
      session_id: "s2",
      cwd: rootDir,
      hook_event_name: "SessionStart",
      source: "startup",
    });

    const lines: string[] = [];
    const logSpy = vi.spyOn(console, "log").mockImplementation((line: unknown) => {
      lines.push(String(line));
    });
    const restore = withStdin(fixture);
    try {
      const code = await runCli(["hook", "session-start"]);
      expect(code).toBe(0);
      const out = JSON.parse(lines.join("\n"));
      expect(out.hookSpecificOutput.hookEventName).toBe("SessionStart");
      expect(out.hookSpecificOutput.additionalContext).toContain("1 verified");
    } finally {
      restore();
      logSpy.mockRestore();
    }
  });
});
