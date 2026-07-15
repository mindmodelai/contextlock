// User CLI Mode 0 commands: seal / reseal / unseal / status / sweep.
// Covers SPEC v2 5 (Mode 0) and the sweep exit-code contract
// (0 = ok, 3 = violations, 2 = operational error) via runCli.
//
// CONTEXTLOCK_HOME and the OS home dir (USERPROFILE/HOME) are pointed at temp
// dirs so neither the real ~/.contextlock nor ~/.claude is ever touched.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SealStore, contextlockHome } from "@contextlock/core";
import { sealCommand } from "./seal.js";
import { statusCommand } from "./status.js";
import { sweepCommand } from "./sweep.js";
import { runCli } from "../index.js";

let homeDir: string;
let osHome: string;
let rootDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(async () => {
  savedEnv = {
    CONTEXTLOCK_HOME: process.env.CONTEXTLOCK_HOME,
    USERPROFILE: process.env.USERPROFILE,
    HOME: process.env.HOME,
  };
  homeDir = await mkdtemp(join(tmpdir(), "cl-cli-home-"));
  osHome = await mkdtemp(join(tmpdir(), "cl-cli-oshome-"));
  rootDir = await mkdtemp(join(tmpdir(), "cl-cli-root-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
  // Redirect the user scope (~/.claude/CLAUDE.md) into the sandbox.
  process.env.USERPROFILE = osHome;
  process.env.HOME = osHome;
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

describe("seal / reseal / unseal commands", () => {
  it("seals explicit paths and status reports them sealed", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# memory\n", "utf-8");

    const result = await sealCommand({ paths: [filePath], note: "reviewed" });
    expect(result.sealed).toHaveLength(1);
    expect(result.errors).toHaveLength(0);

    const status = await statusCommand({ root: rootDir });
    expect(status.rows).toHaveLength(1);
    expect(status.rows[0].file).toBe("CLAUDE.md");
    expect(status.rows[0].state).toBe("sealed");
    expect(status.rows[0].sealed_at).toBeDefined();
  });

  it("seal --all seals every protected-class file under root, including AGENTS.md and .claude/rules", async () => {
    await writeFile(join(rootDir, "CLAUDE.md"), "# a\n", "utf-8");
    await writeFile(join(rootDir, "AGENTS.md"), "# b\n", "utf-8");
    await mkdir(join(rootDir, ".claude", "rules"), { recursive: true });
    await writeFile(join(rootDir, ".claude", "rules", "style.md"), "# rule\n", "utf-8");
    await writeFile(join(rootDir, "README.md"), "# not protected\n", "utf-8");

    const result = await sealCommand({ all: true, root: rootDir });
    expect(result.errors).toHaveLength(0);
    const sealedNames = result.sealed.map((s) => s.path.toLowerCase());
    expect(sealedNames).toHaveLength(3);
    expect(sealedNames.some((p) => p.endsWith("claude.md"))).toBe(true);
    expect(sealedNames.some((p) => p.endsWith("agents.md"))).toBe(true);
    expect(sealedNames.some((p) => p.includes("rules"))).toBe(true);
    expect(sealedNames.some((p) => p.includes("readme"))).toBe(false);
  });

  it("unseal removes the seal; reseal re-approves changed content", async () => {
    const filePath = join(rootDir, "SKILL.md");
    await writeFile(filePath, "v1\n", "utf-8");
    await sealCommand({ paths: [filePath] });

    // Edit then reseal: state returns to sealed.
    await writeFile(filePath, "v2 - intended edit\n", "utf-8");
    let status = await statusCommand({ root: rootDir });
    expect(status.rows[0].state).toBe("seal-modified");

    await sealCommand({ action: "reseal", paths: [filePath] });
    status = await statusCommand({ root: rootDir });
    expect(status.rows[0].state).toBe("sealed");

    // Unseal: state becomes unsealed.
    const un = await sealCommand({ action: "unseal", paths: [filePath] });
    expect(un.unsealed).toHaveLength(1);
    status = await statusCommand({ root: rootDir });
    expect(status.rows[0].state).toBe("unsealed");
  });

  it("reports a corrupt seal store as unavailable (exit 2 through runCli)", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# x\n", "utf-8");
    await sealCommand({ paths: [filePath] });

    // Corrupt the store.
    const store = new SealStore();
    await writeFile(store.path, "{broken", "utf-8");

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const code = await runCli(["seal", filePath]);
      expect(code).toBe(2);
    } finally {
      logSpy.mockRestore();
      errSpy.mockRestore();
    }
  });
});

describe("sweep command and exit codes", () => {
  it("exit 0 when all protected files are sealed and intact", async () => {
    await writeFile(join(rootDir, "CLAUDE.md"), "# ok\n", "utf-8");
    await sealCommand({ all: true, root: rootDir });

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const code = await runCli(["sweep", "--root", rootDir]);
      expect(code).toBe(0);
    } finally {
      logSpy.mockRestore();
    }
  });

  it("exit 3 when a sealed file was tampered with", async () => {
    const filePath = join(rootDir, "CLAUDE.md");
    await writeFile(filePath, "# original\n", "utf-8");
    await sealCommand({ paths: [filePath] });
    await writeFile(filePath, "# original\nINJECTED\n", "utf-8");

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const code = await runCli(["sweep", "--root", rootDir, "--json"]);
      expect(code).toBe(3);
    } finally {
      logSpy.mockRestore();
    }
  });

  it("includes the user-scope ~/.claude/CLAUDE.md when it exists", async () => {
    await mkdir(join(osHome, ".claude"), { recursive: true });
    const userClaude = join(osHome, ".claude", "CLAUDE.md");
    await writeFile(userClaude, "# user scope\n", "utf-8");
    await sealCommand({ paths: [userClaude] });
    await writeFile(userClaude, "# user scope\nPERSISTED INJECTION\n", "utf-8");

    const result = await sweepCommand({ root: rootDir });
    const hit = result.results.find((r) => r.file.toLowerCase() === userClaude.toLowerCase());
    expect(hit).toBeDefined();
    expect(hit!.status).toBe("modified");
    expect(result.violations).toBe(1);
  });

  it("--quarantine moves the violating file and writes a placeholder", async () => {
    const filePath = join(rootDir, "SKILL.md");
    await writeFile(filePath, "# safe\n", "utf-8");
    await sealCommand({ paths: [filePath] });
    await writeFile(filePath, "# tampered\n", "utf-8");

    const result = await sweepCommand({ root: rootDir, quarantine: true });
    expect(result.violations).toBe(1);
    const v = result.violationFiles[0];
    expect(v.quarantinedTo).toBeDefined();
    expect(v.quarantinedTo!.startsWith(join(contextlockHome(), "quarantine"))).toBe(true);
    expect(existsSync(v.quarantinedTo!)).toBe(true);

    // Quarantined copy holds the tampered content; placeholder replaces it.
    expect(await readFile(v.quarantinedTo!, "utf-8")).toBe("# tampered\n");
    const placeholder = await readFile(filePath, "utf-8");
    expect(placeholder).toContain("[ContextLock]");
    expect(placeholder).toContain("failed integrity verification");
    expect(placeholder).toContain(v.quarantinedTo!);
    expect(placeholder).toContain("Run contextlock status for details.");
  });

  it("unsealed (untrusted) files are not violations: exit 0", async () => {
    await writeFile(join(rootDir, "CLAUDE.md"), "# never sealed\n", "utf-8");
    const result = await sweepCommand({ root: rootDir });
    expect(result.violations).toBe(0);
    expect(result.results[0].status).toBe("untrusted");
  });
});
