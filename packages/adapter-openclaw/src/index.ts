/**
 * OpenClaw adapter (SPEC v2 Phase C) - maps ContextLock's enforcement layers
 * onto OpenClaw's REAL extension surface (researched 2026-07-15 against
 * OpenClaw 2026.7.1; full mapping with confirmed/unverified split in
 * docs/openclaw-surface.md):
 *
 *   Layer 1 (install-time): `security.installPolicy` - OpenClaw's operator
 *     install gate (fail-closed, covers ClawHub/git/local skills AND plugins).
 *     -> installPolicy()
 *   Layer 2 (run-start): plugin hook `before_agent_run` can hard-block a turn.
 *     -> handleBeforeAgentRun()
 *   Layer 3 (tool gate): plugin hook `before_tool_call` can hard-deny tool
 *     calls (writes to protected files; reads of failed files).
 *     -> handleBeforeToolCall()
 *
 * There is NO verify-before-context-injection hook for workspace files or
 * skill bodies in OpenClaw today: "verified" on OpenClaw means
 * verified-at-run-start plus write-denied, not verified-at-injection.
 *
 * NOTE: the hook payload shapes below follow the official plugin-hooks docs;
 * they have not yet been exercised against a live OpenClaw gateway. Treat
 * field mappings as needs-live-verification (docs/openclaw-surface.md).
 */

import { homedir } from "node:os";
import { join, resolve } from "node:path";
import {
  VerificationEngine,
  evaluatePolicy,
  findProtectedFiles,
  DEFAULT_PATTERNS,
} from "@contextlock/core";
import type {
  ToolAdapter,
  VerificationResult,
  VerificationEngineConfig,
  PolicyLevel,
  PolicyDecision,
} from "@contextlock/core";

// ---- OpenClaw file classes (docs.openclaw.ai/concepts/agent-workspace) ----

/**
 * Instruction-file classes OpenClaw injects into every session, plus the
 * config surface that can disable enforcement (the config-CVE class:
 * openclaw.json hot-reloads and controls tools.allow/deny, plugins, and
 * security.installPolicy - a config write defeats every other layer).
 */
export const OPENCLAW_PROTECTED_PATTERNS: string[] = [
  // Workspace instruction files (injected every session)
  "**/SOUL.md",
  "**/AGENTS.md",
  "**/USER.md",
  "**/IDENTITY.md",
  "**/TOOLS.md",
  "**/HEARTBEAT.md",
  "**/BOOT.md",
  "**/BOOTSTRAP.md",
  "**/MEMORY.md",
  "**/memory/*.md",
  // Skills (six discovery locations, SKILL.md up to 6 levels deep)
  "**/SKILL.md",
  // Config / automation surface
  "**/openclaw.json",
  "**/cron/jobs.json",
  "**/hooks/**/HOOK.md",
  "**/hooks/**/handler.ts",
];

/** Default OpenClaw state dir (override for profiles/tests). */
export function openclawHome(): string {
  const override = process.env.OPENCLAW_STATE_DIR;
  if (override && override.trim().length > 0) return override;
  return join(homedir(), ".openclaw");
}

/** Roots a sweep should cover: workspace(s), managed skills, hooks, config. */
export function openclawProtectedRoots(home: string = openclawHome()): string[] {
  return [join(home, "workspace"), join(home, "skills"), join(home, "hooks")];
}

// ---- Adapter config ----

export interface OpenClawAdapterConfig {
  trustStorePath: string;
  cachePath: string;
  policyLevel: PolicyLevel;
  protectedPatterns?: string[];
  /** OpenClaw state dir (default ~/.openclaw or OPENCLAW_STATE_DIR). */
  openclawHome?: string;
  /** Engine passthroughs. */
  sealStorePath?: string;
  stateStorePath?: string;
  workspaceRoot?: string;
  /**
   * Tool names treated as file WRITES for the write-deny rule. Name-based on
   * purpose: OpenClaw's tool set is pluggable, so operators can extend this.
   */
  writeToolNames?: string[];
}

const DEFAULT_WRITE_TOOLS = ["write", "edit", "append", "apply_patch", "fs_write", "save_file"];

function makeEngine(config: OpenClawAdapterConfig): VerificationEngine {
  const engineConfig: VerificationEngineConfig = {
    trustStorePath: config.trustStorePath,
    cachePath: config.cachePath,
    protectedPatterns: config.protectedPatterns ?? [
      ...OPENCLAW_PROTECTED_PATTERNS,
      ...DEFAULT_PATTERNS,
    ],
    policyLevel: config.policyLevel,
    sealStorePath: config.sealStorePath,
    stateStorePath: config.stateStorePath,
    workspaceRoot: config.workspaceRoot,
  };
  return new VerificationEngine(engineConfig);
}

// ---- Block message ----

export function formatBlockMessage(filePath: string, result: VerificationResult): string {
  switch (result.status) {
    case "modified":
      return `[ContextLock] Blocked: ${filePath} has been modified since signing (expected: ${result.expectedHash}, got: ${result.fileHash})`;
    case "untrusted":
      return `[ContextLock] Blocked: ${filePath} is untrusted — ${result.reason}`;
    case "revoked":
      return `[ContextLock] Blocked: ${filePath} was signed with a revoked key (key: ${result.keyId})`;
    case "expired":
      return `[ContextLock] Blocked: ${filePath} manifest has expired (expires_at: ${result.expiresAt})`;
    case "rollback":
      return `[ContextLock] Blocked: ${filePath} — ${result.reason}`;
    case "error":
      return `[ContextLock] Blocked: ${filePath} verification error — ${result.reason}`;
    default:
      return `[ContextLock] Blocked: ${filePath} — ${result.status}`;
  }
}

// ---- Generic ToolAdapter (engine-level; kept for host-agnostic embedding) ----

export class OpenClawAdapter implements ToolAdapter {
  private engine: VerificationEngine;
  private policyLevel: PolicyLevel;

  constructor(config: OpenClawAdapterConfig) {
    this.engine = makeEngine(config);
    this.policyLevel = config.policyLevel;
  }

  async onFileLoad(filePath: string): Promise<PolicyDecision> {
    if (!this.engine.isProtected(filePath)) {
      return "allow";
    }

    const result = await this.engine.verify(filePath);
    return evaluatePolicy({
      level: this.policyLevel,
      verificationResult: result,
    });
  }

  async getVerificationStatus(filePath: string): Promise<VerificationResult> {
    return this.engine.verify(filePath);
  }
}

// ---- Layer 3: before_tool_call (hard deny) ----

/** Subset of OpenClaw's before_tool_call payload that the adapter consumes. */
export interface BeforeToolCallInput {
  toolName?: string;
  params?: Record<string, unknown>;
  /** Filesystem paths OpenClaw derived from the tool params. */
  derivedPaths?: string[];
}

/** OpenClaw before_tool_call hook result (block is terminal). */
export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
}

/**
 * Write-deny + read-deny at the tool gate:
 *  - a WRITE tool touching a protected file whose current verification is
 *    sealed/trusted is denied (persistence attempts become visible denials -
 *    T2; deliberate updates go through reseal/install),
 *  - any tool touching a protected file whose verification the policy would
 *    BLOCK is denied (unverified content must not enter context via a tool
 *    result).
 */
export async function handleBeforeToolCall(
  input: BeforeToolCallInput,
  config: OpenClawAdapterConfig,
): Promise<BeforeToolCallResult> {
  const engine = makeEngine(config);
  const paths = (input.derivedPaths ?? []).filter((p) => engine.isProtected(p));
  if (paths.length === 0) return {};

  const writeTools = (config.writeToolNames ?? DEFAULT_WRITE_TOOLS).map((t) => t.toLowerCase());
  const isWrite = writeTools.some((t) => (input.toolName ?? "").toLowerCase().includes(t));

  for (const path of paths) {
    const result = await engine.verify(resolve(path));

    if (isWrite && ["sealed", "trusted", "sealed+trusted"].includes(result.status)) {
      return {
        block: true,
        blockReason:
          `[ContextLock] ${path} is ${result.status}; direct edits are denied. ` +
          `Reseal (contextlock reseal) or reinstall a signed release to change it.`,
      };
    }

    const decision = evaluatePolicy({
      level: config.policyLevel,
      verificationResult: result,
    });
    if (decision === "block" || decision === "quarantine") {
      return { block: true, blockReason: formatBlockMessage(path, result) };
    }
  }
  return {};
}

// ---- Layer 2: before_agent_run (hard block on a tampered workspace) ----

export interface BeforeAgentRunResult {
  outcome: "pass" | "block";
  reason?: string;
  /** Per-file verdicts for logging/telemetry. */
  violations: Array<{ file: string; status: string; reason?: string }>;
}

/**
 * Sweeps every protected-class file under the OpenClaw roots and blocks the
 * run when any fails under the configured policy. This is the OpenClaw
 * equivalent of the Claude Code SessionStart sweep - but it can actually
 * BLOCK (before_agent_run supports outcome: "block").
 */
export async function handleBeforeAgentRun(
  config: OpenClawAdapterConfig,
  roots?: string[],
): Promise<BeforeAgentRunResult> {
  const engine = makeEngine(config);
  const patterns = config.protectedPatterns ?? [
    ...OPENCLAW_PROTECTED_PATTERNS,
    ...DEFAULT_PATTERNS,
  ];
  const sweepRoots = roots ?? openclawProtectedRoots(config.openclawHome);

  const violations: BeforeAgentRunResult["violations"] = [];
  const seen = new Set<string>();

  for (const root of sweepRoots) {
    let files: string[];
    try {
      files = await findProtectedFiles(root, patterns);
    } catch {
      continue; // root does not exist - nothing to sweep
    }
    for (const rel of files) {
      const abs = resolve(join(root, rel));
      if (seen.has(abs)) continue;
      seen.add(abs);

      const result = await engine.verify(abs);
      const decision = evaluatePolicy({
        level: config.policyLevel,
        verificationResult: result,
      });
      if (decision === "block" || decision === "quarantine") {
        violations.push({ file: abs, status: result.status, reason: result.reason });
      }
    }
  }

  if (violations.length > 0) {
    return {
      outcome: "block",
      reason:
        `[ContextLock] ${violations.length} protected file(s) failed verification: ` +
        violations.map((v) => `${v.file} (${v.status})`).join(", "),
      violations,
    };
  }
  return { outcome: "pass", violations: [] };
}

// ---- Layer 1: security.installPolicy (fail-closed install gate) ----

/**
 * Input contract of OpenClaw's `security.installPolicy` command (JSON on
 * stdin). Field names follow the official docs; needs-live-verification.
 */
export interface InstallPolicyInput {
  protocolVersion?: number;
  openclawVersion?: string;
  targetType?: string;
  targetName?: string;
  /** Staged content awaiting the install decision. */
  sourcePath?: string;
}

export interface InstallPolicyDecision {
  decision: "allow" | "block";
  reason?: string;
}

/**
 * ContextLock as the operator's install policy: verify the STAGED package
 * before OpenClaw finishes the install (Layer 1 - verify before placing).
 *
 *  - signed + fully valid  -> allow
 *  - signed but failing    -> block (tamper/rollback/expiry/unknown signer)
 *  - unsigned              -> policy level decides: strict blocks, balanced
 *                             and audit allow (with the reason recorded) -
 *                             most of the ecosystem is unsigned today and
 *                             the install gate must not brick it by default.
 */
export async function installPolicy(
  input: InstallPolicyInput,
  config: OpenClawAdapterConfig,
): Promise<InstallPolicyDecision> {
  if (!input.sourcePath) {
    // Fail closed on a malformed request - this is a security gate.
    return { decision: "block", reason: "[ContextLock] no sourcePath in installPolicy input" };
  }

  const engine = makeEngine(config);
  const verdict = await engine.verifyPackage(input.sourcePath);

  if (verdict.ok) {
    return {
      decision: "allow",
      reason: `[ContextLock] verified "${verdict.manifest?.package}" v${verdict.manifest?.version} (publisher: ${verdict.publisher})`,
    };
  }

  const unsigned =
    verdict.status === "untrusted" &&
    (verdict.reason ?? "").includes("found in package directory");
  if (unsigned) {
    if (config.policyLevel === "strict") {
      return {
        decision: "block",
        reason:
          "[ContextLock] package carries no ContextLock evidence (strict policy blocks unsigned installs)",
      };
    }
    return {
      decision: "allow",
      reason:
        "[ContextLock] package is unsigned (no ContextLock evidence); allowed by non-strict policy",
    };
  }

  return {
    decision: "block",
    reason: `[ContextLock] verification failed: ${verdict.status}${verdict.reason ? ` (${verdict.reason})` : ""}`,
  };
}
