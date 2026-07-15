#!/usr/bin/env node
/**
 * @contextlock/cli-user - User CLI entry point.
 *
 * Commands (all support --json; exit codes: 0 ok, 3 violations, 2 op error):
 *   seal <path...> [--note <t>] | seal --all [--root <dir>]
 *   reseal <path...> | unseal <path...>
 *   status [--root <dir>] [--json]
 *   sweep  [--root <dir>] [--json] [--quarantine]
 *   hook session-start | hook pre-tool-use   (read hook JSON from stdin)
 *   trust add|remove|list|revoke, verify, cache refresh, key-fingerprint (v1)
 */

import { join } from "node:path";
import { contextlockHome } from "@contextlock/core";

export { trustAdd } from "./commands/trust-add.js";
export type { TrustAddOptions, TrustAddResult } from "./commands/trust-add.js";

export { trustRemove } from "./commands/trust-remove.js";
export type { TrustRemoveOptions, TrustRemoveResult } from "./commands/trust-remove.js";

export { trustList } from "./commands/trust-list.js";
export type { TrustListOptions, TrustListResult } from "./commands/trust-list.js";

export { trustRevoke } from "./commands/trust-revoke.js";
export type { TrustRevokeOptions, TrustRevokeResult } from "./commands/trust-revoke.js";

export { userVerify } from "./commands/verify.js";
export type { UserVerifyOptions, UserVerifyResult } from "./commands/verify.js";

export { cacheRefresh } from "./commands/cache-refresh.js";
export type { CacheRefreshOptions, CacheRefreshResult } from "./commands/cache-refresh.js";

export { keyFingerprint } from "./commands/key-fingerprint.js";
export type { KeyFingerprintOptions, KeyFingerprintResult } from "./commands/key-fingerprint.js";

export { sealCommand } from "./commands/seal.js";
export type { SealOptions, SealResult, SealAction, SealedEntry } from "./commands/seal.js";

export { statusCommand } from "./commands/status.js";
export type { StatusOptions, StatusResult, StatusRow } from "./commands/status.js";

export { sweepCommand, defaultTrustStorePath } from "./commands/sweep.js";
export type { SweepOptions, SweepResult, SweepFileResult } from "./commands/sweep.js";

export { hookSessionStart, hookPreToolUse } from "./commands/hook.js";
export type {
  SessionStartInput,
  SessionStartHookResult,
  PreToolUseInput,
  PreToolUseHookResult,
} from "./commands/hook.js";

// ---- argument parsing ----

interface Parsed {
  positionals: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(rest: string[], valueFlags: string[], boolFlags: string[]): Parsed {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valueFlags.includes(a)) {
      flags[a] = rest[i + 1];
      i++;
    } else if (boolFlags.includes(a)) {
      flags[a] = true;
    } else if (a.startsWith("--")) {
      flags[a] = true;
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    if (process.stdin.isTTY) {
      resolve("");
      return;
    }
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", () => resolve(data));
  });
}

function defaultTrustStore(): string {
  return process.env.CONTEXTLOCK_TRUSTSTORE || join(contextlockHome(), "truststore.json");
}

/**
 * CLI dispatcher. Returns the intended process exit code.
 * 0 = ok, 3 = violations found, 2 = operational error.
 */
export async function runCli(argv: string[]): Promise<number> {
  const args = argv;
  const command = args[0];
  const json = args.includes("--json");

  const getFlag = (flag: string): string | undefined => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };

  try {
    switch (command) {
      // ---- Mode 0: seal / reseal / unseal ----
      case "seal":
      case "reseal":
      case "unseal": {
        const { positionals, flags } = parseArgs(
          args.slice(1),
          ["--note", "--root"],
          ["--all", "--json"],
        );
        const { sealCommand } = await import("./commands/seal.js");
        const result = await sealCommand({
          action: command,
          paths: positionals,
          all: Boolean(flags["--all"]),
          root: flags["--root"] as string | undefined,
          note: flags["--note"] as string | undefined,
        });
        if (result.storeUnavailable) {
          if (json) console.log(JSON.stringify(result, null, 2));
          else console.error(`[ContextLock] ${result.storeUnavailable}`);
          return 2;
        }
        if (json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          for (const s of result.sealed) console.log(`sealed  ${s.path}`);
          for (const u of result.unsealed) console.log(`unsealed ${u}`);
          for (const e of result.errors) console.error(`error   ${e.path}: ${e.error}`);
        }
        return result.errors.length > 0 ? 2 : 0;
      }

      // ---- status ----
      case "status": {
        const { statusCommand } = await import("./commands/status.js");
        const result = await statusCommand({ root: getFlag("--root") });
        if (json) {
          console.log(JSON.stringify(result, null, 2));
        } else if (result.storeUnavailable) {
          console.error(`[ContextLock] ${result.storeUnavailable}`);
        } else if (result.rows.length === 0) {
          console.log("No protected-class files found.");
        } else {
          console.log(`file\tstate\tsealed_at`);
          for (const r of result.rows) {
            console.log(`${r.file}\t${r.state}\t${r.sealed_at ?? "-"}`);
          }
        }
        return result.storeUnavailable ? 2 : 0;
      }

      // ---- sweep ----
      case "sweep": {
        const { sweepCommand } = await import("./commands/sweep.js");
        const result = await sweepCommand({
          root: getFlag("--root"),
          quarantine: args.includes("--quarantine"),
        });
        if (json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(
            `ContextLock sweep: ${result.verified} verified, ${result.violations} violation(s).`,
          );
          for (const v of result.violationFiles) {
            const q = v.quarantinedTo ? ` -> quarantined: ${v.quarantinedTo}` : "";
            console.log(`  VIOLATION ${v.file} (${v.status})${q}`);
          }
        }
        return result.violations > 0 ? 3 : 0;
      }

      // ---- hook ----
      case "hook": {
        const sub = args[1];
        const stdin = await readStdin();
        let input: Record<string, unknown> = {};
        try {
          input = stdin.trim() ? JSON.parse(stdin) : {};
        } catch {
          input = {};
        }
        if (sub === "session-start") {
          const { hookSessionStart } = await import("./commands/hook.js");
          const result = await hookSessionStart(input);
          console.log(JSON.stringify({ hookSpecificOutput: result.hookSpecificOutput }));
          return 0; // SessionStart never blocks.
        }
        if (sub === "pre-tool-use") {
          const { hookPreToolUse } = await import("./commands/hook.js");
          const result = await hookPreToolUse(input);
          if (result.hookOutput) {
            // Deny: decision carried in JSON, not the exit code.
            console.log(JSON.stringify(result.hookOutput));
          }
          // Allow: emit nothing so the normal permission flow proceeds.
          return 0;
        }
        console.error(
          "Usage: contextlock hook <session-start|pre-tool-use>\n" +
            "Reads the Claude Code hook input JSON from stdin.\n" +
            "Error policy: if the hook itself fails, it fails OPEN (allow, loud stderr warning)\n" +
            "unless CONTEXTLOCK_STRICT=1 is set, in which case it fails CLOSED (deny).",
        );
        return 2;
      }

      // ---- v1: trust management ----
      case "trust": {
        const subcommand = args[1];
        const storePath = getFlag("--store") ?? defaultTrustStore();
        switch (subcommand) {
          case "add": {
            const pubKeyPath = args[2];
            const name = getFlag("--name") ?? "unknown";
            if (!pubKeyPath) {
              console.error("Usage: contextlock trust add <public-key> --name <publisher>");
              return 2;
            }
            const { trustAdd: run } = await import("./commands/trust-add.js");
            const result = await run({ publicKeyPath: pubKeyPath, publisherName: name, trustStorePath: storePath });
            console.log(`Added publisher "${result.publisherName}" (fingerprint: ${result.fingerprint})`);
            return 0;
          }
          case "remove": {
            const keyId = args[2];
            if (!keyId) {
              console.error("Usage: contextlock trust remove <key-id>");
              return 2;
            }
            const { trustRemove: run } = await import("./commands/trust-remove.js");
            const result = await run({ keyId, trustStorePath: storePath });
            if (result.removed) {
              console.log(`Removed publisher with key ID: ${result.keyId}`);
              return 0;
            }
            console.error(`Key ID not found: ${result.keyId}`);
            return 2;
          }
          case "list": {
            const { trustList: run } = await import("./commands/trust-list.js");
            const result = await run({ trustStorePath: storePath });
            if (result.publishers.length === 0) {
              console.log("No trusted publishers.");
            } else {
              for (const p of result.publishers) {
                console.log(`  ${p.publisher}  key_id=${p.key_id}  fingerprint=${p.fingerprint}${p.revoked ? " [REVOKED]" : ""}`);
              }
            }
            return 0;
          }
          case "revoke": {
            const keyId = args[2];
            if (!keyId) {
              console.error("Usage: contextlock trust revoke <key-id>");
              return 2;
            }
            const { trustRevoke: run } = await import("./commands/trust-revoke.js");
            const result = await run({ keyId, trustStorePath: storePath });
            if (result.revoked) {
              console.log(`Revoked key: ${result.keyId}`);
              return 0;
            }
            console.error(`Key ID not found: ${result.keyId}`);
            return 2;
          }
          default:
            console.error("Unknown trust subcommand. Available: add, remove, list, revoke");
            return 2;
        }
      }

      case "verify": {
        const filePath = args[1];
        if (!filePath) {
          console.error("Usage: contextlock verify <file>");
          return 2;
        }
        const storePath = getFlag("--store") ?? defaultTrustStore();
        const { userVerify: run } = await import("./commands/verify.js");
        const result = await run({ filePath, trustStorePath: storePath });
        console.log(result.displayMessage);
        return ["trusted", "sealed", "sealed+trusted"].includes(result.result.status) ? 0 : 3;
      }

      case "cache": {
        if (args[1] === "refresh") {
          const storePath = getFlag("--store") ?? defaultTrustStore();
          const cachePath = getFlag("--cache") ?? "tcv-cache.json";
          const { cacheRefresh: run } = await import("./commands/cache-refresh.js");
          const result = await run({ cachePath, trustStorePath: storePath });
          console.log(`Cache refresh: ${result.entriesBefore} entries → ${result.entriesAfter} entries (${result.removed} removed)`);
          return 0;
        }
        console.error("Unknown cache subcommand. Available: refresh");
        return 2;
      }

      case "key-fingerprint": {
        const pubKeyPath = args[1];
        if (!pubKeyPath) {
          console.error("Usage: contextlock key-fingerprint <public-key>");
          return 2;
        }
        const { keyFingerprint: run } = await import("./commands/key-fingerprint.js");
        const result = await run({ publicKeyPath: pubKeyPath });
        console.log(result.fingerprint);
        return 0;
      }

      default:
        console.error(
          [
            "contextlock - integrity for AI instruction files (SPEC v2 Phase A)",
            "",
            "Commands:",
            "  seal <path...> [--note <text>]     pin a reviewed file (Mode 0 TOFU)",
            "  seal --all [--root <dir>]          seal every protected-class file under root",
            "  reseal <path...>                   deliberate re-approval after an intended edit",
            "  unseal <path...>                   remove a seal",
            "  status [--root <dir>] [--json]     seal state for protected files under root",
            "  sweep [--root <dir>] [--json] [--quarantine]",
            "                                     verify all protected files plus ~/.claude/CLAUDE.md;",
            "                                     --quarantine moves violators aside with a placeholder",
            "  hook session-start|pre-tool-use    Claude Code hook entry points (JSON on stdin);",
            "                                     hook failures fail OPEN (allow, loud stderr warning)",
            "                                     unless CONTEXTLOCK_STRICT=1, then fail CLOSED (deny)",
            "  trust add|remove|list|revoke       publisher trust management",
            "  verify <file>                      full verification of one file",
            "  cache refresh | key-fingerprint    utilities",
            "",
            "Exit codes: 0 = ok, 3 = violations found, 2 = operational error.",
          ].join("\n"),
        );
        return 2;
    }
  } catch (err) {
    console.error((err as Error).message);
    return 2;
  }
}

// Auto-run only when this module is the executed entry (e.g. the `tcv-user`
// bin -> dist/index.js). The `contextlock` bin imports runCli explicitly, so it
// must NOT trigger this path (which would double-run).
const entry = (process.argv[1] ?? "").replace(/\\/g, "/");
const isDirectRun =
  entry.endsWith("packages/cli-user/dist/index.js") ||
  entry.endsWith("packages/cli-user/src/index.ts");
if (isDirectRun) {
  runCli(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      console.error(err.message);
      process.exit(2);
    });
}
