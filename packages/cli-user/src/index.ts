#!/usr/bin/env node
/**
 * @contextlock/cli-user — User CLI entry point.
 * Requirements: 5, 9, 14, 15, 20
 */

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

/**
 * CLI command routing — parses process.argv and dispatches to command functions.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];
  const subcommand = args[1];

  const defaultTrustStore = "tcv-truststore.json";
  const defaultCache = "tcv-cache.json";

  const getFlag = (flag: string) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };

  switch (command) {
    case "trust": {
      const storePath = getFlag("--store") ?? defaultTrustStore;

      switch (subcommand) {
        case "add": {
          const pubKeyPath = args[2];
          const name = getFlag("--name") ?? "unknown";
          if (!pubKeyPath) {
            console.error("Usage: tcv-user trust add <public-key> --name <publisher>");
            process.exit(1);
          }
          const { trustAdd: run } = await import("./commands/trust-add.js");
          const result = await run({ publicKeyPath: pubKeyPath, publisherName: name, trustStorePath: storePath });
          console.log(`Added publisher "${result.publisherName}" (fingerprint: ${result.fingerprint})`);
          break;
        }
        case "remove": {
          const keyId = args[2];
          if (!keyId) {
            console.error("Usage: tcv-user trust remove <key-id>");
            process.exit(1);
          }
          const { trustRemove: run } = await import("./commands/trust-remove.js");
          const result = await run({ keyId, trustStorePath: storePath });
          if (result.removed) {
            console.log(`Removed publisher with key ID: ${result.keyId}`);
          } else {
            console.error(`Key ID not found: ${result.keyId}`);
            process.exit(1);
          }
          break;
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
          break;
        }
        case "revoke": {
          const keyId = args[2];
          if (!keyId) {
            console.error("Usage: tcv-user trust revoke <key-id>");
            process.exit(1);
          }
          const { trustRevoke: run } = await import("./commands/trust-revoke.js");
          const result = await run({ keyId, trustStorePath: storePath });
          if (result.revoked) {
            console.log(`Revoked key: ${result.keyId}`);
          } else {
            console.error(`Key ID not found: ${result.keyId}`);
            process.exit(1);
          }
          break;
        }
        default:
          console.error("Unknown trust subcommand. Available: add, remove, list, revoke");
          process.exit(1);
      }
      break;
    }

    case "verify": {
      const filePath = args[1];
      if (!filePath) {
        console.error("Usage: tcv-user verify <file>");
        process.exit(1);
      }
      const storePath = getFlag("--store") ?? defaultTrustStore;
      const { userVerify: run } = await import("./commands/verify.js");
      const result = await run({ filePath, trustStorePath: storePath });
      console.log(result.displayMessage);
      process.exit(result.result.status === "trusted" ? 0 : 1);
      break;
    }

    case "cache": {
      if (subcommand === "refresh") {
        const storePath = getFlag("--store") ?? defaultTrustStore;
        const cachePath = getFlag("--cache") ?? defaultCache;
        const { cacheRefresh: run } = await import("./commands/cache-refresh.js");
        const result = await run({ cachePath, trustStorePath: storePath });
        console.log(`Cache refresh: ${result.entriesBefore} entries → ${result.entriesAfter} entries (${result.removed} removed)`);
      } else {
        console.error("Unknown cache subcommand. Available: refresh");
        process.exit(1);
      }
      break;
    }

    case "key-fingerprint": {
      const pubKeyPath = args[1];
      if (!pubKeyPath) {
        console.error("Usage: tcv-user key-fingerprint <public-key>");
        process.exit(1);
      }
      const { keyFingerprint: run } = await import("./commands/key-fingerprint.js");
      const result = await run({ publicKeyPath: pubKeyPath });
      console.log(result.fingerprint);
      break;
    }

    default:
      console.error("Unknown command. Available: trust, verify, cache, key-fingerprint");
      process.exit(1);
  }
}

const isDirectRun = process.argv[1]?.includes("cli-user");
if (isDirectRun) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
