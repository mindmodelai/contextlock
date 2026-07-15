#!/usr/bin/env node
/**
 * @contextlock/cli-publisher - Publisher CLI entry point (SPEC v2 Phase B).
 *
 * Commands:
 *   protect <dir> --mode sign|hash   one-shot: keys + manifest + DSSE envelope
 *   init-key [--output <dir>] [--key-id <label>]
 *   build-manifest <dir> --name <pkg> --version <int> ...
 *   sign-manifest <manifest> --key <private-key> [--key-id <label>]
 *   verify <dir> [--pub <public-key>]
 *   key-fingerprint <public-key>
 *   hash-filename <file>             Mode 1 change hints (not a security mode)
 */

export { initKey, defaultKeyId, PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME } from "./commands/init-key.js";
export type { InitKeyOptions, InitKeyResult } from "./commands/init-key.js";

export { buildManifest, UNSIGNED_MANIFEST_FILENAME } from "./commands/build-manifest.js";
export type { BuildManifestOptions, BuildManifestResult } from "./commands/build-manifest.js";

export { signManifest, readRawKey } from "./commands/sign-manifest.js";
export type { SignManifestOptions, SignManifestResult } from "./commands/sign-manifest.js";

export { verify } from "./commands/verify.js";
export type { VerifyOptions, VerifyResult, FileVerificationResult } from "./commands/verify.js";

export { keyFingerprint } from "./commands/key-fingerprint.js";
export type { KeyFingerprintOptions, KeyFingerprintResult } from "./commands/key-fingerprint.js";

export { hashFilename } from "./commands/hash-filename.js";
export type { HashFilenameOptions, HashFilenameResult } from "./commands/hash-filename.js";

export { protect } from "./commands/protect.js";
export type { ProtectOptions, ProtectResult, ProtectMode } from "./commands/protect.js";

import type { LintRule } from "@contextlock/core";

function collectAllowLints(args: string[]): LintRule[] {
  const rules: LintRule[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--allow-lint" && args[i + 1]) {
      rules.push(args[i + 1] as LintRule);
    }
  }
  return rules;
}

/**
 * CLI command routing - parses process.argv and dispatches to command functions.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  const get = (flag: string) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : "";
  };

  switch (command) {
    case "init-key": {
      const { initKey: run } = await import("./commands/init-key.js");
      const result = await run({
        output: get("--output") || undefined,
        keyId: get("--key-id") || undefined,
      });
      console.log(`Keypair generated:`);
      console.log(`  Private key: ${result.privateKeyPath}`);
      console.log(`  Public key:  ${result.publicKeyPath}`);
      console.log(`  Key ID:      ${result.keyId}`);
      console.log(`  Fingerprint: ${result.fingerprint}`);
      break;
    }

    case "build-manifest": {
      const dir = args[1];
      const versionRaw = get("--version");
      if (!dir || !versionRaw) {
        console.error(
          "Usage: contextlock-publisher build-manifest <dir> --name <pkg> --version <int> --publisher <name> --key-id <label> " +
            "[--display-version <v>] [--expires-days <n>] [--allow-lint <rule>]...",
        );
        process.exit(1);
      }
      const version = Number.parseInt(versionRaw, 10);
      const { buildManifest: run } = await import("./commands/build-manifest.js");
      const result = await run({
        directory: dir,
        packageName: get("--name"),
        version,
        displayVersion: get("--display-version") || undefined,
        publisherName: get("--publisher"),
        keyId: get("--key-id"),
        expiresDays: get("--expires-days") ? Number.parseInt(get("--expires-days"), 10) : undefined,
        allowLints: collectAllowLints(args),
      });
      if (result.fileCount === 0) {
        console.warn(`Warning: ${result.warning}`);
      } else {
        console.log(`Manifest built: ${result.manifestPath}`);
        console.log(`Files (${result.fileCount}):`);
        for (const p of result.filePaths) {
          console.log(`  ${p}`);
        }
      }
      break;
    }

    case "sign-manifest": {
      const manifestPath = args[1];
      const privateKeyPath = get("--key");
      if (!manifestPath || !privateKeyPath) {
        console.error("Usage: contextlock-publisher sign-manifest <manifest> --key <private-key> [--key-id <label>]");
        process.exit(1);
      }
      const { signManifest: run } = await import("./commands/sign-manifest.js");
      const result = await run({
        manifestPath,
        privateKeyPath,
        keyId: get("--key-id") || undefined,
      });
      console.log(`Envelope created: ${result.envelopePath}`);
      console.log(`  Key ID:      ${result.keyId}`);
      console.log(`  Fingerprint: ${result.fingerprint}`);
      break;
    }

    case "verify": {
      const dir = args[1];
      if (!dir) {
        console.error("Usage: contextlock-publisher verify <dir> [--pub <public-key>]");
        process.exit(1);
      }
      const { verify: run } = await import("./commands/verify.js");
      const result = await run({ directory: dir, publicKeyPath: get("--pub") || undefined });
      if (!result.envelopeFound) {
        console.error("Error: contextlock.dsse.json not found");
        process.exit(1);
      }
      if (result.error) {
        console.error(`Error: ${result.error}`);
      }
      if (result.signatureValid === undefined) {
        console.warn("Warning: no public key found; signature NOT verified");
      } else if (result.signatureValid) {
        console.log("Signature: OK");
      }
      for (const fr of result.fileResults) {
        if (fr.status === "ok") {
          console.log(`  ✓ ${fr.path}`);
        } else if (fr.status === "modified") {
          console.log(`  ✗ ${fr.path} (modified)`);
          console.log(`    expected: ${fr.expectedHash}`);
          console.log(`    computed: ${fr.computedHash}`);
        } else {
          console.log(`  ✗ ${fr.path} (${fr.status})`);
        }
      }
      process.exit(result.success ? 0 : 1);
      break;
    }

    case "key-fingerprint": {
      const pubKeyPath = args[1];
      if (!pubKeyPath) {
        console.error("Usage: contextlock-publisher key-fingerprint <public-key>");
        process.exit(1);
      }
      const { keyFingerprint: run } = await import("./commands/key-fingerprint.js");
      const result = await run({ publicKeyPath: pubKeyPath });
      console.log(result.fingerprint);
      break;
    }

    case "hash-filename": {
      const filePath = args[1];
      if (!filePath) {
        console.error("Usage: contextlock-publisher hash-filename <file> [--length <n>] [--output <dir>]");
        process.exit(1);
      }
      const lengthIdx = args.indexOf("--length");
      const hashLength = lengthIdx !== -1 ? parseInt(args[lengthIdx + 1], 10) : 16;
      const { hashFilename: run } = await import("./commands/hash-filename.js");
      const result = await run({ filePath, hashLength, outputDir: get("--output") || undefined });
      console.log(`Change-hint file: ${result.hashedPath}`);
      console.log(`  Full SHA-256: ${result.hash}`);
      console.log(`  Embedded:     ${result.embeddedHash}`);
      break;
    }

    case "protect": {
      const dir = args[1];
      if (!dir) {
        console.error(
          "Usage: contextlock-publisher protect <dir> --mode <hash|sign> [--name <pkg>] [--version <int>] " +
            "[--display-version <v>] [--publisher <name>] [--key <private-key>] [--key-id <label>] " +
            "[--expires-days <n>] [--allow-lint <rule>]...",
        );
        process.exit(1);
      }
      const modeFlag = get("--mode") || "sign";
      if (modeFlag !== "hash" && modeFlag !== "sign") {
        console.error("--mode must be 'hash' or 'sign'");
        process.exit(1);
      }
      const { protect: run } = await import("./commands/protect.js");
      const result = await run({
        directory: dir,
        mode: modeFlag as "hash" | "sign",
        packageName: get("--name"),
        version: get("--version") ? Number.parseInt(get("--version"), 10) : undefined,
        displayVersion: get("--display-version") || undefined,
        publisherName: get("--publisher"),
        keyId: get("--key-id") || undefined,
        privateKeyPath: get("--key") || undefined,
        expiresDays: get("--expires-days") ? Number.parseInt(get("--expires-days"), 10) : undefined,
        allowLints: collectAllowLints(args),
      });
      if (result.filesProtected === 0) {
        console.warn("No protected files found in directory.");
      } else if (result.mode === "hash") {
        console.log(`Change-hinted ${result.filesProtected} file(s):`);
        for (const hr of result.hashResults!) {
          console.log(`  ${hr.originalPath} → ${hr.hashedPath}`);
        }
      } else {
        if (result.keyGenerated) {
          console.log(`Generated new keypair:`);
          console.log(`  Private key: ${result.keyResult!.privateKeyPath}`);
          console.log(`  Public key:  ${result.keyResult!.publicKeyPath}`);
          console.log(`  Fingerprint: ${result.keyResult!.fingerprint}`);
        }
        console.log(`Envelope: ${result.signResult!.envelopePath} (${result.filesProtected} files)`);
        console.log(`  Key ID:      ${result.signResult!.keyId}`);
        console.log(`  Fingerprint: ${result.signResult!.fingerprint}`);
      }
      break;
    }

    default:
      console.error("Unknown command. Available: protect, init-key, build-manifest, sign-manifest, verify, key-fingerprint, hash-filename");
      process.exit(1);
  }
}

// Run CLI when executed directly
const isDirectRun = process.argv[1]?.includes("cli-publisher");
if (isDirectRun) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
