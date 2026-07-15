#!/usr/bin/env node
/**
 * @contextlock/cli-publisher — Publisher CLI entry point.
 * Requirements: 10, 11, 12, 19, 20
 */

export { initKey } from "./commands/init-key.js";
export type { InitKeyOptions, InitKeyResult } from "./commands/init-key.js";

export { buildManifest } from "./commands/build-manifest.js";
export type { BuildManifestOptions, BuildManifestResult } from "./commands/build-manifest.js";

export { signManifest } from "./commands/sign-manifest.js";
export type { SignManifestOptions, SignManifestResult } from "./commands/sign-manifest.js";

export { verify } from "./commands/verify.js";
export type { VerifyOptions, VerifyResult, FileVerificationResult } from "./commands/verify.js";

export { keyFingerprint } from "./commands/key-fingerprint.js";
export type { KeyFingerprintOptions, KeyFingerprintResult } from "./commands/key-fingerprint.js";

export { hashFilename } from "./commands/hash-filename.js";
export type { HashFilenameOptions, HashFilenameResult } from "./commands/hash-filename.js";

export { protect } from "./commands/protect.js";
export type { ProtectOptions, ProtectResult, ProtectMode } from "./commands/protect.js";

/**
 * CLI command routing — parses process.argv and dispatches to command functions.
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case "init-key": {
      const outputIdx = args.indexOf("--output");
      const output = outputIdx !== -1 ? args[outputIdx + 1] : undefined;
      const { initKey: run } = await import("./commands/init-key.js");
      const result = await run({ output });
      console.log(`Keypair generated:`);
      console.log(`  Private key: ${result.privateKeyPath}`);
      console.log(`  Public key:  ${result.publicKeyPath}`);
      console.log(`  Fingerprint: ${result.fingerprint}`);
      break;
    }

    case "build-manifest": {
      const dir = args[1];
      if (!dir) {
        console.error("Usage: tcv-publisher build-manifest <dir> --name <pkg> --version <ver> --publisher <name> --key-id <id> --fingerprint <fp>");
        process.exit(1);
      }
      const get = (flag: string) => {
        const i = args.indexOf(flag);
        return i !== -1 ? args[i + 1] : "";
      };
      const { buildManifest: run } = await import("./commands/build-manifest.js");
      const result = await run({
        directory: dir,
        packageName: get("--name"),
        version: get("--version"),
        publisherName: get("--publisher"),
        keyId: get("--key-id"),
        fingerprint: get("--fingerprint"),
      });
      if (result.warning) {
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
      const keyIdx = args.indexOf("--key");
      const privateKeyPath = keyIdx !== -1 ? args[keyIdx + 1] : "";
      if (!manifestPath || !privateKeyPath) {
        console.error("Usage: tcv-publisher sign-manifest <manifest> --key <private-key>");
        process.exit(1);
      }
      const { signManifest: run } = await import("./commands/sign-manifest.js");
      const result = await run({ manifestPath, privateKeyPath });
      console.log(`Signature created: ${result.signaturePath}`);
      console.log(`  Key ID: ${result.keyId}`);
      break;
    }

    case "verify": {
      const dir = args[1];
      if (!dir) {
        console.error("Usage: tcv-publisher verify <dir>");
        process.exit(1);
      }
      const { verify: run } = await import("./commands/verify.js");
      const result = await run({ directory: dir });
      if (!result.manifestFound) {
        console.error("Error: manifest.json not found");
        process.exit(1);
      }
      if (result.error) {
        console.error(`Error: ${result.error}`);
      }
      for (const fr of result.fileResults) {
        if (fr.status === "ok") {
          console.log(`  ✓ ${fr.path}`);
        } else if (fr.status === "modified") {
          console.log(`  ✗ ${fr.path} (modified)`);
          console.log(`    expected: ${fr.expectedHash}`);
          console.log(`    computed: ${fr.computedHash}`);
        } else {
          console.log(`  ✗ ${fr.path} (missing)`);
        }
      }
      process.exit(result.success ? 0 : 1);
      break;
    }

    case "key-fingerprint": {
      const pubKeyPath = args[1];
      if (!pubKeyPath) {
        console.error("Usage: tcv-publisher key-fingerprint <public-key>");
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
        console.error("Usage: tcv-publisher hash-filename <file> [--length <n>] [--output <dir>]");
        process.exit(1);
      }
      const lengthIdx = args.indexOf("--length");
      const hashLength = lengthIdx !== -1 ? parseInt(args[lengthIdx + 1], 10) : 16;
      const outIdx = args.indexOf("--output");
      const outputDir = outIdx !== -1 ? args[outIdx + 1] : undefined;
      const { hashFilename: run } = await import("./commands/hash-filename.js");
      const result = await run({ filePath, hashLength, outputDir });
      console.log(`Hash-protected file: ${result.hashedPath}`);
      console.log(`  Full SHA-256: ${result.hash}`);
      console.log(`  Embedded:     ${result.embeddedHash}`);
      break;
    }

    case "protect": {
      const dir = args[1];
      if (!dir) {
        console.error("Usage: tcv-publisher protect <dir> --mode <hash|sign> [--name <pkg>] [--version <ver>] [--publisher <name>] [--key <private-key>]");
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
        version: get("--version"),
        publisherName: get("--publisher"),
        privateKeyPath: get("--key"),
      });
      if (result.filesProtected === 0) {
        console.warn("No protected files found in directory.");
      } else if (result.mode === "hash") {
        console.log(`Hash-protected ${result.filesProtected} file(s):`);
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
        console.log(`Manifest: ${result.buildResult!.manifestPath} (${result.filesProtected} files)`);
        console.log(`Signature: ${result.signResult!.signaturePath}`);
        console.log(`  Key ID: ${result.signResult!.keyId}`);
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
