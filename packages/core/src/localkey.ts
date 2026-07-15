/**
 * Machine-local Ed25519 key + ContextLock home resolution.
 * SPEC v2 sections 5 (Mode 0) and 8 (self-protection).
 *
 * A single machine-local key at `~/.contextlock/local.key` (raw 32-byte seed,
 * base64url, one line) signs the local seal store and trust store so that a
 * hand-edited store fails closed rather than silently trusting/untrusting.
 *
 * All `~/.contextlock` paths are overridable via the CONTEXTLOCK_HOME env var.
 * This is critical for tests: pointing CONTEXTLOCK_HOME at a temp dir keeps the
 * real `~/.contextlock` untouched.
 */

import { homedir, userInfo } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { sha256 } from "./hash.js";

// @noble/ed25519 v2 needs a sha512 implementation wired up.
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));
}

const LOCAL_KEY_FILENAME = "local.key";

/**
 * Absolute path to the ContextLock home directory.
 * Honors CONTEXTLOCK_HOME so tests never touch the real `~/.contextlock`.
 */
export function contextlockHome(): string {
  const override = process.env.CONTEXTLOCK_HOME;
  if (override && override.trim().length > 0) {
    return override;
  }
  return join(homedir(), ".contextlock");
}

/** Absolute path to the machine-local key file. */
export function localKeyPath(): string {
  return join(contextlockHome(), LOCAL_KEY_FILENAME);
}

// ---- base64url helpers ----

export function base64urlEncode(data: Uint8Array): string {
  return Buffer.from(data)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64urlDecode(input: string): Uint8Array {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

/**
 * Applies best-effort restrictive permissions to the ContextLock home dir.
 * win32: strip inheritance and grant the current user full control.
 * POSIX: chmod 0700.
 * Non-fatal: a failure warns but does not throw. Skipped when
 * CONTEXTLOCK_SKIP_ACL=1 (used by the test harness).
 */
async function applyHomeAcls(dir: string): Promise<void> {
  if (process.env.CONTEXTLOCK_SKIP_ACL === "1") return;

  if (process.platform === "win32") {
    const user = process.env.USERNAME || safeUsername();
    try {
      const res = spawnSync(
        "icacls",
        [dir, "/inheritance:r", "/grant:r", `${user}:(OI)(CI)F`],
        { stdio: "ignore" },
      );
      if (res.status !== 0) {
        console.warn(
          `[ContextLock] warning: could not tighten ACLs on ${dir} (icacls exit ${res.status}). Continuing.`,
        );
      }
    } catch {
      console.warn(
        `[ContextLock] warning: could not tighten ACLs on ${dir}. Continuing.`,
      );
    }
  } else {
    try {
      await chmod(dir, 0o700);
    } catch {
      console.warn(
        `[ContextLock] warning: could not chmod 0700 on ${dir}. Continuing.`,
      );
    }
  }
}

async function applyFilePerms(file: string): Promise<void> {
  if (process.env.CONTEXTLOCK_SKIP_ACL === "1") return;
  if (process.platform !== "win32") {
    try {
      await chmod(file, 0o600);
    } catch {
      /* best-effort */
    }
  }
}

function safeUsername(): string {
  try {
    return userInfo().username;
  } catch {
    return "";
  }
}

/**
 * Ensures the ContextLock home directory exists (creating it with restrictive
 * ACLs the first time). Safe to call repeatedly.
 */
export async function ensureContextlockHome(): Promise<string> {
  const dir = contextlockHome();
  const created = !existsSync(dir);
  await mkdir(dir, { recursive: true });
  if (created) {
    await applyHomeAcls(dir);
  }
  return dir;
}

export interface LocalKey {
  /** 32-byte Ed25519 seed / private key. */
  seed: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** SHA-256 hex of the public key. */
  fingerprint: string;
}

/**
 * Loads the machine-local key, creating it (with restrictive ACLs) on first
 * use. The key is a raw 32-byte seed stored base64url on a single line.
 */
export async function loadOrCreateLocalKey(): Promise<LocalKey> {
  const keyPath = localKeyPath();
  let seed: Uint8Array;

  if (existsSync(keyPath)) {
    const raw = (await readFile(keyPath, "utf-8")).trim();
    seed = base64urlDecode(raw);
    if (seed.length !== 32) {
      throw new Error(
        `machine-local key at ${keyPath} is malformed (expected 32-byte seed, got ${seed.length})`,
      );
    }
  } else {
    await ensureContextlockHome();
    seed = ed.utils.randomPrivateKey();
    await writeFile(keyPath, base64urlEncode(seed) + "\n", "utf-8");
    await applyFilePerms(keyPath);
  }

  const publicKey = await ed.getPublicKeyAsync(seed);
  const fingerprint = sha256(Buffer.from(publicKey));
  return { seed, publicKey, fingerprint };
}

/**
 * Signs `data` with the machine-local key. Returns a base64url signature and
 * the signing key's fingerprint.
 */
export async function signWithLocalKey(
  data: Buffer,
): Promise<{ signature: string; keyFingerprint: string }> {
  const key = await loadOrCreateLocalKey();
  const sig = await ed.signAsync(new Uint8Array(data), key.seed);
  return { signature: base64urlEncode(sig), keyFingerprint: key.fingerprint };
}

/**
 * Verifies a base64url signature over `data` against the machine-local key.
 * Returns whether it is valid plus the current machine key fingerprint.
 * A signature produced by a different key (moved machine, tampering) fails.
 */
export async function verifyWithLocalKey(
  data: Buffer,
  signature: string,
): Promise<{ valid: boolean; keyFingerprint: string }> {
  const key = await loadOrCreateLocalKey();
  try {
    const sigBytes = base64urlDecode(signature);
    const valid = await ed.verifyAsync(sigBytes, new Uint8Array(data), key.publicKey);
    return { valid, keyFingerprint: key.fingerprint };
  } catch {
    return { valid: false, keyFingerprint: key.fingerprint };
  }
}

/**
 * Canonical JSON serialization with recursively sorted object keys.
 * Used as the signing payload for both the seal store and the trust store so
 * the signature is stable regardless of key insertion order.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
