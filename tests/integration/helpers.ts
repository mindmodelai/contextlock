/**
 * Shared helpers for integration tests (v2 format: contextlock/2 + DSSE).
 */

import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Manifest } from "@contextlock/core";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
} from "../../packages/core/src/testkit.js";
import type { TestKeypair } from "../../packages/core/src/testkit.js";

export async function createTempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

export interface SignedPackage {
  dir: string;
  kp: TestKeypair;
  storePath: string;
  manifest: Manifest;
}

/**
 * Creates a complete signed v2 package (files + contextlock.dsse.json) with a
 * signed trust store trusting the package's key.
 */
export async function createSignedPackage(
  dir: string,
  files: Record<string, string>,
  options?: { expiresAt?: string; packageName?: string; version?: number },
): Promise<SignedPackage> {
  const kp = await makeKeypair();

  const { manifest } = await writeSignedPackage(dir, kp, {
    packageName: options?.packageName ?? "integration-test-pkg",
    version: options?.version ?? 1,
    publisherName: "IntegrationPublisher",
    expiresAt: options?.expiresAt,
    files,
  });

  const storePath = join(dir, "truststore.json");
  await writeTrustStore(storePath, [kp], {
    publisherName: "IntegrationPublisher",
    policy: { default_action: "warn" },
  });

  return { dir, kp, storePath, manifest };
}
