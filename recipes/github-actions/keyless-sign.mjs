#!/usr/bin/env node
/**
 * ContextLock Profile B keyless signer (run inside CI with OIDC available).
 *
 * Wraps a contextlock/2 manifest in a DSSE envelope signed with an ephemeral
 * Fulcio certificate (the workflow's OIDC identity) and logged to Rekor,
 * emitting the Sigstore bundle ContextLock verifies offline:
 * contextlock.sigstore.json.
 *
 * Usage:  node keyless-sign.mjs <contextlock.manifest.json> [output-bundle]
 * Deps:   npm install sigstore   (in the CI job)
 *
 * The DSSE payloadType is application/vnd.contextlock.manifest+json - the
 * type ContextLock's engine requires (a cosign attest-blob wraps payloads in
 * an in-toto Statement instead, which ContextLock rejects by design; see
 * SPEC v2 15 open question 3).
 */

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { attest } from "sigstore";

const PAYLOAD_TYPE = "application/vnd.contextlock.manifest+json";

const manifestPath = process.argv[2];
if (!manifestPath) {
  console.error("Usage: node keyless-sign.mjs <contextlock.manifest.json> [output-bundle]");
  process.exit(1);
}
const outputPath = process.argv[3] ?? join(dirname(manifestPath), "contextlock.sigstore.json");

const payload = await readFile(manifestPath);

// Fail early on a malformed manifest - never sign an invalid payload.
const manifest = JSON.parse(payload.toString("utf-8"));
if (manifest.spec_version !== "contextlock/2") {
  console.error(`refusing to sign: spec_version is "${manifest.spec_version}", expected "contextlock/2"`);
  process.exit(1);
}

const bundle = await attest(payload, PAYLOAD_TYPE);
await writeFile(outputPath, JSON.stringify(bundle, null, 2), "utf-8");
console.log(`keyless-signed ${manifestPath} -> ${outputPath}`);
console.log(`package: ${manifest.package} v${manifest.version}`);
