/**
 * One-time generator for the SYNTHETIC Sigstore fixture used by Profile B
 * tests (tests/fixtures/sigstore/synthetic-*).
 *
 * Uses @sigstore/mock (the sigstore-js project's own test double) to stand up
 * a mock Fulcio CA (+CT log for embedded SCTs) and a mock RFC3161 TSA, then:
 *   1. issues a short-lived leaf certificate for a GitHub-Actions-style
 *      identity,
 *   2. signs a real contextlock/2 manifest into a DSSE envelope with the leaf
 *      key,
 *   3. timestamps the signature with the mock TSA (so certificate validity is
 *      anchored to generation time - the fixture verifies forever),
 *   4. writes a custom trusted_root.json containing the mock CA / CT log /
 *      TSA, the v0.3 bundle, and the package files.
 *
 * The generated fixture has NO transparency log entry, so verification must
 * run with tlogThreshold: 0 (the tests do). Everything else - chain, SCT,
 * timestamp, DSSE signature, identity policy - is verified for real.
 *
 * Run from the repo root:  node scripts/generate-sigstore-fixture.mjs
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { initializeCA, initializeCTLog, initializeTSA } from "@sigstore/mock";
import { bundleFromJSON } from "@sigstore/bundle";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { TrustedRoot } from "@sigstore/protobuf-specs";

const OUT_DIR = "tests/fixtures/sigstore";
const PKG_DIR = join(OUT_DIR, "synthetic-pkg");

const SAN = "https://github.com/contextlock-test/demo/.github/workflows/release.yml@refs/heads/main";
const ISSUER = "https://token.actions.githubusercontent.com";
const OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
const PAYLOAD_TYPE = "application/vnd.contextlock.manifest+json";

const SKILL_CONTENT = "# Sigstore Demo Skill\n\nSigned keylessly via CI (synthetic fixture).\n";

function b64(data) {
  return Buffer.from(data).toString("base64");
}

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf-8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "utf-8"),
    type,
    Buffer.from(` ${payload.length} `, "utf-8"),
    payload,
  ]);
}

function keypairP256() {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

// ---- 1. Mock infrastructure ----

const ctlogKeys = keypairP256();
const caKeys = keypairP256();
const tsaKeys = keypairP256();
const leafKeys = keypairP256();

const ctLog = await initializeCTLog(ctlogKeys);
const ca = await initializeCA(caKeys, ctLog);
const tsa = await initializeTSA(tsaKeys);

// ---- 2. Leaf certificate (GitHub-Actions-style identity) ----

const leafSpki = leafKeys.publicKey.export({ type: "spki", format: "der" });
const leafCert = await ca.issueCertificate({
  publicKey: leafSpki,
  subjectAltName: SAN,
  extensions: [{ oid: OID_FULCIO_ISSUER_V2, value: ISSUER }],
});

// ---- 3. contextlock/2 manifest + DSSE signature ----

const skillBytes = Buffer.from(SKILL_CONTENT, "utf-8");
const manifest = {
  spec_version: "contextlock/2",
  package: "sigstore-demo-pkg",
  version: 1,
  display_version: "1.0.0",
  publisher: { name: "Sigstore Demo", key_id: "sigstore:github-actions" },
  published_at: new Date().toISOString(),
  expires_at: "2036-01-01T00:00:00Z",
  files: [
    {
      path: "SKILL.md",
      sha256: sha256(skillBytes).toString("hex"),
      length: skillBytes.length,
    },
  ],
  lints: { unicode_tags: "absent", zero_width: "absent", bidi_controls: "absent" },
};
const payload = Buffer.from(JSON.stringify(manifest, null, 2), "utf-8");
const signature = createSign("sha256").update(pae(PAYLOAD_TYPE, payload)).sign(leafKeys.privateKey);

// ---- 4. TSA timestamp over the signature ----

const tsToken = await tsa.timestamp({
  artifactHash: sha256(signature),
  hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
  nonce: 8675309,
  policyOID: "1.3.6.1.4.1.57264.2",
  certReq: false,
});

// ---- 5. Bundle (v0.3) + custom trusted root ----

const bundleJson = {
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
  verificationMaterial: {
    certificate: { rawBytes: b64(leafCert) },
    tlogEntries: [],
    timestampVerificationData: {
      rfc3161Timestamps: [{ signedTimestamp: b64(tsToken) }],
    },
  },
  dsseEnvelope: {
    payload: b64(payload),
    payloadType: PAYLOAD_TYPE,
    signatures: [{ sig: b64(signature), keyid: "" }],
  },
};

const now = new Date();
const start = new Date(now.getTime() - 24 * 3600 * 1000).toISOString();
const end = new Date(now.getTime() + 3650 * 24 * 3600 * 1000).toISOString();

const trustedRootJson = {
  mediaType: "application/vnd.dev.sigstore.trustedroot+json",
  tlogs: [],
  certificateAuthorities: [
    {
      subject: { organization: "sigstore.mock", commonName: "sigstore" },
      uri: "https://fulcio.sigstore.mock",
      certChain: { certificates: [{ rawBytes: b64(ca.rootCertificate) }] },
      validFor: { start, end },
    },
  ],
  ctlogs: [
    {
      baseUrl: "https://ctlog.sigstore.mock",
      hashAlgorithm: "SHA2_256",
      publicKey: {
        rawBytes: b64(ctLog.publicKey),
        keyDetails: "PKIX_ECDSA_P256_SHA_256",
        validFor: { start },
      },
      logId: { keyId: b64(ctLog.logID) },
    },
  ],
  timestampAuthorities: [
    {
      subject: { organization: "sigstore.mock", commonName: "tsa" },
      certChain: {
        certificates: [
          { rawBytes: b64(tsa.intCertificate) },
          { rawBytes: b64(tsa.rootCertificate) },
        ],
      },
      validFor: { start, end },
    },
  ],
};

// ---- 6. Self-verify before writing anything ----

const trustedRoot = TrustedRoot.fromJSON(trustedRootJson);
const verifier = new Verifier(toTrustMaterial(trustedRoot), {
  tlogThreshold: 0,
  ctlogThreshold: 1,
  timestampThreshold: 1,
});
const signer = verifier.verify(toSignedEntity(bundleFromJSON(bundleJson)), {
  subjectAlternativeName: SAN,
  extensions: { issuer: ISSUER },
});
console.log("self-verification OK");
console.log("  SAN:   ", signer.identity?.subjectAlternativeName);
console.log("  issuer:", signer.identity?.extensions?.issuer);

// ---- 7. Write fixture files ----

await mkdir(PKG_DIR, { recursive: true });
await writeFile(join(PKG_DIR, "SKILL.md"), skillBytes);
await writeFile(join(PKG_DIR, "contextlock.sigstore.json"), JSON.stringify(bundleJson, null, 2));
await writeFile(join(OUT_DIR, "synthetic-trusted-root.json"), JSON.stringify(trustedRootJson, null, 2));
console.log(`fixtures written to ${OUT_DIR}`);
