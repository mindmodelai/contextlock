/**
 * One-time generator for the nono-INTEROP fixture
 * (tests/fixtures/sigstore/nono-pkg + nono-trusted-root.json).
 *
 * Produces an attestation in nono's exact wire shape (confirmed against
 * nolabs-ai/nono source, 2026-07-15):
 *   Sigstore bundle v0.3 -> DSSE payloadType application/vnd.in-toto+json
 *   -> in-toto Statement v1, predicateType
 *   https://nono.sh/attestation/multi-file/v1, subjects = relative paths
 *   with sha256 digests, sidecar named `.nono-trust.bundle`.
 *
 * Signed via @sigstore/mock (mock Fulcio CA + CT log + RFC3161 TSA), same
 * technique as generate-sigstore-fixture.mjs: no transparency log entry, so
 * verification uses tlogThreshold: 0; timestamps anchor cert validity to
 * generation time, so the fixture never expires.
 *
 * Run from the repo root:  node scripts/generate-nono-fixture.mjs
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { initializeCA, initializeCTLog, initializeTSA } from "@sigstore/mock";
import { bundleFromJSON } from "@sigstore/bundle";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { TrustedRoot } from "@sigstore/protobuf-specs";

const OUT_DIR = "tests/fixtures/sigstore";
const PKG_DIR = join(OUT_DIR, "nono-pkg");

const SAN = "https://github.com/nono-interop/skill/.github/workflows/sign.yml@refs/heads/main";
const ISSUER = "https://token.actions.githubusercontent.com";
const OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";
const PAYLOAD_TYPE = "application/vnd.in-toto+json";
const PREDICATE_TYPE = "https://nono.sh/attestation/multi-file/v1";

const FILES = {
  "SKILL.md": "# Interop Skill\n\nAttested in nono's multi-file format.\n",
  "scripts/helper.py": "print('hello from the interop fixture')\n",
};

const b64 = (data) => Buffer.from(data).toString("base64");
const sha256 = (data) => createHash("sha256").update(data).digest();

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf-8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "utf-8"),
    type,
    Buffer.from(` ${payload.length} `, "utf-8"),
    payload,
  ]);
}

const keypairP256 = () => generateKeyPairSync("ec", { namedCurve: "P-256" });

// ---- Mock infrastructure + leaf cert ----

const ctlogKeys = keypairP256();
const caKeys = keypairP256();
const tsaKeys = keypairP256();
const leafKeys = keypairP256();

const ctLog = await initializeCTLog(ctlogKeys);
const ca = await initializeCA(caKeys, ctLog);
const tsa = await initializeTSA(tsaKeys);

const leafCert = await ca.issueCertificate({
  publicKey: leafKeys.publicKey.export({ type: "spki", format: "der" }),
  subjectAltName: SAN,
  extensions: [{ oid: OID_FULCIO_ISSUER_V2, value: ISSUER }],
});

// ---- in-toto Statement (nono multi-file shape) ----

const statement = {
  _type: "https://in-toto.io/Statement/v1",
  subject: Object.entries(FILES).map(([path, content]) => ({
    name: path,
    digest: { sha256: sha256(Buffer.from(content, "utf-8")).toString("hex") },
  })),
  predicateType: PREDICATE_TYPE,
  predicate: {
    version: 1,
    signer: {
      kind: "keyless",
      oidc_issuer: ISSUER,
      server_url: "https://github.com",
      repository: "nono-interop/skill",
      workflow: "nono-interop/skill/.github/workflows/sign.yml@refs/heads/main",
      ref: "refs/heads/main",
    },
  },
};
const payload = Buffer.from(JSON.stringify(statement), "utf-8");
const signature = createSign("sha256").update(pae(PAYLOAD_TYPE, payload)).sign(leafKeys.privateKey);

const tsToken = await tsa.timestamp({
  artifactHash: sha256(signature),
  hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
  nonce: 424242,
  policyOID: "1.3.6.1.4.1.57264.2",
  certReq: false,
});

// ---- Bundle + trusted root ----

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

// ---- Self-verify, then write ----

const verifier = new Verifier(toTrustMaterial(TrustedRoot.fromJSON(trustedRootJson)), {
  tlogThreshold: 0,
  ctlogThreshold: 1,
  timestampThreshold: 1,
});
const signer = verifier.verify(toSignedEntity(bundleFromJSON(bundleJson)), {
  subjectAlternativeName: SAN,
  extensions: { issuer: ISSUER },
});
console.log("self-verification OK:", signer.identity?.subjectAlternativeName);

await mkdir(join(PKG_DIR, "scripts"), { recursive: true });
for (const [path, content] of Object.entries(FILES)) {
  await writeFile(join(PKG_DIR, path), content);
}
await writeFile(join(PKG_DIR, ".nono-trust.bundle"), JSON.stringify(bundleJson, null, 2));
await writeFile(join(OUT_DIR, "nono-trusted-root.json"), JSON.stringify(trustedRootJson, null, 2));
console.log(`fixtures written to ${PKG_DIR}`);
