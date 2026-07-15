/**
 * Sigstore keyless verification - Mode 2, Profile B (SPEC v2 5).
 *
 * A package signed in CI carries `contextlock.sigstore.json`: a Sigstore
 * bundle (v0.3) whose DSSE envelope payload is the contextlock/2 manifest.
 * Identity policy is expressed exactly the way npm provenance trained
 * developers: a pinned (certificate-identity, certificate-oidc-issuer) pair.
 *
 * Verification is FULLY OFFLINE given the bundle and a pinned
 * trusted_root.json (shipped with ContextLock at assets/trusted_root.json,
 * fetched from sigstore/root-signing; override via options or the
 * CONTEXTLOCK_SIGSTORE_ROOT env var). Signing is never offline (OIDC + Fulcio
 * + Rekor round-trips), which is why Profile A remains the baseline - see the
 * CI recipes for the signing side.
 *
 * The heavy lifting (certificate chain, SCTs, transparency log, RFC3161
 * timestamps, DSSE signature) is delegated to the official sigstore-js
 * verification libraries; ContextLock owns the identity-pinning policy and
 * the verify-then-parse handoff of the manifest payload.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { minimatch } from "minimatch";
import { sha256 } from "./hash.js";

// ---- Constants ----

/** Profile B artifact: a Sigstore bundle containing the manifest envelope. */
export const SIGSTORE_BUNDLE_FILENAME = "contextlock.sigstore.json";

/** Oversize defense, same rationale as MAX_ENVELOPE_BYTES. */
export const MAX_BUNDLE_BYTES = 4 * 1024 * 1024;

// ---- Types ----

/** A pinned keyless identity (SPEC v2 5, Profile B). */
export interface TrustedIdentity {
  /** Publisher display name this identity belongs to. */
  publisher: string;
  /**
   * Certificate identity (Fulcio SAN) pattern. Glob semantics via minimatch:
   * `*` does not cross `/`, `**` does. An exact URI or email works verbatim.
   */
  identity: string;
  /** OIDC issuer URL. Matched EXACTLY - no patterns. */
  issuer: string;
}

export interface SigstoreThresholds {
  /** Minimum transparency log entries (default 1; 0 only for private PKI/tests). */
  tlogThreshold?: number;
  /** Minimum SCTs on the signing certificate (default 1). */
  ctlogThreshold?: number;
  /** Minimum trusted timestamps (default 1; tlog entries count). */
  timestampThreshold?: number;
}

export interface SigstoreVerifyOptions {
  /** Path to a pinned trusted_root.json. Defaults to the shipped asset. */
  trustedRootPath?: string;
  thresholds?: SigstoreThresholds;
}

export interface SigstoreVerification {
  valid: boolean;
  reason?: string;
  /** Publisher name of the matched pinned identity. */
  publisher?: string;
  /** The ACTUAL certificate identity (SAN) of the signer. */
  identity?: string;
  /** The ACTUAL OIDC issuer of the signer. */
  issuer?: string;
  /** Decoded DSSE payload bytes of the VERIFIED bundle. Only set when valid. */
  payload?: Buffer;
  payloadType?: string;
  /**
   * Stable fingerprint of the signing identity (sha256 of issuer + SAN),
   * used to key anti-rollback state for keyless signers.
   */
  signerFingerprint?: string;
}

// ---- Trusted root resolution ----

/** Path of the pinned trusted root shipped with ContextLock. */
export function defaultTrustedRootPath(): string {
  const override = process.env.CONTEXTLOCK_SIGSTORE_ROOT;
  if (override && override.trim().length > 0) {
    return override;
  }
  return fileURLToPath(new URL("../assets/trusted_root.json", import.meta.url));
}

// ---- Identity policy ----

/**
 * Matches a signer's actual (SAN, issuer) against the pinned identities.
 * Issuer must match exactly; identity is a minimatch glob (exact URIs work
 * verbatim). Returns the first matching pin.
 */
export function matchTrustedIdentity(
  san: string | undefined,
  issuer: string | undefined,
  identities: TrustedIdentity[],
): TrustedIdentity | undefined {
  if (!san || !issuer) return undefined;
  // dot: true - Fulcio SANs routinely contain dot-segments (".github/...");
  // an identity glob must not silently skip them the way filename globs do.
  return identities.find(
    (id) =>
      id.issuer === issuer &&
      (id.identity === san || minimatch(san, id.identity, { dot: true })),
  );
}

/** Stable rollback-state key for a keyless signer. */
export function signerFingerprint(issuer: string, san: string): string {
  return sha256(Buffer.from(`sigstore\n${issuer}\n${san}`, "utf-8"));
}

// ---- Bundle verification ----

interface SigstoreLibs {
  bundleFromJSON: (json: unknown) => unknown;
  toSignedEntity: (bundle: never, artifact?: Buffer) => never;
  toTrustMaterial: (root: never) => never;
  Verifier: new (material: never, opts?: object) => {
    verify: (entity: never, policy?: object) => {
      identity?: { subjectAlternativeName?: string; extensions?: { issuer?: string } };
    };
  };
  TrustedRoot: { fromJSON: (json: unknown) => unknown };
}

let libs: SigstoreLibs | undefined;

/**
 * Lazily loads the sigstore-js verification libraries so that Profile A
 * deployments never pay for them. A missing dependency is a loud,
 * actionable error - never a silent downgrade.
 */
async function loadSigstoreLibs(): Promise<SigstoreLibs> {
  if (libs) return libs;
  try {
    const [bundle, verify, specs] = await Promise.all([
      import("@sigstore/bundle"),
      import("@sigstore/verify"),
      import("@sigstore/protobuf-specs"),
    ]);
    libs = {
      bundleFromJSON: bundle.bundleFromJSON as SigstoreLibs["bundleFromJSON"],
      toSignedEntity: verify.toSignedEntity as unknown as SigstoreLibs["toSignedEntity"],
      toTrustMaterial: verify.toTrustMaterial as unknown as SigstoreLibs["toTrustMaterial"],
      Verifier: verify.Verifier as unknown as SigstoreLibs["Verifier"],
      TrustedRoot: specs.TrustedRoot as SigstoreLibs["TrustedRoot"],
    };
    return libs;
  } catch (e) {
    throw new Error(
      "Sigstore verification unavailable: install @sigstore/bundle, @sigstore/verify, " +
        `and @sigstore/protobuf-specs to verify Profile B bundles (${(e as Error).message})`,
    );
  }
}

/**
 * Verifies a Sigstore bundle offline against the pinned trusted root, then
 * matches the signer's certificate identity against the pinned identities.
 *
 * On success the returned payload is the DSSE payload from the VERIFIED
 * bundle (verify-then-parse; callers must consume these bytes).
 */
export async function verifySigstoreBundle(
  bundleContent: Buffer | string,
  identities: TrustedIdentity[],
  options: SigstoreVerifyOptions = {},
): Promise<SigstoreVerification> {
  const text =
    typeof bundleContent === "string" ? bundleContent : bundleContent.toString("utf-8");
  if (Buffer.byteLength(text) > MAX_BUNDLE_BYTES) {
    return { valid: false, reason: `bundle exceeds maximum size (${MAX_BUNDLE_BYTES} bytes)` };
  }

  let sigstore: SigstoreLibs;
  try {
    sigstore = await loadSigstoreLibs();
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }

  // 1. Load the pinned trusted root.
  const rootPath = options.trustedRootPath ?? defaultTrustedRootPath();
  let trustedRoot: unknown;
  try {
    trustedRoot = sigstore.TrustedRoot.fromJSON(JSON.parse(await readFile(rootPath, "utf-8")));
  } catch (e) {
    return {
      valid: false,
      reason: `cannot load pinned Sigstore trusted root (${rootPath}): ${(e as Error).message}`,
    };
  }

  // 2. Parse the bundle (structural).
  let bundle: unknown;
  try {
    bundle = sigstore.bundleFromJSON(JSON.parse(text));
  } catch (e) {
    return { valid: false, reason: `invalid Sigstore bundle: ${(e as Error).message}` };
  }

  // 3. Full cryptographic verification (chain, SCTs, tlog, timestamps, DSSE).
  let signerSan: string | undefined;
  let signerIssuer: string | undefined;
  try {
    const verifier = new sigstore.Verifier(
      sigstore.toTrustMaterial(trustedRoot as never),
      {
        tlogThreshold: options.thresholds?.tlogThreshold ?? 1,
        ctlogThreshold: options.thresholds?.ctlogThreshold ?? 1,
        timestampThreshold: options.thresholds?.timestampThreshold ?? 1,
      },
    );
    const signer = verifier.verify(sigstore.toSignedEntity(bundle as never));
    signerSan = signer.identity?.subjectAlternativeName;
    signerIssuer = signer.identity?.extensions?.issuer;
  } catch (e) {
    return { valid: false, reason: `Sigstore verification failed: ${(e as Error).message}` };
  }

  // 4. Identity policy: the signer must match a pinned identity. The keyless
  //    equivalent of "unknown signing key".
  const pin = matchTrustedIdentity(signerSan, signerIssuer, identities);
  if (!pin) {
    return {
      valid: false,
      reason:
        `signer identity not pinned (identity: ${signerSan ?? "<none>"}, ` +
        `issuer: ${signerIssuer ?? "<none>"})`,
      identity: signerSan,
      issuer: signerIssuer,
    };
  }

  // 5. Extract the verified DSSE payload for the caller (verify-then-parse).
  const parsed = JSON.parse(text) as {
    dsseEnvelope?: { payload?: string; payloadType?: string };
  };
  const envelope = parsed.dsseEnvelope;
  if (!envelope?.payload || !envelope.payloadType) {
    return { valid: false, reason: "bundle does not contain a DSSE envelope" };
  }

  return {
    valid: true,
    publisher: pin.publisher,
    identity: signerSan,
    issuer: signerIssuer,
    payload: Buffer.from(envelope.payload, "base64"),
    payloadType: envelope.payloadType,
    signerFingerprint: signerFingerprint(signerIssuer!, signerSan!),
  };
}
