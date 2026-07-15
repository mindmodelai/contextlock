/**
 * Verification Engine - orchestrates the full ContextLock verification flow.
 *
 * SPEC v2: consults TWO evidence sources for every file:
 *   - the machine-local SEAL store (Mode 0, trust-on-first-use), and
 *   - the signed MANIFEST chain (Mode 2, publisher trust) - a DSSE envelope
 *     (`contextlock.dsse.json`) carrying a contextlock/2 manifest.
 *
 * Hashing is over the EXACT bytes on disk (SPEC v2 6.1); canonicalization is
 * used only as a line-endings-only diagnostic on a mismatch.
 *
 * Manifest discovery is BOUNDED (SPEC v2 6.3 / T10): the walk-up stops at the
 * workspace boundary (configured protected-root, else the enclosing git repo
 * root, else the user home when the file lives under it), the FIRST envelope
 * found wins (deeper manifests shadow shallower ones), and the file's relative
 * path must appear in that manifest.
 *
 * Verify-then-parse (SPEC v2 6.2): the manifest consumed here is the decoded
 * payload of the VERIFIED envelope, never a re-read of a sidecar file.
 *
 * Anti-rollback (SPEC v2 6.3 / T7): per-(package, key) highest-version-seen
 * state rejects any manifest version strictly below the baseline.
 */

import { readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseManifest, validateManifest } from "./manifest.js";
import type { Manifest } from "./manifest.js";
import {
  ENVELOPE_FILENAME,
  MANIFEST_PAYLOAD_TYPE,
  MAX_ENVELOPE_BYTES,
  parseEnvelope,
  verifyEnvelope,
} from "./dsse.js";
import type { DsseEnvelope, EnvelopeVerification } from "./dsse.js";
import {
  SIGSTORE_BUNDLE_FILENAME,
  verifySigstoreBundle,
} from "./sigstore.js";
import type { SigstoreVerifyOptions } from "./sigstore.js";
import { TrustStore } from "./trust-store.js";
import { sha256 } from "./hash.js";
import { canonicalize } from "./canonicalize.js";
import { SealStore } from "./seal.js";
import { RollbackState } from "./state.js";
import { isProtectedFile } from "./detector.js";
import type { PolicyLevel } from "./policy.js";

// ---- Types ----

export type VerificationStatus =
  | "trusted"
  | "sealed"
  | "sealed+trusted"
  | "modified"
  | "untrusted"
  | "revoked"
  | "expired"
  | "rollback"
  | "error"
  | "seal-store-unavailable";

export interface VerificationResult {
  status: VerificationStatus;
  publisher?: string;
  keyId?: string;
  manifestSource?: string;
  fileHash?: string;
  expectedHash?: string;
  reason?: string;
  expiresAt?: string;
  warning?: string;
  /** Seal timestamp when the verdict rests on a local seal. */
  sealedAt?: string;
  /** Number of distinct trusted keys that signed (reviewer multi-signatures). */
  signerCount?: number;
  /** Profile B: the signer's certificate identity (SAN). */
  identity?: string;
  /** Profile B: the signer's OIDC issuer. */
  issuer?: string;
}

export interface VerificationEngineConfig {
  trustStorePath: string;
  cachePath: string;
  protectedPatterns: string[];
  policyLevel: PolicyLevel;
  /** Optional override for the seal store path. Defaults to CONTEXTLOCK_HOME/seals.json. */
  sealStorePath?: string;
  /** Optional override for the anti-rollback state path. Defaults to CONTEXTLOCK_HOME/state.json. */
  stateStorePath?: string;
  /**
   * Optional explicit workspace boundary for manifest discovery (the
   * "configured protected-root" of SPEC v2 6.3). When unset, the boundary is
   * the enclosing git repo root, else the user home when the file lives under
   * it, else the file's own directory (no walk-up).
   */
  workspaceRoot?: string;
  /**
   * Minimum number of DISTINCT trusted keys whose signatures must verify
   * (reviewer multi-signatures). Default 1. Values > 1 cannot be satisfied by
   * a Profile B bundle (single certificate).
   */
  requiredSigners?: number;
  /** Profile B (Sigstore) verification options: pinned root path, thresholds. */
  sigstore?: SigstoreVerifyOptions;
}

/** Result of verifying a whole package directory (used by `contextlock install`). */
export interface PackageVerificationResult {
  ok: boolean;
  status: VerificationStatus;
  reason?: string;
  publisher?: string;
  keyId?: string;
  manifest?: Manifest;
  envelopePath?: string;
  warning?: string;
  files: Array<{
    path: string;
    status: "ok" | "modified" | "missing" | "length-mismatch";
    expectedHash?: string;
    computedHash?: string;
  }>;
}

// ---- Helpers ----

const LINE_ENDINGS_HINT =
  "difference is line endings only (CRLF vs LF); re-seal or restore LF endings";

const NO_LINTS_WARNING = "manifest lacks lint attestations (SPEC v2 6.7)";

/**
 * Resolves the workspace boundary for bounded manifest discovery.
 */
function resolveBoundary(fileDir: string, configured?: string): string {
  if (configured) return resolve(configured);

  let current = resolve(fileDir);
  while (true) {
    if (existsSync(join(current, ".git"))) return current;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }

  const home = resolve(homedir());
  const relToHome = relative(home, resolve(fileDir));
  if (relToHome === "" || (!relToHome.startsWith("..") && !isAbsolute(relToHome))) {
    return home;
  }
  return resolve(fileDir);
}

/** The two Profile evidence artifacts. Profile A shadows Profile B in a dir. */
type EvidenceKind = "dsse" | "sigstore";

interface Evidence {
  dir: string;
  kind: EvidenceKind;
  path: string;
}

function evidenceIn(dir: string): Evidence | undefined {
  const dssePath = join(dir, ENVELOPE_FILENAME);
  if (existsSync(dssePath)) return { dir, kind: "dsse", path: dssePath };
  const bundlePath = join(dir, SIGSTORE_BUNDLE_FILENAME);
  if (existsSync(bundlePath)) return { dir, kind: "sigstore", path: bundlePath };
  return undefined;
}

/**
 * Walk up from `startDir` looking for contextlock.dsse.json (Profile A) or
 * contextlock.sigstore.json (Profile B), stopping at the boundary
 * (inclusive). First evidence found wins (deeper shadows shallower).
 */
function locateEvidence(startDir: string, boundary: string): Evidence | undefined {
  let current = resolve(startDir);
  const stop = resolve(boundary);

  // If the file is not under the boundary at all, only its own directory is
  // consulted (no walk-up).
  const relToBoundary = relative(stop, current);
  const underBoundary =
    relToBoundary === "" || (!relToBoundary.startsWith("..") && !isAbsolute(relToBoundary));
  if (!underBoundary) {
    return evidenceIn(current);
  }

  while (true) {
    const found = evidenceIn(current);
    if (found) return found;
    if (current === stop) break;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return undefined;
}

// ---- VerificationEngine ----

export class VerificationEngine {
  private config: VerificationEngineConfig;

  constructor(config: VerificationEngineConfig) {
    this.config = config;
  }

  /**
   * Returns true if the file path matches any of the configured protected patterns.
   */
  isProtected(filePath: string): boolean {
    return isProtectedFile(filePath, this.config.protectedPatterns);
  }

  /**
   * Full verification flow for a single file, combining seal + manifest evidence.
   *
   * Combination rules (SPEC v2 5):
   *   seal ok + no manifest     -> sealed
   *   seal ok + manifest trusted-> sealed+trusted
   *   seal mismatch             -> modified  (seal wins: the user pinned it)
   *   no seal + manifest trusted-> trusted
   *   seal store unavailable    -> seal-store-unavailable (fail closed)
   *   otherwise                 -> the manifest verdict (untrusted/rollback/...)
   */
  async verify(filePath: string): Promise<VerificationResult> {
    const absPath = resolve(filePath);

    // 1. Seal evidence (Mode 0). A corrupt/tampered store fails closed for
    //    every file rather than silently reporting "unsealed".
    const sealStore = new SealStore(this.config.sealStorePath);
    await sealStore.load();
    const sealVerdict = await sealStore.verifySeal(absPath);

    if (sealVerdict.status === "store-unavailable") {
      return {
        status: "seal-store-unavailable",
        reason:
          sealVerdict.reason ??
          "seal store unavailable: possible tampering (treat as unverifiable)",
      };
    }

    // Seal mismatch wins over any manifest verdict: the user explicitly pinned
    // these bytes, so a change is a violation regardless of publisher status.
    if (sealVerdict.status === "seal-modified") {
      const reason = sealVerdict.lineEndingsOnly
        ? `sealed content modified; ${LINE_ENDINGS_HINT}`
        : "sealed content modified since it was sealed";
      return {
        status: "modified",
        expectedHash: sealVerdict.expectedHash,
        fileHash: sealVerdict.actualHash,
        reason,
        sealedAt: sealVerdict.sealedAt,
      };
    }

    // 2. Manifest evidence (Mode 2).
    const manifestResult = await this.verifyViaManifest(absPath);

    // 3. Combine.
    if (sealVerdict.status === "sealed") {
      if (manifestResult.status === "trusted") {
        return { ...manifestResult, status: "sealed+trusted", sealedAt: sealVerdict.sealedAt };
      }
      return {
        status: "sealed",
        fileHash: sealVerdict.actualHash,
        expectedHash: sealVerdict.expectedHash,
        sealedAt: sealVerdict.sealedAt,
        reason: sealVerdict.note
          ? `sealed via local trust-on-first-use (${sealVerdict.note})`
          : "sealed via local trust-on-first-use",
      };
    }

    // Unsealed: the manifest verdict stands.
    return manifestResult;
  }

  /**
   * Verifies a DSSE envelope (signature, manifest schema, anti-rollback,
   * expiry) WITHOUT checking any covered file. Returns the manifest-level
   * verdict plus the verified manifest for callers that go on to check files
   * (verify-then-parse: the manifest comes from the verified payload).
   */
  async verifyEnvelopeFile(
    envelopePath: string,
  ): Promise<{ result: VerificationResult; manifest?: Manifest; verification?: EnvelopeVerification }> {
    // 1. Read + size-check the envelope.
    let envStat;
    try {
      envStat = await stat(envelopePath);
    } catch {
      return { result: { status: "error", reason: `cannot read envelope: ${envelopePath}` } };
    }
    if (envStat.size > MAX_ENVELOPE_BYTES) {
      return {
        result: {
          status: "error",
          reason: `envelope exceeds maximum size (${MAX_ENVELOPE_BYTES} bytes)`,
        },
      };
    }

    let envelopeContent: Buffer;
    try {
      envelopeContent = await readFile(envelopePath);
    } catch {
      return { result: { status: "error", reason: `cannot read envelope: ${envelopePath}` } };
    }

    // 2. Parse the envelope (structural validation only; no trust yet).
    let envelope: DsseEnvelope;
    try {
      envelope = parseEnvelope(envelopeContent);
    } catch (e) {
      return { result: { status: "error", reason: `invalid envelope: ${(e as Error).message}` } };
    }

    // 3. The payloadType is covered by the signature (T12); a non-manifest
    //    payload is a hard error before any trust decision.
    if (envelope.payloadType !== MANIFEST_PAYLOAD_TYPE) {
      return {
        result: {
          status: "error",
          reason: `unexpected payloadType "${envelope.payloadType}" (expected "${MANIFEST_PAYLOAD_TYPE}")`,
        },
      };
    }

    // 4. Load trust state and verify the signature over PAE.
    const trustStore = new TrustStore();
    try {
      await trustStore.load(this.config.trustStorePath);
    } catch (e) {
      return {
        result: { status: "error", reason: `cannot load trust store: ${(e as Error).message}` },
      };
    }

    const verification = await verifyEnvelope(envelope, trustStore.candidateKeys());
    if (!verification.valid) {
      if (verification.reason === "key revoked") {
        return {
          result: {
            status: "revoked",
            keyId: verification.keyId,
            publisher: verification.publisher,
            reason: verification.reason,
          },
        };
      }
      return {
        result: {
          status: "untrusted",
          keyId: verification.keyId,
          publisher: verification.publisher,
          reason: verification.reason ?? "signature verification failed",
        },
      };
    }

    // 5. Reviewer multi-signature threshold (distinct trusted keys).
    const signers = verification.signers ?? [];
    const requiredSigners = this.config.requiredSigners ?? 1;
    if (signers.length < requiredSigners) {
      return {
        result: {
          status: "untrusted",
          keyId: verification.keyId,
          publisher: verification.publisher,
          signerCount: signers.length,
          reason: `insufficient signatures: ${signers.length} distinct trusted key(s) verified, ${requiredSigners} required`,
        },
      };
    }

    const outcome = await this.evaluateManifestPayload({
      payload: verification.payload!,
      source: envelopePath,
      publisher: verification.publisher,
      keyId: verification.keyId,
      signerFingerprints: signers.map((s) => s.keyFingerprint),
      signerCount: signers.length,
      trustStore,
    });
    return { ...outcome, verification };
  }

  /**
   * Verifies a Profile B Sigstore bundle (keyless): full Sigstore
   * verification against the pinned trusted root, identity-pin policy, then
   * the same manifest checks as Profile A (schema, anti-rollback, expiry).
   */
  async verifySigstoreFile(
    bundlePath: string,
  ): Promise<{ result: VerificationResult; manifest?: Manifest }> {
    let bundleContent: Buffer;
    try {
      bundleContent = await readFile(bundlePath);
    } catch {
      return { result: { status: "error", reason: `cannot read bundle: ${bundlePath}` } };
    }

    const trustStore = new TrustStore();
    try {
      await trustStore.load(this.config.trustStorePath);
    } catch (e) {
      return {
        result: { status: "error", reason: `cannot load trust store: ${(e as Error).message}` },
      };
    }

    const verification = await verifySigstoreBundle(
      bundleContent,
      trustStore.listIdentities(),
      this.config.sigstore,
    );
    if (!verification.valid) {
      return {
        result: {
          status: "untrusted",
          identity: verification.identity,
          issuer: verification.issuer,
          reason: verification.reason ?? "Sigstore verification failed",
        },
      };
    }

    // The payloadType is covered by the DSSE signature inside the bundle.
    if (verification.payloadType !== MANIFEST_PAYLOAD_TYPE) {
      return {
        result: {
          status: "error",
          reason: `unexpected payloadType "${verification.payloadType}" (expected "${MANIFEST_PAYLOAD_TYPE}")`,
        },
      };
    }

    // A bundle carries exactly one signing identity; a multi-signer
    // requirement cannot be met by Profile B alone.
    const requiredSigners = this.config.requiredSigners ?? 1;
    if (requiredSigners > 1) {
      return {
        result: {
          status: "untrusted",
          identity: verification.identity,
          issuer: verification.issuer,
          signerCount: 1,
          reason: `insufficient signatures: a Sigstore bundle carries 1 signer, ${requiredSigners} required`,
        },
      };
    }

    const outcome = await this.evaluateManifestPayload({
      payload: verification.payload!,
      source: bundlePath,
      publisher: verification.publisher,
      keyId: verification.identity,
      signerFingerprints: [verification.signerFingerprint!],
      signerCount: 1,
      trustStore,
    });
    if (outcome.result.status === "trusted" || outcome.result.status === "expired") {
      outcome.result.identity = verification.identity;
      outcome.result.issuer = verification.issuer;
    }
    return outcome;
  }

  /**
   * Shared post-signature manifest evaluation (verify-then-parse bytes in):
   * schema validation, anti-rollback across every verified signer, expiry,
   * and lint-attestation warnings.
   */
  private async evaluateManifestPayload(opts: {
    payload: Buffer;
    source: string;
    publisher?: string;
    keyId?: string;
    signerFingerprints: string[];
    signerCount: number;
    trustStore: TrustStore;
  }): Promise<{ result: VerificationResult; manifest?: Manifest }> {
    // Verify-then-parse: the manifest is the verified payload's bytes.
    let manifest: Manifest;
    try {
      manifest = parseManifest(opts.payload);
    } catch (e) {
      return { result: { status: "error", reason: `invalid manifest: ${(e as Error).message}` } };
    }

    const manifestErrors = validateManifest(manifest);
    if (manifestErrors.length > 0) {
      return {
        result: {
          status: "error",
          reason: `manifest validation failed: ${manifestErrors.map((e) => e.message).join("; ")}`,
        },
      };
    }

    // Anti-rollback (T7). A corrupt/tampered state store fails CLOSED. The
    // baseline is checked and recorded against EVERY verified signer so a
    // rollback is caught regardless of which signature the attacker replays.
    const state = new RollbackState(this.config.stateStorePath);
    await state.load();
    if (!state.available) {
      return {
        result: {
          status: "error",
          reason: state.unavailableReason ?? "rollback state unavailable",
        },
      };
    }
    for (const fingerprint of opts.signerFingerprints) {
      const rollbackCheck = state.check(manifest.package, fingerprint, manifest.version);
      if (!rollbackCheck.ok) {
        return {
          result: {
            status: "rollback",
            keyId: opts.keyId,
            publisher: opts.publisher,
            reason:
              `manifest version ${manifest.version} is older than the highest ` +
              `version already seen (${rollbackCheck.highestSeen}) for package ` +
              `"${manifest.package}" - possible rollback attack (T7)`,
          },
        };
      }
    }
    // Raise the baseline: the manifest itself verified, so this version has
    // been "seen" regardless of the per-file verdicts that may follow.
    for (const fingerprint of opts.signerFingerprints) {
      await state.record(
        manifest.package,
        fingerprint,
        manifest.version,
        opts.publisher ?? "unknown",
      );
    }

    // Expiry (required field in contextlock/2; T8).
    let warning: string | undefined;
    const expiresAt = new Date(manifest.expires_at);
    if (expiresAt.getTime() < Date.now()) {
      const publisherEntry =
        opts.trustStore.getPublisher(opts.keyId ?? "") ??
        opts.trustStore.getPublisherByName(opts.publisher ?? "");
      const allowExpired = publisherEntry?.policy?.allow_expired_manifest ?? false;
      if (!allowExpired) {
        return {
          result: {
            status: "expired",
            expiresAt: manifest.expires_at,
            keyId: opts.keyId,
            publisher: opts.publisher,
          },
          manifest,
        };
      }
      warning = "manifest is expired but allowed by publisher policy";
    }

    // Missing lint attestations are worth a warning (SPEC v2 6.7).
    if (!manifest.lints) {
      warning = warning ? `${warning}; ${NO_LINTS_WARNING}` : NO_LINTS_WARNING;
    }

    const result: VerificationResult = {
      status: "trusted",
      publisher: opts.publisher,
      keyId: opts.keyId,
      manifestSource: opts.source,
      signerCount: opts.signerCount,
    };
    if (warning) {
      result.warning = warning;
      if (expiresAt.getTime() < Date.now()) result.expiresAt = manifest.expires_at;
    }
    return { result, manifest };
  }

  /**
   * Manifest-chain verification for a single file. Hashes exact bytes on disk.
   * On a hash mismatch, computes the LF-normalized hash purely to append a
   * line-endings-only diagnostic (verdict stays `modified`).
   */
  private async verifyViaManifest(absPath: string): Promise<VerificationResult> {
    const fileDir = dirname(absPath);

    // 1. Bounded discovery (T10): stop at the workspace boundary, first found wins.
    const boundary = resolveBoundary(fileDir, this.config.workspaceRoot);
    const evidence = locateEvidence(fileDir, boundary);
    if (!evidence) {
      return { status: "untrusted", reason: "no manifest found" };
    }

    const { result: envResult, manifest } =
      evidence.kind === "dsse"
        ? await this.verifyEnvelopeFile(evidence.path)
        : await this.verifySigstoreFile(evidence.path);
    if (envResult.status !== "trusted") {
      return envResult;
    }

    // 2. Containment (T10): the file's relative path must appear in THIS
    //    manifest. Deeper manifests shadow shallower ones - a miss here does
    //    NOT continue the walk-up.
    const relPath = relative(evidence.dir, absPath).replace(/\\/g, "/");
    if (relPath.startsWith("..") || isAbsolute(relPath)) {
      return { status: "untrusted", reason: "file resolves outside the manifest directory" };
    }
    const entry = manifest!.files.find((f) => f.path === relPath);
    if (!entry) {
      return { status: "untrusted", reason: "file not listed in manifest" };
    }

    // 3. Length is enforced BEFORE hashing (endless-data defense, SPEC v2 6.3).
    let fileStat;
    try {
      fileStat = await stat(absPath);
    } catch (e) {
      return { status: "error", reason: `cannot read file: ${(e as Error).message}` };
    }
    if (fileStat.size !== entry.length) {
      return {
        status: "modified",
        expectedHash: entry.sha256,
        publisher: envResult.publisher,
        keyId: envResult.keyId,
        reason: `file length mismatch (expected ${entry.length} bytes, found ${fileStat.size})`,
      };
    }

    // 4. Hash the EXACT bytes on disk (SPEC v2 6.1).
    let fileContent: Buffer;
    try {
      fileContent = await readFile(absPath);
    } catch (e) {
      return { status: "error", reason: `cannot read file: ${(e as Error).message}` };
    }
    const fileHash = sha256(fileContent);

    if (fileHash === entry.sha256) {
      return {
        ...envResult,
        status: "trusted",
        fileHash,
        expectedHash: entry.sha256,
      };
    }

    // Hash mismatch. Compute the LF-normalized hash purely for diagnostics.
    const normalizedHash = sha256(canonicalize(fileContent));
    const reason =
      normalizedHash === entry.sha256
        ? `file modified since signing; ${LINE_ENDINGS_HINT}`
        : "file modified since signing";

    return {
      status: "modified",
      fileHash,
      expectedHash: entry.sha256,
      publisher: envResult.publisher,
      keyId: envResult.keyId,
      reason,
    };
  }

  /**
   * Verifies a whole package directory against its envelope: signature,
   * manifest schema, anti-rollback, expiry, then EVERY listed file's length
   * and hash. Used by `contextlock install` (Layer 1: verify BEFORE placing
   * files) and pre-publish checks.
   */
  async verifyPackage(dir: string): Promise<PackageVerificationResult> {
    const evidence = evidenceIn(resolve(dir));
    if (!evidence) {
      return {
        ok: false,
        status: "untrusted",
        reason: `no ${ENVELOPE_FILENAME} or ${SIGSTORE_BUNDLE_FILENAME} found in package directory`,
        envelopePath: join(resolve(dir), ENVELOPE_FILENAME),
        files: [],
      };
    }

    const envelopePath = evidence.path;
    const { result, manifest } =
      evidence.kind === "dsse"
        ? await this.verifyEnvelopeFile(envelopePath)
        : await this.verifySigstoreFile(envelopePath);

    if (result.status !== "trusted") {
      return {
        ok: false,
        status: result.status,
        reason: result.reason ?? result.status,
        publisher: result.publisher,
        keyId: result.keyId,
        manifest,
        envelopePath,
        files: [],
      };
    }

    const files: PackageVerificationResult["files"] = [];
    let allOk = true;
    for (const entry of manifest!.files) {
      const filePath = join(resolve(dir), entry.path);
      let fileStat;
      try {
        fileStat = await stat(filePath);
      } catch {
        allOk = false;
        files.push({ path: entry.path, status: "missing", expectedHash: entry.sha256 });
        continue;
      }
      if (fileStat.size !== entry.length) {
        allOk = false;
        files.push({ path: entry.path, status: "length-mismatch", expectedHash: entry.sha256 });
        continue;
      }
      const content = await readFile(filePath);
      const hash = sha256(content);
      if (hash === entry.sha256) {
        files.push({ path: entry.path, status: "ok", expectedHash: entry.sha256, computedHash: hash });
      } else {
        allOk = false;
        files.push({ path: entry.path, status: "modified", expectedHash: entry.sha256, computedHash: hash });
      }
    }

    return {
      ok: allOk,
      status: allOk ? "trusted" : "modified",
      reason: allOk ? undefined : "one or more files failed verification",
      publisher: result.publisher,
      keyId: result.keyId,
      manifest,
      envelopePath,
      warning: result.warning,
      files,
    };
  }
}
