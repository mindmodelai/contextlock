// @contextlock/core - Shared verification engine
// Barrel file: re-exports all public APIs

// Canonicalizer (write-path normalization + verify-time diagnostic)
export { canonicalize, normalizeContent, normalizeFileOnDisk } from "./canonicalize.js";

// Hasher
export {
  sha256,
  sha256Bytes,
  computeFileHash,
  computeNormalizedFileHash,
  computeFingerprint,
} from "./hash.js";

// Machine-local key + ContextLock home (SPEC v2 5, 8)
export {
  contextlockHome,
  localKeyPath,
  ensureContextlockHome,
  loadOrCreateLocalKey,
  signWithLocalKey,
  verifyWithLocalKey,
  canonicalJson,
  base64urlEncode,
  base64urlDecode,
} from "./localkey.js";
export type { LocalKey } from "./localkey.js";

// Seal store (Mode 0: local TOFU)
export { SealStore, SEAL_STORE_SPEC } from "./seal.js";
export type { SealEntry, SealVerdict, SealStatus } from "./seal.js";

// Manifest (contextlock/2, SPEC v2 6.3)
export {
  parseManifest,
  serializeManifest,
  validateManifest,
  manifestPathError,
  MANIFEST_SPEC_VERSION,
  MAX_MANIFEST_BYTES,
  MAX_MANIFEST_FILES,
} from "./manifest.js";
export type {
  Manifest,
  ManifestFileEntry,
  ManifestPublisher,
  ValidationError,
} from "./manifest.js";

// DSSE envelope (SPEC v2 6.2)
export {
  pae,
  parseEnvelope,
  serializeEnvelope,
  validateEnvelope,
  signEnvelope,
  verifyEnvelope,
  envelopeVerifiesWithKey,
  verifyingKeyIds,
  b64Decode,
  b64Encode,
  MANIFEST_PAYLOAD_TYPE,
  ROOT_PAYLOAD_TYPE,
  ENVELOPE_FILENAME,
  MAX_ENVELOPE_BYTES,
} from "./dsse.js";
export type {
  DsseEnvelope,
  DsseSignature,
  CandidateKey,
  EnvelopeVerification,
  EnvelopeSigner,
} from "./dsse.js";

// Root of trust + rotation (SPEC v2 6.5)
export {
  validateRoot,
  parseRoot,
  rootExpired,
  verifyInitialRoot,
  verifyRootTransition,
  ROOT_SPEC_VERSION,
  ROOT_ENVELOPE_FILENAME,
} from "./root.js";
export type { RootFile, RootKey, RootVerification } from "./root.js";

// Anti-rollback state (SPEC v2 6.3, T7)
export { RollbackState, STATE_STORE_SPEC } from "./state.js";
export type { RollbackEntry, RollbackCheck } from "./state.js";

// Sign-time content lints (SPEC v2 6.7)
export { lintContent, buildLintAttestation, LINT_RULES } from "./lints.js";
export type { LintRule, LintHit } from "./lints.js";

// Trust Store
export { TrustStore, TRUST_STORE_SPEC } from "./trust-store.js";
export type {
  TrustedPublisher,
  PublisherPolicy,
  TrustStoreData,
} from "./trust-store.js";

// Policy Engine
// VerificationStatus is defined identically in both policy.ts and engine.ts.
// We export it from policy.ts as the canonical source.
export { evaluatePolicy } from "./policy.js";
export type {
  PolicyLevel,
  PolicyDecision,
  PolicyInput,
  VerificationStatus,
} from "./policy.js";

// Protected File Detector
export { DEFAULT_PATTERNS, isProtectedFile, findProtectedFiles } from "./detector.js";

// Filename Hash Extractor (Mode 1: change hints, not a security mode)
export { extractFilenameHash, verifyFilenameHash } from "./filename-hash.js";
export type { FilenameHashResult } from "./filename-hash.js";

// Manifest Cache
export { ManifestCache } from "./cache.js";
export type { CacheEntry } from "./cache.js";

// Verification Engine
// engine.ts also exports VerificationStatus (identical type) - alias it to avoid conflict.
export { VerificationEngine } from "./engine.js";
export { VerificationStatus as EngineVerificationStatus } from "./engine.js";
export type {
  VerificationEngineConfig,
  VerificationResult,
  PackageVerificationResult,
} from "./engine.js";

// Tool Adapter Interface
export type { ToolAdapter } from "./adapter.js";
