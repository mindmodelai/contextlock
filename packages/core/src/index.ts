// @contextlock/core — Shared verification engine
// Barrel file: re-exports all public APIs

// Canonicalizer
export { canonicalize } from "./canonicalize.js";

// Hasher
export { sha256, sha256Bytes, computeFileHash, computeFingerprint } from "./hash.js";

// Manifest Parser
export {
  parseManifest,
  serializeManifest,
  parseSignature,
  serializeSignature,
  validateManifest,
  validateSignature,
} from "./manifest.js";
export type {
  Manifest,
  ManifestFileEntry,
  DetachedSignature,
  ValidationError,
} from "./manifest.js";

// Signature Verifier
export { verifySignature } from "./signature.js";
export type {
  SignatureVerificationInput,
  SignatureVerificationOutput,
} from "./signature.js";

// Trust Store
export { TrustStore } from "./trust-store.js";
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

// Filename Hash Extractor
export { extractFilenameHash, verifyFilenameHash } from "./filename-hash.js";
export type { FilenameHashResult } from "./filename-hash.js";

// Manifest Cache
export { ManifestCache } from "./cache.js";
export type { CacheEntry } from "./cache.js";

// Verification Engine
// engine.ts also exports VerificationStatus (identical type) — alias it to avoid conflict.
export { VerificationEngine } from "./engine.js";
export { VerificationStatus as EngineVerificationStatus } from "./engine.js";
export type {
  VerificationEngineConfig,
  VerificationResult,
} from "./engine.js";

// Tool Adapter Interface
export type { ToolAdapter } from "./adapter.js";
