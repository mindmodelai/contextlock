# Implementation Plan: ContextLock

## Overview

Incremental implementation of the ContextLock TCV plugin system as a TypeScript monorepo. Tasks build from foundational core utilities up through the verification engine, CLI tools, and tool adapters. Property-based tests (fast-check) and unit tests (vitest) are woven in close to each implementation step. All code is TypeScript; test runner is vitest; property testing uses fast-check with minimum 100 iterations per property.

## Tasks

- [x] 1. Initialize monorepo structure and shared configuration
  - Create top-level `package.json` with workspaces: `packages/core`, `packages/cli-publisher`, `packages/cli-user`, `packages/adapter-claude-code`, `packages/adapter-openclaw`
  - Create `tsconfig.json` (base) and per-package `tsconfig.json` extending it
  - Create `vitest.config.ts` at root
  - Add dependencies: `vitest`, `fast-check`, `@noble/ed25519`, `@noble/hashes`, `minimatch` (or `picomatch`)
  - Create `packages/core/src/index.ts`, `packages/core/package.json`
  - Create placeholder `package.json` for each package
  - _Requirements: Design architecture overview_

- [x] 2. Implement Canonicalizer and Hasher
  - [x] 2.1 Implement `packages/core/src/canonicalize.ts`
    - Export `canonicalize(content: Buffer): Buffer` — strip UTF-8 BOM, convert CRLF/CR to LF
    - _Requirements: 1.1, 1.2, 1.3_

  - [x] 2.2 Implement `packages/core/src/hash.ts`
    - Export `sha256(data: Buffer): string` (lowercase hex), `sha256Bytes(data: Buffer): Buffer`, `computeFileHash(filePath: string): Promise<string>`, `computeFingerprint(publicKey: Buffer): string`
    - _Requirements: 1.4, 5.2, 20.1, 20.2_

  - [x] 2.3 Write property test: Canonicalization idempotence
    - **Property 1: Canonicalization idempotence**
    - Generate random strings with mixed line endings (LF, CRLF, CR) and optional BOM; assert `canonicalize(canonicalize(x)) == canonicalize(x)`
    - **Validates: Requirements 1.1, 1.2, 1.3**

  - [x] 2.4 Write property test: Cross-platform hash equivalence
    - **Property 2: Cross-platform hash equivalence**
    - For any content string, generate LF/CRLF/CR/BOM variants; assert all produce the same SHA-256 after canonicalization
    - **Validates: Requirements 1.4**

  - [x] 2.5 Write property test: Key fingerprint is SHA-256 of public key
    - **Property 8: Key fingerprint is SHA-256 of public key**
    - Generate random 32-byte buffers as mock public keys; assert `computeFingerprint(key) === sha256(key)`
    - **Validates: Requirements 5.2, 20.1, 20.2**

  - [x] 2.6 Write unit tests for Canonicalizer and Hasher
    - Test BOM-only content, empty content, already-canonical content, known SHA-256 vectors
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 3. Implement Manifest Parser and Signature Parser
  - [x] 3.1 Implement `packages/core/src/manifest.ts`
    - Define `Manifest`, `ManifestFileEntry`, `DetachedSignature` interfaces
    - Export `parseManifest`, `serializeManifest`, `parseSignature`, `serializeSignature`, `validateManifest`, `validateSignature`
    - Validate schema field, required fields, no duplicate paths, ISO 8601 dates
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 13.1, 13.2, 13.3, 13.4_

  - [x] 3.2 Write property test: Manifest round-trip
    - **Property 3: Manifest round-trip**
    - Generate random valid Manifest objects; assert `parseManifest(serializeManifest(m))` equals `m`
    - **Validates: Requirements 2.5, 13.3**

  - [x] 3.3 Write property test: Detached signature round-trip
    - **Property 4: Detached signature round-trip**
    - Generate random valid DetachedSignature objects; assert `parseSignature(serializeSignature(s))` equals `s`
    - **Validates: Requirements 13.4**

  - [x] 3.4 Write property test: Invalid manifest rejection
    - **Property 5: Invalid manifest rejection**
    - Generate JSON objects missing required fields or with wrong types; assert parser returns error with descriptive reason
    - **Validates: Requirements 2.2**

  - [x] 3.5 Write unit tests for Manifest Parser
    - Test duplicate file paths, missing fields, wrong schema version, valid round-trip with known fixture
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [x] 4. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement Signature Verifier and Trust Store
  - [x] 5.1 Implement `packages/core/src/trust-store.ts`
    - Define `TrustedPublisher`, `PublisherPolicy`, `TrustStoreData` interfaces
    - Implement `TrustStore` class: `load`, `save`, `addPublisher`, `removePublisher`, `getPublisher`, `revokeKey`, `listPublishers`
    - Persist as `tcv-truststore/v1` JSON
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 9.1_

  - [x] 5.2 Implement `packages/core/src/signature.ts`
    - Export `verifySignature(input: SignatureVerificationInput): SignatureVerificationOutput`
    - Steps: compute manifest SHA-256, compare with sig.manifest_sha256, lookup key_id, check revocation, verify Ed25519 signature
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 9.2, 9.3_

  - [x] 5.3 Write property test: Sign-then-verify round-trip
    - **Property 6: Sign-then-verify round-trip**
    - Generate random manifest content and Ed25519 keypairs; sign with private key, verify with public key succeeds; verify with different public key fails
    - **Validates: Requirements 3.2, 3.4, 12.1, 12.2, 12.3**

  - [x] 5.4 Write property test: Ed25519 keypair validity
    - **Property 13: Ed25519 keypair validity**
    - Generate keypairs; sign arbitrary messages; verify with matching public key succeeds
    - **Validates: Requirements 10.1**

  - [x] 5.5 Write property test: Trust store add-then-remove round-trip
    - **Property 9: Trust store add-then-remove round-trip**
    - Generate random TrustedPublisher entries; add then remove by key_id; assert publisher absent and other entries unchanged
    - **Validates: Requirements 5.3**

  - [x] 5.6 Write property test: Revoked key rejection
    - **Property 12: Revoked key rejection**
    - For any signature with a revoked key_id in the trust store, assert verification returns `revoked` regardless of signature validity
    - **Validates: Requirements 9.1, 9.2, 9.3**

  - [x] 5.7 Write unit tests for Signature Verifier and Trust Store
    - Test unknown key_id, revoked key with valid signature, manifest hash mismatch, valid signature flow
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 5.1, 5.3, 9.1, 9.2, 9.3_

- [x] 6. Implement Policy Engine
  - [x] 6.1 Implement `packages/core/src/policy.ts`
    - Define `PolicyLevel`, `PolicyDecision`, `PolicyInput` types
    - Export `evaluatePolicy(input: PolicyInput): PolicyDecision`
    - Implement policy matrix: strict blocks all non-trusted; balanced allows trusted, warns untrusted/expired, blocks modified/revoked/error; audit allows all
    - Support per-publisher policy overrides
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.7_

  - [x] 6.2 Write property test: Policy engine evaluation
    - **Property 10: Policy engine evaluation**
    - Generate random VerificationResult statuses and policy levels; assert decisions match the policy matrix; per-publisher overrides take precedence
    - **Validates: Requirements 7.2, 7.3, 7.4, 7.7**

  - [x] 6.3 Write unit tests for Policy Engine
    - Test each cell of the policy matrix with concrete inputs; test per-publisher override scenarios
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.7_

- [x] 7. Implement Protected File Detector and Filename Hash Extractor
  - [x] 7.1 Implement `packages/core/src/detector.ts`
    - Export `DEFAULT_PATTERNS`, `isProtectedFile(filePath, patterns): boolean`, `findProtectedFiles(directory, patterns): Promise<string[]>`
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 7.2 Implement `packages/core/src/filename-hash.ts`
    - Export `extractFilenameHash(filename): string | null`, `verifyFilenameHash(filePath): Promise<FilenameHashResult>`
    - Filename hash is advisory only — never produces `trusted` status
    - _Requirements: 16.1, 16.2, 16.3, 16.4_

  - [x] 7.3 Write property test: Protected file pattern matching
    - **Property 15: Protected file pattern matching**
    - Generate random file paths and glob patterns; assert `isProtectedFile` returns true iff path matches at least one pattern
    - **Validates: Requirements 6.1, 6.3**

  - [x] 7.4 Write property test: Filename hash extraction and verification
    - **Property 16: Filename hash extraction and verification**
    - Generate files with `<name>.<hex-hash>.<ext>` names; assert hash extraction and prefix comparison work; assert filename hash alone never returns `trusted`
    - **Validates: Requirements 16.1, 16.2, 16.3, 16.4**

  - [x] 7.5 Write unit tests for Detector and Filename Hash
    - Test default patterns against known filenames (SKILL.md, CLAUDE.md, foo.prompt.md, etc.); test filename hash extraction edge cases
    - _Requirements: 6.1, 6.2, 16.1, 16.2_

- [x] 8. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement Manifest Cache
  - [x] 9.1 Implement `packages/core/src/cache.ts`
    - Implement `ManifestCache` class: `get`, `put`, `remove`, `refresh`, `listEntries`
    - Index by package name, version, key fingerprint
    - Record `fetchedAt` and `expiresAt`
    - Reject writes of unsigned/unverified manifests (require a `verified` flag or signature proof)
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5_

  - [x] 9.2 Write property test: Manifest cache stores only verified manifests
    - **Property 18: Manifest cache stores only verified manifests**
    - Assert cache rejects unverified manifests; assert cached manifests are retrievable by package, version, fingerprint
    - **Validates: Requirements 15.1, 15.4**

  - [x] 9.3 Write unit tests for Manifest Cache
    - Test put/get/remove lifecycle, reject unverified write, refresh removes failed entries
    - _Requirements: 15.1, 15.2, 15.4, 15.5_

- [x] 10. Implement Verification Engine
  - [x] 10.1 Implement `packages/core/src/engine.ts`
    - Implement `VerificationEngine` class with `verify(filePath)`, `isProtected(filePath)`, `verifyManifest(manifestPath, signaturePath)`
    - Orchestrate full flow: locate manifest/sig, parse, validate schema, verify signature, check revocation, check expiry, canonicalize file, compute hash, compare with manifest entry
    - Return `VerificationResult` with all required fields per status type
    - _Requirements: 2.1, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.2, 4.3, 4.4, 6.4, 8.1, 8.2, 8.3, 9.2, 9.3, 9.4, 18.1, 18.2, 18.3, 18.4, 18.5, 18.6_

  - [x] 10.2 Write property test: File hash verification correctness
    - **Property 7: File hash verification correctness**
    - Generate file content and build a valid signed manifest; assert unmodified file returns `trusted`; mutate a single byte and assert `modified` with both hashes
    - **Validates: Requirements 4.1, 4.2**

  - [x] 10.3 Write property test: Manifest expiry evaluation
    - **Property 11: Manifest expiry evaluation**
    - Generate manifests with `expires_at` in the past; assert `expired` when `allow_expired_manifest` is false; assert `trusted` with warning when true
    - **Validates: Requirements 8.1, 8.2, 8.3**

  - [x] 10.4 Write property test: Verification result completeness
    - **Property 17: Verification result completeness**
    - For each status type, generate a VerificationResult and assert required fields are present: trusted→publisher+keyId, modified→fileHash+expectedHash, untrusted→reason, revoked→keyId, expired→expiresAt, error→reason
    - **Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.6**

  - [x] 10.5 Write unit tests for Verification Engine
    - Test full verify flow with fixture package (trusted, modified, untrusted, no manifest, revoked key, expired manifest)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 8.1, 8.2, 8.3, 9.2, 9.3_

- [x] 11. Wire core package exports
  - Export all public APIs from `packages/core/src/index.ts`
  - Ensure all core components are importable from `@contextlock/core`
  - _Requirements: Design architecture_

- [x] 12. Checkpoint — Ensure all core tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Implement Publisher CLI
  - [x] 13.1 Implement `packages/cli-publisher/src/commands/init-key.ts`
    - Generate Ed25519 keypair using `@noble/ed25519`
    - Save private key and public key to separate files
    - Display key fingerprint
    - _Requirements: 10.1, 10.2, 10.3, 10.4_

  - [x] 13.2 Implement `packages/cli-publisher/src/commands/build-manifest.ts`
    - Scan directory for files matching protected patterns
    - Compute SHA-256 of each file using canonicalization
    - Generate `manifest.json` conforming to `tcv-manifest/v1`
    - Display file count and paths; warn if no matching files
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [x] 13.3 Implement `packages/cli-publisher/src/commands/sign-manifest.ts`
    - Compute SHA-256 of manifest content
    - Produce Ed25519 signature
    - Generate `manifest.sig.json` conforming to `tcv-signature/v1`
    - Display confirmation with key ID
    - _Requirements: 12.1, 12.2, 12.3, 12.4_

  - [x] 13.4 Implement `packages/cli-publisher/src/commands/verify.ts`
    - Perform full verification flow on a package directory
    - Report per-file status; display failing file path, expected hash, computed hash on failure
    - _Requirements: 19.1, 19.2, 19.3, 19.4_

  - [x] 13.5 Implement `packages/cli-publisher/src/commands/key-fingerprint.ts`
    - Compute and display SHA-256 fingerprint of a public key file in lowercase hex
    - _Requirements: 20.1, 20.2_

  - [x] 13.6 Wire Publisher CLI entry point (`packages/cli-publisher/src/index.ts`)
    - Set up command routing (e.g., using `commander` or simple arg parsing)
    - _Requirements: 10, 11, 12, 19, 20_

  - [x] 13.7 Write property test: Manifest building includes all protected files
    - **Property 14: Manifest building includes all protected files**
    - Generate a temp directory with files matching protected patterns; assert manifest entries correspond exactly to matching files with correct hashes
    - **Validates: Requirements 11.1, 11.2, 11.3**

  - [x] 13.8 Write unit tests for Publisher CLI commands
    - Test init-key generates valid keypair, build-manifest with known fixture, sign-manifest produces valid signature, verify detects modified files
    - _Requirements: 10.1, 11.1, 12.1, 19.1_

- [x] 14. Implement User CLI
  - [x] 14.1 Implement `packages/cli-user/src/commands/trust-add.ts`
    - Read public key file, compute fingerprint, add to trust store
    - _Requirements: 5.2, 5.4_

  - [x] 14.2 Implement `packages/cli-user/src/commands/trust-remove.ts`
    - Remove publisher entry by key ID from trust store
    - _Requirements: 5.3_

  - [x] 14.3 Implement `packages/cli-user/src/commands/trust-list.ts`
    - Display publisher name, key ID, fingerprint for each trusted entry
    - _Requirements: 5.6_

  - [x] 14.4 Implement `packages/cli-user/src/commands/trust-revoke.ts`
    - Mark key as revoked in trust store
    - _Requirements: 9.1_

  - [x] 14.5 Implement `packages/cli-user/src/commands/verify.ts`
    - Locate manifest.json and manifest.sig.json in file's package directory
    - Invoke Verification Engine for full flow
    - Display success message (file name, publisher, key ID) or failure message (file name, status, reason)
    - Handle missing manifest case
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [x] 14.6 Implement `packages/cli-user/src/commands/cache-refresh.ts`
    - Re-verify all cached manifests, remove entries that fail
    - _Requirements: 15.5_

  - [x] 14.7 Implement `packages/cli-user/src/commands/key-fingerprint.ts`
    - Compute and display fingerprint of a public key file
    - _Requirements: 20.1, 20.2_

  - [x] 14.8 Wire User CLI entry point (`packages/cli-user/src/index.ts`)
    - Set up command routing for trust add/remove/list/revoke, verify, cache refresh, key-fingerprint
    - _Requirements: 5, 9, 14, 15, 20_

  - [x] 14.9 Write property test: CLI verification output completeness
    - **Property 19: CLI verification output completeness**
    - For any VerificationResult, assert CLI output contains file name and either (publisher + key ID) on success or (status + reason) on failure
    - **Validates: Requirements 14.3, 14.4**

  - [x] 14.10 Write unit tests for User CLI commands
    - Test trust add/remove/list/revoke with fixture trust store; test verify output formatting
    - _Requirements: 5.2, 5.3, 5.6, 9.1, 14.3, 14.4_

- [x] 15. Checkpoint — Ensure all CLI tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Implement Tool Adapters
  - [x] 16.1 Implement `packages/core/src/adapter.ts` — ToolAdapter interface
    - Define `ToolAdapter` interface with `onFileLoad(filePath): Promise<PolicyDecision>` and `getVerificationStatus(filePath): Promise<VerificationResult>`
    - _Requirements: 17.1, 17.2, 17.3, 17.4_

  - [x] 16.2 Implement `packages/adapter-claude-code/src/index.ts`
    - Implement `ToolAdapter` for Claude Code
    - Intercept file load events, invoke Verification Engine, enforce policy decision
    - Provide user-facing message on block
    - _Requirements: 17.1, 17.2, 17.3, 17.5, 7.5, 7.6_

  - [x] 16.3 Implement `packages/adapter-openclaw/src/index.ts`
    - Implement `ToolAdapter` for OpenClaw
    - Same adapter contract as Claude Code adapter
    - _Requirements: 17.1, 17.2, 17.3, 17.5, 7.5, 7.6_

  - [x] 16.4 Write unit tests for Tool Adapters
    - Test onFileLoad returns correct PolicyDecision for trusted/modified/untrusted files; test block message generation
    - _Requirements: 17.1, 17.2, 17.3, 17.5_

- [x] 17. Integration tests — End-to-end verification flows
  - [x] 17.1 Create test fixtures in `tests/fixtures/`
    - Generate sample Ed25519 keypair, sample package with SKILL.md and RULES.md, signed manifest, signature file, sample trust store
    - _Requirements: Design testing strategy_

  - [x] 17.2 Write integration test: Full publisher flow
    - init-key → build-manifest → sign-manifest → verify (all pass)
    - _Requirements: 10, 11, 12, 19_

  - [x] 17.3 Write integration test: Full user verification flow
    - Trust a publisher → verify a trusted file (success) → modify file → verify again (modified) → verify unknown signer (untrusted)
    - _Requirements: 4, 5, 14_

  - [x] 17.4 Write integration test: Cache and offline verification
    - Verify file (caches manifest) → remove original manifest → verify again using cache (succeeds if policy allows offline)
    - _Requirements: 15.1, 15.3_

  - [x] 17.5 Write integration test: Revocation and expiry
    - Revoke a key → verify file signed by revoked key (returns revoked) → test expired manifest with both policy settings
    - _Requirements: 8, 9_

- [x] 18. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (19 properties total)
- Unit tests validate specific examples and edge cases
- Integration tests validate end-to-end flows with real Ed25519 keys (no mocks)
- All 19 correctness properties are covered: Properties 1–19 mapped across tasks 2, 3, 5, 6, 7, 9, 10, 13, 14
