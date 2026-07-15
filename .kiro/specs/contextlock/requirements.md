# Requirements Document

## Introduction

ContextLock is a Trusted Content Verification (TCV) plugin system for AI coding tools (Claude Code, OpenClaw). It verifies the authenticity and integrity of trusted text-based project artifacts (SKILL.md, CLAUDE.md, RULES.md, prompt packs, policy files, etc.) before they are loaded, interpreted, or acted on. The system uses SHA-256 cryptographic hashes and Ed25519 digital signatures with signed manifests. Publishers opt in by signing manifests; users pin trusted public keys to establish trust.

## Glossary

- **Verification_Engine**: The core reusable component that performs cryptographic hash computation, manifest parsing, signature verification, and policy evaluation across all tool integrations.
- **Publisher_CLI**: The command-line tool used by content publishers to generate Ed25519 keypairs, build manifests, sign manifests, and verify packages before distribution.
- **User_CLI**: The command-line tool used by end users to manage trusted publishers, manually verify files, inspect verification failures, and manage the manifest cache.
- **Trust_Store**: The local persistent store of pinned public keys, key fingerprints, publisher policies, and revocation state used to determine which publishers are trusted.
- **Manifest**: A JSON document conforming to the `tcv-manifest/v1` schema that contains package metadata, publisher information, and SHA-256 hashes for each protected file in a package.
- **Detached_Signature**: A separate JSON document conforming to the `tcv-signature/v1` schema that contains the Ed25519 signature over the manifest, the signing key ID, and the manifest hash.
- **Manifest_Cache**: A local cache of previously verified manifests, indexed by package, version, and key fingerprint, supporting offline verification.
- **Policy_Engine**: The component that evaluates verification results against configured policy levels (strict, balanced, audit) and returns enforcement decisions (allow, warn, block, quarantine, audit).
- **Tool_Adapter**: A tool-specific integration layer (for Claude Code or OpenClaw) that intercepts file load events, invokes the Verification_Engine, and enforces policy decisions before files influence model behavior.
- **Protected_File**: A text-based project artifact (markdown, prompt, policy, or config file) that matches configured glob patterns and is subject to verification before loading.
- **Canonicalization**: The process of normalizing file content to UTF-8 encoding with LF line endings and no BOM before computing cryptographic hashes.
- **Filename_Hash_Mode**: A lightweight integrity mode where a truncated SHA-256 hash is embedded in the filename for basic change detection without publisher identity verification.
- **Trusted_Publisher_Mode**: The full verification mode using signed manifests and pinned public keys to verify both integrity and authenticity.
- **Verification_Result**: A structured object returned by the Verification_Engine containing the verification status, publisher info, key ID, hashes, and failure reason.
- **Key_Fingerprint**: The SHA-256 hash of a publisher's Ed25519 public key, used for display and identification purposes.

## Requirements

### Requirement 1: File Canonicalization

**User Story:** As a publisher, I want file content to be canonicalized before hashing, so that cross-platform differences in line endings or encoding do not cause false verification failures.

#### Acceptance Criteria

1. WHEN computing a hash for a Protected_File, THE Verification_Engine SHALL normalize the file content to UTF-8 encoding with LF line endings and no byte order mark before hashing.
2. WHEN a Protected_File contains CRLF or CR line endings, THE Verification_Engine SHALL convert all line endings to LF before computing the SHA-256 hash.
3. WHEN a Protected_File contains a UTF-8 BOM, THE Verification_Engine SHALL strip the BOM before computing the SHA-256 hash.
4. THE Verification_Engine SHALL compute SHA-256 hashes over the canonicalized byte content of the file.

### Requirement 2: Manifest Parsing and Validation

**User Story:** As a developer, I want the system to parse and validate manifest files against a defined schema, so that only well-formed manifests are processed.

#### Acceptance Criteria

1. WHEN a `manifest.json` file is loaded, THE Verification_Engine SHALL parse the JSON content and validate it against the `tcv-manifest/v1` schema.
2. IF a Manifest does not conform to the `tcv-manifest/v1` schema, THEN THE Verification_Engine SHALL return a Verification_Result with status `error` and a descriptive reason identifying the schema violation.
3. THE Verification_Engine SHALL validate that each file entry in the Manifest contains a `path`, `sha256`, and `size` field.
4. IF a Manifest contains duplicate file paths, THEN THE Verification_Engine SHALL return a Verification_Result with status `error` indicating the duplicate entry.
5. FOR ALL valid Manifest objects, parsing then serializing then parsing SHALL produce an equivalent object (round-trip property).

### Requirement 3: Detached Signature Verification

**User Story:** As a user, I want manifest signatures to be verified against pinned public keys, so that I can confirm the manifest was signed by a trusted publisher.

#### Acceptance Criteria

1. WHEN a `manifest.sig.json` file is loaded, THE Verification_Engine SHALL parse the JSON content and validate it against the `tcv-signature/v1` schema.
2. WHEN verifying a Detached_Signature, THE Verification_Engine SHALL compute the SHA-256 hash of the Manifest content and compare it to the `manifest_sha256` field in the Detached_Signature.
3. IF the computed manifest hash does not match the `manifest_sha256` field in the Detached_Signature, THEN THE Verification_Engine SHALL return a Verification_Result with status `error` and reason indicating manifest hash mismatch.
4. WHEN the manifest hash matches, THE Verification_Engine SHALL verify the Ed25519 signature in the Detached_Signature using the public key associated with the `key_id` from the Trust_Store.
5. IF the Ed25519 signature verification fails, THEN THE Verification_Engine SHALL return a Verification_Result with status `untrusted` and reason indicating signature verification failure.
6. IF the `key_id` in the Detached_Signature does not match any key in the Trust_Store, THEN THE Verification_Engine SHALL return a Verification_Result with status `untrusted` and reason indicating unknown signing key.

### Requirement 4: File Hash Verification

**User Story:** As a user, I want each protected file's content to be verified against the signed manifest, so that I can detect any modifications since publication.

#### Acceptance Criteria

1. WHEN verifying a Protected_File, THE Verification_Engine SHALL compute the SHA-256 hash of the canonicalized file content and compare it to the corresponding `sha256` entry in the verified Manifest.
2. IF the computed hash matches the Manifest entry, THEN THE Verification_Engine SHALL return a Verification_Result with status `trusted`.
3. IF the computed hash does not match the Manifest entry, THEN THE Verification_Engine SHALL return a Verification_Result with status `modified` including both the computed hash and the expected hash.
4. IF the Protected_File path does not appear in the verified Manifest, THEN THE Verification_Engine SHALL return a Verification_Result with status `untrusted` and reason indicating the file is not listed in the manifest.

### Requirement 5: Trust Store Management

**User Story:** As a user, I want to explicitly manage which publishers I trust by pinning their public keys, so that only files from approved publishers are treated as trusted.

#### Acceptance Criteria

1. THE Trust_Store SHALL store trusted publisher entries containing the publisher name, key ID, Ed25519 public key, Key_Fingerprint, and per-publisher policy configuration.
2. WHEN a user adds a trusted publisher via the User_CLI, THE Trust_Store SHALL persist the publisher's public key and compute and store the Key_Fingerprint as the SHA-256 hash of the public key.
3. WHEN a user removes a trusted publisher via the User_CLI, THE Trust_Store SHALL delete the publisher entry and all associated keys from the Trust_Store.
4. THE Trust_Store SHALL require an explicit user action to add a trusted publisher and SHALL NOT auto-trust publishers based on manifest URL, repository, or package name.
5. THE Trust_Store SHALL support multiple active trusted keys per publisher to enable key rotation.
6. WHEN listing trusted publishers, THE User_CLI SHALL display the publisher name, key ID, and Key_Fingerprint for each entry.

### Requirement 6: Protected File Detection

**User Story:** As a user, I want the system to automatically detect which files require verification based on configurable patterns, so that all relevant instruction files are checked.

#### Acceptance Criteria

1. THE Verification_Engine SHALL identify Protected_Files by matching file paths against a configurable list of glob patterns.
2. THE Verification_Engine SHALL support a default set of protected patterns including `**/SKILL.md`, `**/CLAUDE.md`, `**/RULES.md`, `**/*.prompt.md`, and `**/*.policy.md`.
3. WHEN a user configures custom protected patterns, THE Verification_Engine SHALL use the custom patterns in addition to or instead of the defaults as specified by the user configuration.
4. WHEN a file matches a protected pattern but no Manifest is found in the file's package directory, THE Verification_Engine SHALL return a Verification_Result with status `untrusted` and reason indicating no manifest found.

### Requirement 7: Policy Engine

**User Story:** As a user or team lead, I want to configure how the system responds to different verification outcomes, so that I can enforce appropriate security levels for different contexts.

#### Acceptance Criteria

1. THE Policy_Engine SHALL support three policy levels: `strict`, `balanced`, and `audit`.
2. WHILE the policy level is `strict`, THE Policy_Engine SHALL block loading of any Protected_File that does not have a `trusted` verification status.
3. WHILE the policy level is `balanced`, THE Policy_Engine SHALL allow `trusted` files to load automatically, warn on `untrusted` files, and block `modified` files.
4. WHILE the policy level is `audit`, THE Policy_Engine SHALL allow all files to load and log the verification status for each Protected_File.
5. WHEN a Protected_File is blocked by the Policy_Engine, THE Tool_Adapter SHALL prevent the file from being loaded or interpreted by the AI tool.
6. WHEN a Protected_File triggers a warning, THE Tool_Adapter SHALL display the verification status and require explicit user confirmation before loading.
7. THE Policy_Engine SHALL support per-publisher policy overrides stored in the Trust_Store.

### Requirement 8: Manifest Expiry Handling

**User Story:** As a user, I want the system to check manifest expiry dates, so that stale manifests do not silently remain trusted indefinitely.

#### Acceptance Criteria

1. WHEN a Manifest contains an `expires_at` field, THE Verification_Engine SHALL compare the expiry timestamp against the current system time.
2. IF a Manifest has expired and the publisher's policy sets `allow_expired_manifest` to false, THEN THE Verification_Engine SHALL return a Verification_Result with status `expired`.
3. IF a Manifest has expired and the publisher's policy sets `allow_expired_manifest` to true, THEN THE Verification_Engine SHALL return a Verification_Result with status `trusted` and include a warning indicating the manifest is expired.

### Requirement 9: Key Revocation

**User Story:** As a user, I want to revoke trust in a compromised publisher key, so that files signed with that key are no longer treated as trusted.

#### Acceptance Criteria

1. WHEN a user revokes a key via the User_CLI, THE Trust_Store SHALL mark the key as revoked and persist the revocation state.
2. WHEN verifying a Detached_Signature, THE Verification_Engine SHALL check the signing key's revocation status in the Trust_Store before accepting the signature.
3. IF the signing key is marked as revoked in the Trust_Store, THEN THE Verification_Engine SHALL return a Verification_Result with status `revoked` regardless of signature validity.
4. WHEN a Manifest contains a `revocation.status` field set to a value other than `active`, THE Verification_Engine SHALL return a Verification_Result with status `revoked`.

### Requirement 10: Publisher Key Generation

**User Story:** As a publisher, I want to generate an Ed25519 keypair, so that I can sign manifests for my packages.

#### Acceptance Criteria

1. WHEN a publisher runs the `init-key` command, THE Publisher_CLI SHALL generate a new Ed25519 keypair.
2. THE Publisher_CLI SHALL save the private key and public key to separate files in the specified output directory.
3. WHEN the keypair is generated, THE Publisher_CLI SHALL display the Key_Fingerprint of the generated public key.
4. THE Publisher_CLI SHALL generate cryptographically secure random keys using the platform's secure random number generator.

### Requirement 11: Manifest Building

**User Story:** As a publisher, I want to build a manifest for my package directory, so that users can verify the integrity of my files.

#### Acceptance Criteria

1. WHEN a publisher runs the `build-manifest` command with a package directory path, THE Publisher_CLI SHALL scan the directory for files matching protected patterns.
2. THE Publisher_CLI SHALL compute the SHA-256 hash of each discovered file using the Canonicalization rules (UTF-8, LF newlines, no BOM).
3. THE Publisher_CLI SHALL generate a `manifest.json` file conforming to the `tcv-manifest/v1` schema containing entries for each discovered file with path, sha256, size, and media_type fields.
4. WHEN the manifest is built, THE Publisher_CLI SHALL display the number of files included and their paths.
5. IF the package directory contains no files matching protected patterns, THEN THE Publisher_CLI SHALL display a warning and produce no manifest.

### Requirement 12: Manifest Signing

**User Story:** As a publisher, I want to sign my manifest with my private key, so that users can verify the manifest came from me.

#### Acceptance Criteria

1. WHEN a publisher runs the `sign-manifest` command with a manifest file path and private key, THE Publisher_CLI SHALL compute the SHA-256 hash of the manifest file content.
2. THE Publisher_CLI SHALL produce an Ed25519 signature over the manifest hash using the provided private key.
3. THE Publisher_CLI SHALL generate a `manifest.sig.json` file conforming to the `tcv-signature/v1` schema containing the manifest hash, signature, key ID, and algorithm field set to `Ed25519`.
4. WHEN the signature is created, THE Publisher_CLI SHALL display a confirmation message including the key ID used for signing.

### Requirement 13: Manifest Pretty Printing

**User Story:** As a publisher, I want to serialize Manifest objects back into valid JSON files, so that manifests can be round-tripped through the system without data loss.

#### Acceptance Criteria

1. THE Publisher_CLI SHALL format Manifest objects into valid JSON conforming to the `tcv-manifest/v1` schema.
2. THE Publisher_CLI SHALL format Detached_Signature objects into valid JSON conforming to the `tcv-signature/v1` schema.
3. FOR ALL valid Manifest objects, parsing then pretty-printing then parsing SHALL produce an equivalent Manifest object (round-trip property).
4. FOR ALL valid Detached_Signature objects, parsing then pretty-printing then parsing SHALL produce an equivalent Detached_Signature object (round-trip property).

### Requirement 14: End-to-End Verification Flow

**User Story:** As a user, I want to verify a protected file through a single command, so that I can quickly check whether a file is trusted.

#### Acceptance Criteria

1. WHEN a user runs the `verify` command with a file path, THE User_CLI SHALL locate the `manifest.json` and `manifest.sig.json` in the file's package directory.
2. THE User_CLI SHALL invoke the Verification_Engine to perform the full verification flow: signature verification, manifest validation, file hash comparison.
3. WHEN verification succeeds, THE User_CLI SHALL display a message including the file name, publisher name, and key ID.
4. WHEN verification fails, THE User_CLI SHALL display a message including the file name, failure status, and descriptive reason.
5. IF no manifest files are found in the file's package directory, THEN THE User_CLI SHALL display a message indicating no TCV manifest was found for the file.

### Requirement 15: Manifest Cache

**User Story:** As a user, I want verified manifests to be cached locally, so that verification works offline after the first successful check.

#### Acceptance Criteria

1. WHEN a Manifest passes signature verification, THE Manifest_Cache SHALL store the verified Manifest indexed by package name, version, and Key_Fingerprint.
2. THE Manifest_Cache SHALL record the fetch timestamp and the manifest's `expires_at` value for each cached entry.
3. WHEN verifying a file offline, THE Verification_Engine SHALL use a cached Manifest if one exists and the publisher's policy sets `allow_offline_cached_manifest` to true.
4. THE Manifest_Cache SHALL reject writes of unsigned or unverified manifests.
5. WHEN a user runs the `cache refresh` command, THE User_CLI SHALL re-verify all cached manifests and remove entries that fail verification.

### Requirement 16: Filename Hash Mode

**User Story:** As a publisher, I want to optionally embed a content hash in the filename, so that users can perform quick visual integrity checks without full manifest verification.

#### Acceptance Criteria

1. WHEN a file has a filename matching the pattern `<name>.<hex-hash>.<ext>`, THE Verification_Engine SHALL extract the embedded hash from the filename.
2. THE Verification_Engine SHALL compute the SHA-256 hash of the canonicalized file content and compare the first N characters to the embedded filename hash, where N is the length of the embedded hash string.
3. IF the filename hash matches the computed hash prefix, THEN THE Verification_Engine SHALL treat the file as having basic integrity (not authenticity) confirmation.
4. THE Verification_Engine SHALL treat filename hash verification as advisory only and SHALL require signed manifest verification for `trusted` status.

### Requirement 17: Tool Adapter Integration

**User Story:** As a user, I want the verification plugin to integrate with AI coding tools, so that protected files are verified before they influence model behavior.

#### Acceptance Criteria

1. THE Tool_Adapter SHALL intercept file load events for Protected_Files before the AI tool interprets or acts on the file content.
2. WHEN a Protected_File load event is intercepted, THE Tool_Adapter SHALL invoke the Verification_Engine and receive a Verification_Result.
3. THE Tool_Adapter SHALL enforce the Policy_Engine decision by blocking, warning, or allowing the file load based on the Verification_Result and configured policy level.
4. THE Tool_Adapter SHALL expose a standard `VerificationResult` interface containing status, publisher, keyId, manifestSource, fileHash, expectedHash, and reason fields.
5. WHEN a file is blocked, THE Tool_Adapter SHALL provide a user-facing message explaining the verification failure and the file's status.

### Requirement 18: Verification Status Reporting

**User Story:** As a user, I want clear status messages for each verification outcome, so that I understand why a file was trusted, blocked, or flagged.

#### Acceptance Criteria

1. WHEN a file is verified as `trusted`, THE Verification_Engine SHALL include the publisher name and key ID in the Verification_Result.
2. WHEN a file is verified as `modified`, THE Verification_Engine SHALL include both the computed hash and the expected hash in the Verification_Result.
3. WHEN a file is verified as `untrusted`, THE Verification_Engine SHALL include the reason (unknown key, no manifest, or file not in manifest) in the Verification_Result.
4. WHEN a file is verified as `revoked`, THE Verification_Engine SHALL include the revoked key ID in the Verification_Result.
5. WHEN a file is verified as `expired`, THE Verification_Engine SHALL include the manifest expiry timestamp in the Verification_Result.
6. WHEN a file verification produces an `error`, THE Verification_Engine SHALL include a descriptive error message in the Verification_Result.

### Requirement 19: Publisher Verification Before Publish

**User Story:** As a publisher, I want to verify my package locally before distributing it, so that I can catch issues before users encounter them.

#### Acceptance Criteria

1. WHEN a publisher runs the `verify` command on a package directory, THE Publisher_CLI SHALL perform the full verification flow against the local manifest and signature files.
2. THE Publisher_CLI SHALL report the verification status for each file listed in the manifest.
3. IF any file fails verification, THEN THE Publisher_CLI SHALL display the failing file path, expected hash, and computed hash.
4. IF the manifest or signature file is missing from the package directory, THEN THE Publisher_CLI SHALL display an error indicating which file is missing.

### Requirement 20: Key Fingerprint Display

**User Story:** As a user or publisher, I want to view the fingerprint of a public key, so that I can verify key identity through an out-of-band channel.

#### Acceptance Criteria

1. WHEN a user or publisher runs the `key-fingerprint` command with a public key file path, THE Publisher_CLI SHALL compute the SHA-256 hash of the public key and display it as the Key_Fingerprint.
2. THE Publisher_CLI SHALL display the Key_Fingerprint in lowercase hexadecimal format.
