# Trusted Content Verification Plugin

> **Superseded (2026-07-14):** this v1 spec is retained for history. The current
> specification is [`SPEC.md`](./SPEC.md) (ContextLock Specification v2), which
> revises the crypto format (exact-byte hashing, DSSE envelope, anti-rollback),
> adds the Local Seal (TOFU) mode as the MVP, grounds enforcement in Claude
> Code's real hook surface, and adds prior-art positioning and a naming-risk
> assessment.

## Project Goal

Build a plugin, or parallel plugins, for Claude Code, OpenClaw, or both, that verify the authenticity and integrity of trusted text-based project artifacts before they are loaded, interpreted, or acted on.

The system is designed for ecosystems where publishers opt in to a shared verification standard. A publisher who adopts the standard can distribute files such as `SKILL.md`, `CLAUDE.md`, `RULES.md`, prompt packs, policy files, instructions, agent configs, or other text artifacts together with signed metadata. Once the plugin is installed, compatible files can be verified after download and before use.

The main objective is not privacy or encryption. The objective is:

- verify where a file came from
- verify that it has not been modified since publication
- let the user define which publishers are trusted
- reduce the risk of prompt or instruction injection through tampered local files

---

## Problem Statement

Modern AI coding tools and agent systems often consume local markdown and text files as instructions, policy, context, or behavioral control. These files are easy to edit, easy to replace, and often trusted implicitly.

This creates several risks:

- malicious modification of downloaded instruction files
- accidental corruption or partial overwrites
- spoofed files that imitate well-known packages or repositories
- supply chain risk when instruction packs are shared informally
- loss of provenance once a file leaves its original repository

Traditional integrity checks such as CRC are useful for corruption detection but are not suitable against intentional tampering. This project therefore uses cryptographic hashes and digital signatures.

---

## Core Concept

Each protected file is verified against a signed manifest published by a trusted source.

The trust model works like this:

1. A publisher creates one or more protected files.
2. The publisher computes a strong cryptographic hash for each protected file.
3. The publisher places those hashes into a JSON manifest.
4. The publisher signs the manifest with a private key.
5. The user or organization configures the plugin to trust the publisher's public key.
6. When a compatible file is loaded, the plugin verifies:
   - the manifest signature
   - the file hash against the manifest
   - optional metadata such as package name, origin, version, and policy

If verification fails, the plugin can block, warn, quarantine, or load the file as untrusted.

---

## Desired User Experience

### For publishers

A publisher should be able to:

- generate a keypair
- sign a manifest for one package or release
- publish files and manifest in a repo, package archive, or website
- optionally rotate keys later

### For users

A user should be able to:

- install the plugin
- trust one or more publishers
- download compatible instruction files from approved sources
- see whether files are verified, unverified, stale, revoked, or modified
- enforce policy such as "block all unverified instruction files"

### For teams

A team should be able to:

- maintain an allowlist of trusted publishers
- pin required keys or fingerprints
- cache manifests locally
- audit verification failures
- apply different rules to different file classes

---

## Scope

### In scope

- markdown and plain text file verification
- signed manifest format
- public key trust store
- plugin hook integration for pre-load or pre-interpret checks
- publisher tooling for signing packages
- CLI tool for verification and debugging
- local policy configuration
- failure handling modes
- key rotation and revocation support

### Out of scope for v1

- encrypting file contents
- remote execution sandboxing
- runtime network prompt filtering
- semantic safety analysis of signed content
- protection against a malicious but already trusted publisher
- full package manager replacement

---

## Threat Model

### Defended against

- local tampering after download
- malicious mirror serving altered files
- repository compromise that does not include signing key compromise
- accidental file corruption
- renamed or relocated files that try to impersonate trusted artifacts without matching manifest data

### Not fully defended against

- compromised publisher private key
- malicious content signed by a trusted publisher
- tool bypasses that disable hooks or verification
- attacks that inject content through other channels at runtime
- operating system level compromise on the user's machine

---

## High-Level Architecture

```text
Publisher Files -> Hash Generator -> Signed Manifest -> Distribution Channel
                                                   \
                                                    \-> Public Key / Key Fingerprint

User Machine:
AI Tool Hook -> Plugin -> Trust Store -> Manifest Fetch/Cache -> Signature Verification -> File Hash Verification -> Policy Decision
```

### Main components

1. **Verification plugin core**

   - common verification engine
   - reusable across Claude Code and OpenClaw integrations

2. **Tool-specific adapters**

   - Claude Code hook adapter
   - OpenClaw hook adapter

3. **Publisher CLI**

   - create keys
   - hash files
   - build manifest
   - sign manifest
   - verify package before publish

4. **Trust store**

   - approved public keys
   - fingerprints
   - revocation state
   - source policies

5. **Manifest cache**

   - local copy of verified manifests
   - expiry rules
   - offline verification support

6. **Policy engine**

   - allow, warn, block, quarantine
   - per publisher and per file type policies

---

## Recommended Cryptographic Choices

### Hash algorithm

Use **SHA-256** for v1.

Reason:

- mature
- widely available
- easy to implement in many languages
- sufficient for file integrity

Optional future support:

- SHA-512
- BLAKE3 for performance, if needed

### Signature algorithm

Use **Ed25519** for v1.

Reason:

- compact signatures
- strong modern default
- good library support
- simple key handling compared with older formats

### Encoding

- file hashes: lowercase hex for readability, or base64url if space matters
- signatures: base64 or base64url
- key fingerprints: SHA-256 of public key, displayed in hex or base64url

---

## Why Not CRC

CRC is good for accidental corruption detection. It is not suitable for adversarial tampering because it is not collision-resistant and is not tied to publisher identity.

This project should use:

- cryptographic hash for file integrity
- digital signature for authenticity

---

## Two Recommended Design Paths

This project can be positioned with two implementation options.

### Option 1: Easier, faster, lower-assurance approach

Use a content hash directly in the filename.

Example:

```text
SKILL.a3f5c9e8d1f24a6c.md
```

Verification flow:

1. Read the file.
2. Compute the SHA-256 hash of the file contents.
3. Compare the computed hash against the hash embedded in the filename.
4. If they match, treat the file as unchanged since it received that filename.

Benefits:

- very simple to implement
- no signature infrastructure required
- no manifest required
- easy to explain to users
- useful for accidental corruption detection and quick local integrity checks

Limitations:

- does not prove publisher identity
- an attacker can modify the file, recompute the hash, and rename the file
- cannot distinguish original publisher output from repackaged or spoofed content
- not enough on its own for strong supply-chain protection

Best positioning:

- lightweight integrity mode
- starter version or MVP for local change detection
- useful where convenience matters more than trust provenance

### Option 2: Better, stronger, more complete approach

Use a signed manifest containing file hashes, verified against a pinned public key.

Verification flow:

1. Read the file.
2. Locate the package manifest.
3. Verify the manifest signature using a trusted public key.
4. Compute the SHA-256 hash of the file contents.
5. Compare the computed hash against the expected hash in the signed manifest.
6. Only trust the file if both the signature and hash checks succeed.

Benefits:

- proves both integrity and authenticity
- protects against attackers who can re-hash and rename files
- supports multi-file packages cleanly
- supports trusted publishers, revocation, key rotation, and policy enforcement
- aligns with modern software supply-chain security practices

Limitations:

- more moving parts
- requires manifest generation and signing workflow
- requires trust store and key management
- slightly harder for publishers to adopt at first

Best positioning:

- trusted publisher mode
- enterprise or open standard mode
- recommended long-term architecture

### Recommended strategy

Treat Option 1 as the easy on-ramp and Option 2 as the full trust model.

In other words:

- Option 1 is easier to do
- Option 2 is better, just more complicated

The plugin could even support both:

- filename-hash verification for basic integrity mode
- signed-manifest verification for trusted mode

This would let early adopters start simple while allowing serious publishers to opt into stronger authenticity guarantees.

---

## Protected File Format

A protected file remains a normal text file. It does not need to be encrypted.

It may include an optional header block at the top for discovery and lookup.

### Example header for markdown

```md
<!-- tcv:package=acme-secure-skills -->
<!-- tcv:file=SKILL.md -->
<!-- tcv:version=1.2.0 -->
<!-- tcv:manifest=https://example.org/tcv/acme-secure-skills/1.2.0/manifest.json -->
<!-- tcv:keyid=acme-main-2026 -->
```

Notes:

- `tcv` stands for Trusted Content Verification
- the header is metadata only
- the file hash should be computed over the canonical file content rules defined below

### Canonicalization rules

To avoid false mismatches, define exact hash rules:

- hash file bytes as stored on disk in UTF-8
- normalize line endings to LF before hashing, or require exact byte hashing and document that policy
- exclude nothing unless explicitly standardized
- if header is part of the file, it is part of the hash

Recommended v1 rule:

- hash normalized UTF-8 content with LF newlines
- require no BOM

This makes cross-platform verification more predictable.

---

## Manifest Format

The manifest is the signed source of truth.

### Example `manifest.json`

```json
{
  "schema": "tcv-manifest/v1",
  "package": "acme-secure-skills",
  "version": "1.2.0",
  "publisher": {
    "name": "Acme Security",
    "key_id": "acme-main-2026",
    "public_key_fingerprint": "c8e4b7d5f9c2..."
  },
  "published_at": "2026-04-02T12:00:00Z",
  "expires_at": "2027-04-02T12:00:00Z",
  "source": {
    "repository": "https://example.org/acme-secure-skills",
    "release": "https://example.org/acme-secure-skills/releases/1.2.0"
  },
  "files": [
    {
      "path": "SKILL.md",
      "sha256": "a3f5c9...",
      "size": 18432,
      "media_type": "text/markdown"
    },
    {
      "path": "RULES.md",
      "sha256": "c18be2...",
      "size": 7221,
      "media_type": "text/markdown"
    }
  ],
  "revocation": {
    "status": "active",
    "url": "https://example.org/tcv/revocations.json"
  }
}
```

### Detached signature example

```json
{
  "schema": "tcv-signature/v1",
  "manifest_sha256": "...",
  "algorithm": "Ed25519",
  "key_id": "acme-main-2026",
  "signature": "base64url-signature-here"
}
```

Alternative:

- use one envelope file that contains both manifest and signature

Recommended v1:

- keep manifest and signature separate for simplicity

Files:

- `manifest.json`
- `manifest.sig.json`

---

## Trust Store Format

The plugin maintains a local trust store.

### Example `truststore.json`

```json
{
  "schema": "tcv-truststore/v1",
  "trusted_publishers": [
    {
      "publisher": "Acme Security",
      "key_id": "acme-main-2026",
      "public_key": "base64-public-key-here",
      "fingerprint": "c8e4b7d5f9c2...",
      "policy": {
        "default_action": "block",
        "allow_expired_manifest": false,
        "allow_offline_cached_manifest": true
      }
    }
  ]
}
```

### Trust store requirements

- trust should be explicit, not automatic
- public keys should be pinned locally
- fingerprints should be visible to the user
- adding a trusted publisher should require a deliberate user action

---

## Verification Flow

### Standard verification path

1. Tool encounters a candidate protected file.
2. Plugin detects TCV header or recognizes file based on configured path patterns.
3. Plugin locates `manifest.json` and `manifest.sig.json`.
4. Plugin fetches them from local package directory, remote origin, or local cache.
5. Plugin verifies the manifest signature using a pinned public key from the trust store.
6. Plugin checks manifest validity:
   - schema valid
   - package matches
   - version matches if required
   - manifest not expired unless policy allows
   - publisher key matches trusted key
7. Plugin computes SHA-256 of the current file.
8. Plugin compares computed hash with manifest entry.
9. Plugin returns a policy result:
   - trusted
   - trusted but stale
   - untrusted
   - modified
   - revoked
   - verification unavailable
10. Tool adapter enforces configured behavior.

### Failure outcomes

- **block**: do not load file
- **warn**: require explicit confirmation
- **quarantine**: copy aside and disable
- **readonly**: open but mark untrusted and prevent automatic use
- **audit-only**: log failure but continue

---

## Supported Source Models

### Model A: Sidecar manifest in package folder

Example layout:

```text
my-package/
  SKILL.md
  RULES.md
  manifest.json
  manifest.sig.json
```

Best for:

- downloaded package archives
- git repositories
- simple offline verification

### Model B: Remote manifest referenced by header

Example:

- file contains manifest URL in header
- plugin fetches the manifest and signature

Best for:

- centrally managed content
- update channels

Risk note:

- remote manifest location alone is not trusted
- only the signature and pinned key establish trust

### Model C: Embedded package metadata plus local cache

Best for:

- environments with limited connectivity
- enterprise-managed deployments

Recommended v1:

- support Model A first
- add Model B second

---

## Filename Hashes

A filename may include a short or full hash for convenience, but filename hashes should not be the root security mechanism.

Example:

```text
SKILL.a3f5c9e8d1f24a6c.md
```

Benefits:

- visible change indicator
- easier cache busting
- quick human inspection

Limitations:

- does not prove publisher identity
- can be renamed by an attacker
- should be treated as advisory only

Recommended policy:

- allow optional filename hash hints
- always require manifest signature verification for trusted mode

---

## Plugin Integration Points

### Claude Code integration

The plugin should intercept the earliest practical point where instruction or policy files are read.

Potential hook points:

- before file load
- before context assembly
- before instruction parsing
- before agent startup if boot files are present

Adapter responsibilities:

- determine which files are protected
- call verification engine
- return structured status to Claude Code
- enforce configured policy

### OpenClaw integration

The same verification engine should be reused.

Adapter responsibilities are similar:

- watch file load hooks
- verify target files
- provide user-facing status
- enforce policy before the file affects agent behavior

### Shared adapter contract

Each adapter should expose something like:

```ts
interface VerificationResult {
  status: "trusted" | "modified" | "untrusted" | "revoked" | "expired" | "error";
  publisher?: string;
  keyId?: string;
  manifestSource?: string;
  fileHash?: string;
  expectedHash?: string;
  reason?: string;
}
```

---

## File Classes to Protect

The system should support configurable classes of files, for example:

- `SKILL.md`
- `CLAUDE.md`
- `SYSTEM.md`
- `RULES.md`
- `.prompt.md`
- `.policy.md`
- `.instructions.md`
- tool-specific text configs
- JSON config files if needed later

### Suggested default matching rules

- exact filename list
- glob patterns
- optional repository subpaths

Example config:

```json
{
  "protected_patterns": [
    "**/SKILL.md",
    "**/CLAUDE.md",
    "**/RULES.md",
    "**/*.prompt.md",
    "**/*.policy.md"
  ]
}
```

---

## Policy Engine

### Example policy levels

#### Strict

- only trusted signed files may load
- expired or unverifiable files are blocked

#### Balanced

- trusted signed files load automatically
- unknown files warn
- modified trusted files are blocked

#### Audit

- everything loads
- verification status is logged and displayed

### Recommended enterprise policy

- strict for system-level instruction files
- balanced for user-added prompt files
- audit for experimental directories

---

## Revocation and Key Rotation

### Key rotation support

A publisher should be able to:

- create a new keypair
- sign a transition statement with old key if possible
- publish new manifests with new key ID

The plugin should support:

- multiple active trusted keys per publisher
- optional trust expiry dates
- visible key fingerprints

### Revocation

If a signing key is compromised:

- publisher posts revocation document
- enterprise admins can revoke locally immediately
- plugin should refuse future signatures from revoked keys

Recommended v1:

- local revocation list support
- optional remote revocation check later

---

## Offline and Caching Behavior

### Goals

- avoid unnecessary network calls
- keep verification working after first trust validation
- prevent stale unsigned data from replacing trusted metadata

### Cache rules

- cache only manifests that have already passed signature verification
- cache by package, version, and key fingerprint
- record fetch time and expiry
- never trust unsigned cache writes

### Offline policy examples

- allow cached verified manifests if not expired
- deny remote-only packages when cache missing

---

## CLI Publisher Tool

A companion CLI makes adoption easier.

### Proposed commands

```bash
# Generate Ed25519 keypair
trusted-content init-key

# Build manifest for a package directory
trusted-content build-manifest ./package

# Sign the manifest
trusted-content sign-manifest ./package/manifest.json

# Verify locally before publishing
trusted-content verify ./package/SKILL.md

# Show fingerprint
trusted-content key-fingerprint ./keys/public.pem
```

### Suggested outputs

- manifest created
- files hashed
- signature created
- key fingerprint displayed
- warnings for untracked files or mismatched line endings

---

## Plugin CLI for Users

### Proposed commands

```bash
# Trust a publisher
trusted-content trust add ./publisher-public-key.pem

# List trusted publishers
trusted-content trust list

# Verify a file manually
trusted-content verify ./downloaded/SKILL.md

# Explain failure
trusted-content explain ./downloaded/SKILL.md

# Rebuild cache
trusted-content cache refresh
```

---

## Suggested Repository Structure

```text
trusted-content-verification/
  docs/
    spec.md
    threat-model.md
    manifest-schema.md
  packages/
    core/
    adapter-claude-code/
    adapter-openclaw/
    cli-publisher/
    cli-user/
  schemas/
    manifest.schema.json
    signature.schema.json
    truststore.schema.json
  examples/
    sample-package/
    sample-truststore/
  tests/
    fixtures/
    integration/
  README.md
```

---

## Suggested Tech Stack

### Language options

#### TypeScript

Best if:

- target plugins are JavaScript or Node-based
- you want one codebase for CLI and adapters

Benefits:

- great ecosystem
- easy JSON and file handling
- good Ed25519 and SHA-256 libraries

#### Rust

Best if:

- you want a fast secure core library and CLI
- you want bindings later

Benefits:

- strong safety model
- good for a long-term security-focused core

### Recommended v1

Use **TypeScript** for fastest iteration.

Possible split:

- core verification engine in TypeScript
- adapters in TypeScript
- optional Rust core later if performance or portability matters

---

## Minimal Viable Product

### MVP goals

- verify local markdown files against sidecar signed manifests
- trust publishers through pinned Ed25519 public keys
- support a manual CLI verify command
- integrate with at least one tool hook
- block modified trusted files before load

### MVP non-goals

- remote manifest discovery
- revocation endpoint polling
- GUI trust manager
- enterprise admin sync

### MVP acceptance criteria

- a signed `SKILL.md` can be verified locally
- a modified `SKILL.md` is detected and blocked
- an unsigned file is marked untrusted
- a manifest signed by an unknown key is rejected
- the same verification engine works through CLI and plugin adapter

---

## Proposed Development Phases

### Phase 1: specification

Deliverables:

- manifest schema
- signature schema
- trust store schema
- canonical hashing rules
- threat model

### Phase 2: core engine

Deliverables:

- file hashing
- manifest verification
- signature verification
- result model
- tests with fixtures

### Phase 3: publisher CLI

Deliverables:

- key generation
- manifest generation
- signing flow
- local verification tools

### Phase 4: first adapter

Deliverables:

- Claude Code or OpenClaw integration
- pre-load verification hook
- user-facing error and status messages

### Phase 5: second adapter

Deliverables:

- shared engine reuse
- integration-specific policy enforcement

### Phase 6: ecosystem adoption

Deliverables:

- example publisher guide
- onboarding docs
- reference implementation package

---

## Example Verification Status Messages

### Success

`Verified: SKILL.md matches signed manifest from Acme Security using key acme-main-2026.`

### Modified

`Blocked: SKILL.md does not match the signed hash in the trusted manifest.`

### Unknown signer

`Untrusted: manifest signature is valid cryptographically, but the signing key is not in your trust store.`

### Expired manifest

`Blocked: manifest was signed correctly, but it is expired under current policy.`

### No manifest

`Warning: file is in a protected class but no compatible TCV manifest was found.`

---

## Example End-to-End Scenario

1. A publisher distributes a package containing `SKILL.md`, `RULES.md`, `manifest.json`, and `manifest.sig.json`.
2. The user installs the verification plugin.
3. The user imports the publisher public key into the trust store.
4. The user downloads the package.
5. Claude Code or OpenClaw attempts to load `SKILL.md`.
6. The adapter calls the core verifier.
7. The core verifier checks the manifest signature.
8. The verifier hashes `SKILL.md` and matches it against the manifest.
9. The file is marked trusted and allowed to load.
10. If someone later edits one sentence in `SKILL.md`, the hash mismatch is detected and the file is blocked.

---

## Important Design Decisions

### Decision 1: Trust should be explicit

Do not auto-trust based on manifest URL, repository, or package name alone. Only pinned public keys establish trust.

### Decision 2: Keep content readable

Files stay as normal markdown or text. No encryption is required.

### Decision 3: Signed manifest is primary, not filename hash

Filename hashes can help, but the signed manifest is the real security layer.

### Decision 4: Verification should happen before interpretation

The plugin must verify before the target file influences model behavior.

### Decision 5: Canonicalization must be precise

A vague hashing rule will create false positives and confusion. This should be finalized early.

---

## Risks and Adoption Challenges

### Adoption friction

Publishers need to:

- generate keys
- maintain signatures
- include manifest files

Mitigation:

- provide a dead simple CLI
- publish templates
- give copy-paste examples

### User confusion about trust

Users may confuse valid signatures with safe content.

Mitigation:

- message clearly: verified means authentic, not necessarily benign

### Plugin bypass

If the host tool allows alternate load paths, some files may avoid checks.

Mitigation:

- document integration boundaries clearly
- cover all load hooks possible

### Private key loss or compromise

Mitigation:

- support key rotation and revocation
- encourage hardware-backed keys for serious publishers later

---

## Future Enhancements

- transparency log for published manifests
- trusted timestamping
- multi-signature support for high assurance packages
- organization-wide trust sync
- GUI trust manager
- support for ZIP or tarball package signatures
- support for signed dependency graphs
- support for semantic diff on verification failure
- support for notarized releases

---

## Open Questions

1. Should hash canonicalization normalize line endings or use exact bytes?
2. Should the plugin support per-file signatures or only package manifest signatures?
3. Should trust be per key, per publisher, or per package namespace?
4. What is the cleanest hook surface in Claude Code?
5. What is the cleanest hook surface in OpenClaw?
6. Should remote manifest fetching be enabled by default?
7. How should revoked-but-cached packages behave offline?
8. Should verified files display a visible badge in the tool UI?

---

## Recommended v1 Positioning

This project should be described as:

**An opt-in authenticity and integrity layer for AI instruction files and prompt packages.**

It is not malware scanning. It is not content moderation. It is not encryption.

It is a supply-chain style verification system for markdown and text artifacts that AI tools rely on.

---

## One-Sentence Summary

Create a shared cryptographic verification standard and plugin ecosystem that lets Claude Code, OpenClaw, and similar tools verify that critical instruction files came from approved publishers and have not been modified since signing.

