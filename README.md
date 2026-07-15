# ContextLock — Trusted Content Verification for AI Coding Tools

> **Direction:** the authoritative design is [`SPEC.md`](./SPEC.md)
> (Specification v2, 2026-07-14). Phase A (Local Seal + Claude Code plugin),
> Phase B (signed manifests v2: DSSE envelope, `contextlock/2` format,
> anti-rollback, root/rotation, content lints, `contextlock install`), and
> Phase C (Sigstore keyless Profile B, reviewer multi-signatures, OpenClaw
> adapter, CI signing recipes) are implemented. Some long-form integration
> walkthroughs below predate v2; where they disagree with SPEC.md, SPEC.md
> wins.

ContextLock is a cryptographic verification system that protects AI coding tools from tampered instruction files. It verifies the authenticity and integrity of markdown artifacts — SKILL.md, CLAUDE.md, RULES.md, prompt packs, policy files — before they influence model behavior.

Publishers sign manifests with Ed25519 keys. Users pin trusted public keys (or a rotatable publisher root). When an AI tool loads a protected file, ContextLock checks the signature chain, anti-rollback state, and file hash, then allows, warns, or blocks based on configurable policy. Users can also seal files they reviewed themselves (Mode 0, trust-on-first-use) with zero publisher involvement.

## How It Works

```
Publisher: files → normalize (UTF-8/LF) → SHA-256 + length → contextlock/2 manifest
           → DSSE envelope (Ed25519 over PAE) → contextlock.dsse.json
User:      file load → bounded envelope discovery → verify signature (pinned keys/root)
           → anti-rollback check → expiry check → length + hash compare → policy decision
```

The system uses:
- SHA-256 over the **exact bytes on disk** (canonicalization happens at sign time only)
- Ed25519 signatures in a **DSSE v1.0.2 envelope** (`payloadType application/vnd.contextlock.manifest+json`)
- One shipped artifact per package: `contextlock.dsse.json` (envelope containing the manifest)
- A monotonic integer manifest `version` + local highest-seen state (anti-rollback, T7)
- Mandatory `expires_at` (freeze defense, T8) and per-file `length` (enforced before hashing)
- Sign-time content lints (Unicode Tag block, zero-width, bidi controls)
- Explicit trust only — no auto-trust from URLs, repos, or package names

## Repository Structure

```
contextlock/
├── packages/
│   ├── core/                    # Shared verification engine (+ pinned Sigstore trusted root in assets/)
│   ├── cli-publisher/           # Publisher CLI (key gen, manifest, signing, countersign)
│   ├── cli-user/                # User CLI (trust management, verification, install)
│   ├── adapter-claude-code/     # Claude Code integration adapter
│   ├── adapter-openclaw/        # OpenClaw adapter (installPolicy + blocking hooks)
│   └── plugin-claude-code/      # Installable Claude Code plugin (hooks + CLI shim)
├── recipes/
│   └── github-actions/          # CI signing recipes (Profile A key, Profile B keyless)
├── docs/                        # Empirical host-tool surface maps (Claude Code, OpenClaw)
├── tests/
│   ├── integration/             # End-to-end, red-team, and MVP acceptance tests
│   └── fixtures/sigstore/       # Real + synthetic Sigstore bundles and trusted roots
├── vitest.config.ts
├── tsconfig.json
└── package.json
```

---

## Implementation Setup

### Prerequisites

- Node.js 18+ (LTS recommended)
- npm 9+ (ships with Node.js)

### 1. Clone and Install

```bash
git clone <repository-url>
cd contextlock
npm install
```

npm installs all workspace dependencies including:
- `@noble/ed25519` and `@noble/hashes` for cryptography
- `minimatch` for glob pattern matching
- `vitest` and `fast-check` for testing

### 2. Build

```bash
npm run build
```

This runs `tsc --build` across all packages. Each package compiles from `src/` to `dist/`.

### 3. Run Tests

```bash
npm test
```

Runs all 213 tests across 29 test files — unit tests, property-based tests (fast-check, 100+ iterations each), and integration tests. The test suite covers 19 formal correctness properties from the design document.

### 4. Package Overview

| Package | Purpose | Entry Point |
|---------|---------|-------------|
| `@contextlock/core` | Verification engine, trust store, policy, caching | `packages/core/src/index.ts` |
| `@contextlock/cli-publisher` | Publisher key gen, manifest building, signing, filename hashing | `packages/cli-publisher/src/index.ts` |
| `@contextlock/cli-user` | Trust management, file verification, cache ops | `packages/cli-user/src/index.ts` |
| `@contextlock/adapter-claude-code` | Claude Code file-load interception | `packages/adapter-claude-code/src/index.ts` |
| `@contextlock/adapter-openclaw` | OpenClaw file-load interception | `packages/adapter-openclaw/src/index.ts` |

### 5. Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `@noble/ed25519` | ^2.3.0 | Ed25519 key generation, signing, verification |
| `@noble/hashes` | ^1.7.2 | SHA-256 and SHA-512 hashing |
| `minimatch` | ^10.0.1 | Glob pattern matching for protected file detection |
| `vitest` | ^3.2.1 | Test runner |
| `fast-check` | ^4.1.1 | Property-based testing |

---

## Usage

ContextLock supports two publishing modes:

1. **Filename Hash Mode** (lightweight) — Embeds a SHA-256 prefix in the filename for basic integrity checking. No keys, no manifest, no signatures. Detects accidental corruption but does not prove publisher identity.
2. **Signed Manifest Mode** (full trust) — Publisher signs a manifest with Ed25519. Proves both integrity and authenticity. Protects against intentional tampering.

You can use either mode independently, or both together.

---

### Mode 1: Filename Hash Publishing (Lightweight)

This is the quick way. No keys needed. Just embed a content hash in the filename.

```
SKILL.md → SKILL.a3f5c9e8d1f24a6c.md
```

Anyone can verify the file hasn't changed by recomputing the hash and comparing it to the filename. But anyone can also re-hash a tampered file and rename it — so this mode is advisory only and never produces a `trusted` status.

```typescript
import { hashFilename } from "@contextlock/cli-publisher";

// Produce a hash-protected copy of your file
const result = await hashFilename({
  filePath: "./my-package/SKILL.md",
  hashLength: 16,  // embed first 16 hex chars of SHA-256 (default)
});

console.log(result.hashedPath);    // "./my-package/SKILL.a3f5c9e8d1f24a6c.md"
console.log(result.hash);          // full 64-char SHA-256
console.log(result.embeddedHash);  // "a3f5c9e8d1f24a6c"
```

Users verify by checking the embedded hash:

```typescript
import { verifyFilenameHash } from "@contextlock/core";

const check = await verifyFilenameHash("./SKILL.a3f5c9e8d1f24a6c.md");
console.log(check.matches);  // true if content still matches the filename hash
// Note: this is advisory only — it does NOT prove who created the file
```

**When to use this mode:**
- Quick integrity checks during development
- Sharing files informally where full signing is overkill
- As a visible "has this changed?" indicator in filenames
- Cache busting

**Limitations:**
- Does not prove publisher identity
- An attacker can modify the file, recompute the hash, and rename it
- Never produces `trusted` verification status

Or use the unified `protect` command to hash-protect all protected files in a directory at once:

```typescript
import { protect } from "@contextlock/cli-publisher";

const result = await protect({
  directory: "./my-package",
  mode: "hash",
});
// result.filesProtected === 2
// result.hashResults → [{ originalPath, hashedPath, hash, embeddedHash }, ...]
```

---

### Mode 2: Signed Manifest Publishing (Full Trust)

This is the real security layer. Publisher signs a manifest with their Ed25519 private key. Users pin the publisher's public key. Files are verified against both the signature and the hash.

The easiest way is the `protect` command, which handles key generation, manifest building, and signing in one step:

```typescript
import { protect } from "@contextlock/cli-publisher";

const result = await protect({
  directory: "./my-package",
  mode: "sign",
  packageName: "acme-secure-skills",
  version: 1,                       // monotonic integer (anti-rollback counter)
  displayVersion: "1.0.0",          // human-facing, informational
  publisherName: "Acme Security",
  keyId: "cl-acme-2026",            // short key label (DSSE keyid hint)
});

// If no keypair exists, one is generated automatically:
console.log(result.keyGenerated);                    // true
console.log(result.keyResult!.fingerprint);          // "c8e4b7d5..."
console.log(result.signResult!.envelopePath);        // "./my-package/contextlock.dsse.json"
console.log(result.filesProtected);                  // 2
```

Or do each step individually for more control:

#### Publisher Workflow

Publishers create keys, build manifests, sign them into a DSSE envelope, and distribute alongside their files. Building normalizes each covered file to UTF-8/LF/no-BOM on disk, runs the content lints (Unicode Tags, zero-width, bidi controls — a hit blocks signing unless `allowLints` records the exception), and hashes the exact resulting bytes.

```typescript
import { initKey, buildManifest, signManifest, verify } from "@contextlock/cli-publisher";

// 1. Generate Ed25519 keypair (raw 32-byte keys, base64url)
const keys = await initKey({ output: "./keys", keyId: "cl-acme-2026" });
// → keys.privateKeyPath, keys.publicKeyPath, keys.fingerprint, keys.keyId

// 2. Build a contextlock/2 manifest for a package directory
const manifest = await buildManifest({
  directory: "./my-package",
  packageName: "acme-secure-skills",
  version: 1,                        // integer, monotonic
  displayVersion: "1.0.0",
  publisherName: "Acme Security",
  keyId: keys.keyId,
  expiresDays: 365,                  // expires_at is REQUIRED in v2
});
// → contextlock.manifest.json (unsigned intermediate) written to ./my-package

// 3. Sign the manifest into the DSSE envelope
const sig = await signManifest({
  manifestPath: manifest.manifestPath,
  privateKeyPath: keys.privateKeyPath,
});
// → contextlock.dsse.json written alongside (the ONLY artifact you ship)

// 4. Verify before publishing (signature + every file's length, hash, lints)
const result = await verify({ directory: "./my-package" });
// → result.success === true, result.signatureValid === true
```

#### User Workflow

Users manage trusted publishers and verify files before loading.

```typescript
import { trustAdd, trustList, userVerify, trustRevoke, install, inspect } from "@contextlock/cli-user";

// 1. Trust a publisher by their public key
await trustAdd({
  publicKeyPath: "./acme-public.key",
  publisherName: "Acme Security",
  keyId: "cl-acme-2026",            // optional label; defaults to cl-<fp8>
  trustStorePath: "./truststore.json",
});

// 2. List trusted publishers
const { publishers } = await trustList({ trustStorePath: "./truststore.json" });
// → [{ publisher: "Acme Security", key_id: "cl-acme-2026", fingerprint: "c8e4b7..." }]

// 3. Install a downloaded package: verify EVERYTHING, then place files (Layer 1)
const installed = await install({
  source: "./downloads/acme-secure-skills",
  dest: "./.claude/skills/acme-secure-skills",
  trustStorePath: "./truststore.json",
});
// → installed.installed === true, or nothing was written at all

// 4. Verify a file in place
const result = await userVerify({
  filePath: "./my-package/SKILL.md",
  trustStorePath: "./truststore.json",
});
// → result.result.status === "trusted"
// → result.displayMessage === "✓ ./my-package/SKILL.md — trusted (publisher: Acme Security, key: cl-acme-2026)"

// 5. Inspect an envelope payload (pretty-print; does NOT verify)
const inspected = await inspect({ envelopePath: "./my-package/contextlock.dsse.json" });

// 6. Revoke a compromised key (by label or fingerprint)
await trustRevoke({
  keyId: "cl-acme-2026",
  trustStorePath: "./truststore.json",
});
```

Root-of-trust management for publishers who rotate keys (SPEC v2 6.5):

```bash
contextlock trust root add "Acme Security" ./contextlock.root.dsse.json     # pin initial root (TOFU)
contextlock trust root update "Acme Security" ./root-v2.dsse.json          # verified rotation (N+1, old+new thresholds)
contextlock trust reset "Acme Security"                                     # fast-forward recovery (clears rollback baselines)
```

**Profile B — Sigstore keyless (SPEC v2 5, Phase C).** Packages signed in CI
carry `contextlock.sigstore.json` (a Sigstore bundle whose DSSE payload is the
contextlock/2 manifest). No publisher key exists; users pin the CI workflow's
OIDC identity, exactly like npm provenance, and verification is fully offline
against the pinned Sigstore trusted root shipped with ContextLock:

```bash
contextlock trust identity add "Acme Security" \
  --identity "https://github.com/acme/skills/.github/workflows/sign.yml@refs/heads/main" \
  --issuer   "https://token.actions.githubusercontent.com"
# identity accepts globs: * does not cross /, ** does
contextlock verify ./downloads/acme-skills/SKILL.md   # engine auto-detects the bundle
```

Signing recipes for both profiles live in [`recipes/github-actions/`](./recipes/).

**Reviewer multi-signatures (SPEC v2 6.2).** The DSSE envelope carries
multiple signatures natively; a reviewer countersigns the exact payload bytes
and verifiers can demand a threshold of distinct trusted keys:

```bash
contextlock-publisher countersign ./pkg/contextlock.dsse.json --key reviewer-private.key --key-id cl-reviewer
contextlock verify ./pkg/SKILL.md --min-signers 2
```

### Policy Levels

The policy engine evaluates verification results against three levels:

| Status | strict | balanced | audit |
|--------|--------|----------|-------|
| trusted / sealed / sealed+trusted | allow | allow | allow |
| modified | block | block | audit |
| untrusted | block | warn | audit |
| revoked | block | block | audit |
| expired | block | warn | audit |
| rollback | block | block | audit |
| error / seal-store-unavailable | block | block | audit |

Per-publisher policy overrides can be set in the trust store to customize behavior for specific publishers. `rollback` (an older signed manifest replayed after a newer one was seen) blocks under both strict and balanced — it is an active attack signal, like `revoked`.

---

## User Stories with Demo Walkthroughs

### User Story 1: Publisher Signs and Distributes a Skill Pack

**Scenario:** You maintain a popular AI skill pack with SKILL.md and RULES.md. You want users to verify your files haven't been tampered with after download.

**Quick option — filename hash (no keys needed):**

```typescript
import { hashFilename } from "@contextlock/cli-publisher";

// Just hash-protect each file — done in seconds
const skill = await hashFilename({ filePath: "./my-package/SKILL.md" });
const rules = await hashFilename({ filePath: "./my-package/RULES.md" });

console.log(skill.hashedPath);  // ./my-package/SKILL.a3f5c9e8d1f24a6c.md
console.log(rules.hashedPath);  // ./my-package/RULES.7b2e1df4c8a93b50.md

// Distribute these files. Users can verify integrity by checking the hash in the name.
// But this does NOT prove you are the publisher.
```

**Full option — signed manifest (proves identity):**

```typescript
import { protect, verify } from "@contextlock/cli-publisher";
import { writeFile, mkdir } from "node:fs/promises";

// Setup: create a sample package
await mkdir("./demo-package", { recursive: true });
await writeFile("./demo-package/SKILL.md", `# Code Review Skill
You are an expert code reviewer. Focus on security, performance, and readability.
Always explain your reasoning.`, "utf-8");

await writeFile("./demo-package/RULES.md", `# Rules
1. Never approve code with known vulnerabilities.
2. Flag any hardcoded credentials.
3. Suggest tests for untested code paths.`, "utf-8");

// One command does it all: generates keys, builds the manifest, signs the envelope
const result = await protect({
  directory: "./demo-package",
  mode: "sign",
  packageName: "code-review-skills",
  version: 1,
  displayVersion: "1.0.0",
  publisherName: "YourName",
});

console.log(`Protected ${result.filesProtected} files`);
if (result.keyGenerated) {
  console.log(`Generated keypair — fingerprint: ${result.keyResult!.fingerprint}`);
  console.log(`Share your public key: ${result.keyResult!.publicKeyPath}`);
}
console.log(`Envelope: ${result.signResult!.envelopePath}`);

// Verify everything is correct before distributing
const check = await verify({ directory: "./demo-package" });
console.log(`Pre-publish check: ${check.success ? "PASS" : "FAIL"}`);
for (const f of check.fileResults) {
  console.log(`  ${f.status === "ok" ? "✓" : "✗"} ${f.path}`);
}

// Distribute: ./demo-package/ now contains:
//   SKILL.md, RULES.md, contextlock.dsse.json
//   Share contextlock-public.key separately (website, README, key server)
```

**What to distribute:**
- The package directory (SKILL.md, RULES.md, contextlock.dsse.json)
- Your public key file (contextlock-public.key) through a separate trusted channel

---

### User Story 2: User Verifies Downloaded Files Before Use

**Scenario:** You downloaded a skill pack from a publisher. Before letting your AI tool use it, you want to verify the files are authentic and unmodified.

**Step-by-step demo:**

```typescript
import { trustAdd, userVerify, trustList } from "@contextlock/cli-user";

// Step 1: Add the publisher's public key to your trust store
// (You got the public key file from the publisher's website or docs)
const addResult = await trustAdd({
  publicKeyPath: "./downloaded/contextlock-public.key",
  publisherName: "Acme Security",
  trustStorePath: "./my-truststore.json",
});
console.log(`Trusted: ${addResult.publisherName} (${addResult.fingerprint})`);

// Step 2: Confirm your trust store
const { publishers } = await trustList({ trustStorePath: "./my-truststore.json" });
for (const p of publishers) {
  console.log(`  ${p.publisher} — ${p.fingerprint}`);
}

// Step 3: Verify a file from the downloaded package
const result = await userVerify({
  filePath: "./downloaded/acme-skills/SKILL.md",
  trustStorePath: "./my-truststore.json",
});
console.log(result.displayMessage);
// ✓ ./downloaded/acme-skills/SKILL.md — trusted (publisher: Acme Security, key: c8e4b7...)

// Step 4: What happens if someone tampered with the file?
// (Simulate: edit SKILL.md, then verify again)
const tampered = await userVerify({
  filePath: "./downloaded/acme-skills/SKILL.md",
  trustStorePath: "./my-truststore.json",
});
console.log(tampered.displayMessage);
// ✗ ./downloaded/acme-skills/SKILL.md — modified (expected: a3f5c9..., computed: 7b2e1d...)
```

---

### User Story 3: Team Enforces Verification Policy Across Projects

**Scenario:** Your team uses multiple AI skill packs. You want to enforce that only verified files from approved publishers can influence AI behavior, with different strictness levels.

**Step-by-step demo:**

```typescript
import { ClaudeCodeAdapter, formatBlockMessage } from "@contextlock/adapter-claude-code";
import { trustAdd } from "@contextlock/cli-user";
import type { VerificationResult } from "@contextlock/core";

// Step 1: Set up trust store with approved publishers
await trustAdd({
  publicKeyPath: "./keys/acme-public.key",
  publisherName: "Acme Security",
  trustStorePath: "./team-truststore.json",
  policy: {
    default_action: "block",           // strict for this publisher
    allow_expired_manifest: false,
    allow_offline_cached_manifest: true,
  },
});

await trustAdd({
  publicKeyPath: "./keys/internal-public.key",
  publisherName: "Internal Team",
  trustStorePath: "./team-truststore.json",
  policy: {
    default_action: "warn",            // more lenient for internal
    allow_expired_manifest: true,
    allow_offline_cached_manifest: true,
  },
});

// Step 2: Create adapter with team policy
const adapter = new ClaudeCodeAdapter({
  trustStorePath: "./team-truststore.json",
  cachePath: "./tcv-cache.json",
  policyLevel: "balanced",  // team default: balanced
});

// Step 3: Intercept file loads (this is what the adapter does automatically)
async function onFileLoad(filePath: string) {
  const decision = await adapter.onFileLoad(filePath);

  switch (decision) {
    case "allow":
      console.log(`✓ Loading ${filePath}`);
      break;
    case "warn":
      console.log(`⚠ ${filePath} is unverified — proceed with caution`);
      break;
    case "block": {
      const status = await adapter.getVerificationStatus(filePath);
      console.log(formatBlockMessage(filePath, status));
      break;
    }
  }

  return decision;
}

// Demo: simulate file load events
await onFileLoad("./project/SKILL.md");      // ✓ trusted → allow
await onFileLoad("./project/RULES.md");      // ✗ modified → block
await onFileLoad("./project/README.md");     // not protected → allow
await onFileLoad("./unknown/SKILL.md");      // unknown signer → warn
```

---

## Integration Guide: Claude Code

Claude Code loads instruction files (SKILL.md, CLAUDE.md, RULES.md) that control agent behavior. ContextLock intercepts these loads to verify authenticity before the content reaches the model.

### Setup

```typescript
import { ClaudeCodeAdapter, formatBlockMessage } from "@contextlock/adapter-claude-code";

const adapter = new ClaudeCodeAdapter({
  trustStorePath: "/path/to/tcv-truststore.json",
  cachePath: "/path/to/tcv-cache.json",
  policyLevel: "balanced",  // "strict" | "balanced" | "audit"
});
```

### Hook into Claude Code's File Loading

The adapter exposes two methods that map to Claude Code's file lifecycle:

```typescript
// Before loading any protected file, check the policy decision
async function beforeFileLoad(filePath: string): Promise<boolean> {
  const decision = await adapter.onFileLoad(filePath);

  if (decision === "block") {
    const result = await adapter.getVerificationStatus(filePath);
    const message = formatBlockMessage(filePath, result);
    // Display message to user, prevent file from being loaded
    console.error(message);
    return false;
  }

  if (decision === "warn") {
    const result = await adapter.getVerificationStatus(filePath);
    // Show warning, let user decide
    console.warn(`⚠ Unverified: ${filePath} — ${result.reason}`);
    // Return true to allow with warning, or false to block
    return true;
  }

  // "allow" or "audit" — proceed
  return true;
}
```

### Integration Points in Claude Code

Hook the adapter at these points in Claude Code's execution:

1. **Before context assembly** — When Claude Code collects SKILL.md, CLAUDE.md, and RULES.md files to build the system prompt, call `adapter.onFileLoad()` for each file.

2. **Before instruction parsing** — When Claude Code reads .prompt.md or .policy.md files for agent instructions, verify before parsing.

3. **On agent startup** — If boot files are present, verify all protected files in the project before the agent begins work.

### Example: Claude Code Project Hook

```typescript
// claude-code-plugin.ts
import { ClaudeCodeAdapter, formatBlockMessage } from "@contextlock/adapter-claude-code";

const adapter = new ClaudeCodeAdapter({
  trustStorePath: `${process.env.HOME}/.contextlock/truststore.json`,
  cachePath: `${process.env.HOME}/.contextlock/cache.json`,
  policyLevel: "balanced",
});

/**
 * Called by Claude Code before loading any instruction file.
 * Returns the file content if allowed, or null if blocked.
 */
export async function verifyAndLoad(filePath: string): Promise<string | null> {
  const decision = await adapter.onFileLoad(filePath);

  if (decision === "block") {
    const status = await adapter.getVerificationStatus(filePath);
    console.error(formatBlockMessage(filePath, status));
    return null;
  }

  if (decision === "warn") {
    const status = await adapter.getVerificationStatus(filePath);
    console.warn(`[ContextLock] Warning: ${filePath} — ${status.reason ?? status.status}`);
  }

  // File is allowed — read and return content
  const { readFile } = await import("node:fs/promises");
  return readFile(filePath, "utf-8");
}

/**
 * Verify all protected files in a project directory at startup.
 */
export async function verifyProject(projectDir: string): Promise<void> {
  const { findProtectedFiles, DEFAULT_PATTERNS } = await import("@contextlock/core");
  const files = await findProtectedFiles(projectDir, DEFAULT_PATTERNS);

  for (const file of files) {
    const fullPath = `${projectDir}/${file}`;
    const decision = await adapter.onFileLoad(fullPath);
    const status = await adapter.getVerificationStatus(fullPath);

    switch (status.status) {
      case "trusted":
        console.log(`  ✓ ${file} — ${status.publisher}`);
        break;
      case "modified":
        console.error(`  ✗ ${file} — MODIFIED (blocked)`);
        break;
      case "untrusted":
        console.warn(`  ? ${file} — unverified`);
        break;
      default:
        console.warn(`  ! ${file} — ${status.status}: ${status.reason}`);
    }
  }
}
```

### Claude Code Configuration File

Create a `.contextlock.json` in your project root:

```json
{
  "policyLevel": "balanced",
  "trustStorePath": "~/.contextlock/truststore.json",
  "cachePath": "~/.contextlock/cache.json",
  "protectedPatterns": [
    "**/SKILL.md",
    "**/CLAUDE.md",
    "**/RULES.md",
    "**/*.prompt.md",
    "**/*.policy.md"
  ]
}
```

---

## Integration Guide: OpenClaw

OpenClaw uses the same verification engine through a dedicated adapter. The integration pattern is identical to Claude Code — only the adapter class name differs.

### Setup

```typescript
import { OpenClawAdapter, formatBlockMessage } from "@contextlock/adapter-openclaw";

const adapter = new OpenClawAdapter({
  trustStorePath: "/path/to/tcv-truststore.json",
  cachePath: "/path/to/tcv-cache.json",
  policyLevel: "strict",  // OpenClaw may prefer stricter defaults
});
```

### Hook into OpenClaw's Agent Lifecycle

```typescript
// openclaw-plugin.ts
import { OpenClawAdapter, formatBlockMessage } from "@contextlock/adapter-openclaw";

const adapter = new OpenClawAdapter({
  trustStorePath: `${process.env.HOME}/.contextlock/truststore.json`,
  cachePath: `${process.env.HOME}/.contextlock/cache.json`,
  policyLevel: "strict",
});

/**
 * OpenClaw file load interceptor.
 * Register this as a middleware in OpenClaw's file loading pipeline.
 */
export async function openclawFileMiddleware(
  filePath: string,
  next: () => Promise<string>,
): Promise<string> {
  const decision = await adapter.onFileLoad(filePath);

  if (decision === "block") {
    const status = await adapter.getVerificationStatus(filePath);
    throw new Error(formatBlockMessage(filePath, status));
  }

  if (decision === "warn") {
    const status = await adapter.getVerificationStatus(filePath);
    console.warn(`[ContextLock] ${filePath}: ${status.status} — ${status.reason ?? "unverified"}`);
  }

  return next();
}

/**
 * Verify all skill files before an OpenClaw agent session starts.
 */
export async function preSessionVerification(skillDir: string): Promise<{
  verified: string[];
  blocked: string[];
  warnings: string[];
}> {
  const { findProtectedFiles, DEFAULT_PATTERNS } = await import("@contextlock/core");
  const files = await findProtectedFiles(skillDir, DEFAULT_PATTERNS);

  const verified: string[] = [];
  const blocked: string[] = [];
  const warnings: string[] = [];

  for (const file of files) {
    const fullPath = `${skillDir}/${file}`;
    const result = await adapter.getVerificationStatus(fullPath);

    switch (result.status) {
      case "trusted":
        verified.push(file);
        break;
      case "modified":
      case "revoked":
      case "error":
        blocked.push(file);
        break;
      default:
        warnings.push(file);
    }
  }

  return { verified, blocked, warnings };
}
```

### OpenClaw Agent Configuration

In your OpenClaw agent config, reference the verification middleware:

```yaml
# openclaw-agent.yaml
agent:
  name: secure-code-reviewer
  skills_dir: ./skills
  verification:
    enabled: true
    policy: strict
    trust_store: ~/.contextlock/truststore.json
  pre_session_hooks:
    - contextlock-verify
```

---

## Integration Guide: VS Code with AI Coding Assistants

ContextLock can protect instruction files used by any VS Code AI extension that reads local markdown files — GitHub Copilot (with workspace instructions), Continue, Cody, Kiro, or any MCP-based assistant.

### Approach: VS Code Extension Wrapper

Create a VS Code extension that intercepts file reads for protected patterns and verifies them before the AI assistant consumes them.

### Example: VS Code Extension

```typescript
// extension.ts
import * as vscode from "vscode";
import {
  VerificationEngine,
  evaluatePolicy,
  DEFAULT_PATTERNS,
  isProtectedFile,
} from "@contextlock/core";
import type { VerificationEngineConfig, PolicyLevel } from "@contextlock/core";

let engine: VerificationEngine;

export function activate(context: vscode.ExtensionContext) {
  const config = vscode.workspace.getConfiguration("contextlock");
  const trustStorePath = config.get<string>("trustStorePath",
    `${process.env.HOME}/.contextlock/truststore.json`);
  const policyLevel = config.get<PolicyLevel>("policyLevel", "balanced");

  const engineConfig: VerificationEngineConfig = {
    trustStorePath,
    cachePath: `${context.globalStorageUri.fsPath}/tcv-cache.json`,
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel,
  };

  engine = new VerificationEngine(engineConfig);

  // Register file system watcher for protected files
  const watcher = vscode.workspace.createFileSystemWatcher("**/*.md");

  watcher.onDidChange(async (uri) => {
    if (isProtectedFile(uri.fsPath, DEFAULT_PATTERNS)) {
      await verifyAndNotify(uri.fsPath, policyLevel);
    }
  });

  // Register manual verify command
  const verifyCmd = vscode.commands.registerCommand(
    "contextlock.verifyFile",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      await verifyAndNotify(editor.document.uri.fsPath, policyLevel);
    },
  );

  // Register verify-all command
  const verifyAllCmd = vscode.commands.registerCommand(
    "contextlock.verifyAll",
    async () => {
      await verifyWorkspace(policyLevel);
    },
  );

  // Status bar item showing verification state
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right, 100,
  );
  statusBar.command = "contextlock.verifyFile";
  statusBar.show();

  // Update status bar when active editor changes
  vscode.window.onDidChangeActiveTextEditor(async (editor) => {
    if (!editor) {
      statusBar.hide();
      return;
    }
    const filePath = editor.document.uri.fsPath;
    if (!isProtectedFile(filePath, DEFAULT_PATTERNS)) {
      statusBar.hide();
      return;
    }
    const result = await engine.verify(filePath);
    switch (result.status) {
      case "trusted":
        statusBar.text = "$(shield) TCV: Trusted";
        statusBar.backgroundColor = undefined;
        break;
      case "modified":
        statusBar.text = "$(shield) TCV: Modified";
        statusBar.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.errorBackground",
        );
        break;
      case "untrusted":
        statusBar.text = "$(shield) TCV: Untrusted";
        statusBar.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.warningBackground",
        );
        break;
      default:
        statusBar.text = `$(shield) TCV: ${result.status}`;
        statusBar.backgroundColor = new vscode.ThemeColor(
          "statusBarItem.warningBackground",
        );
    }
    statusBar.show();
  });

  context.subscriptions.push(watcher, verifyCmd, verifyAllCmd, statusBar);
}

async function verifyAndNotify(filePath: string, policyLevel: PolicyLevel) {
  const result = await engine.verify(filePath);
  const decision = evaluatePolicy({
    level: policyLevel,
    verificationResult: result,
  });

  switch (decision) {
    case "allow":
      vscode.window.showInformationMessage(
        `✓ ${filePath}: Verified — ${result.publisher} (${result.keyId?.slice(0, 12)}...)`,
      );
      break;
    case "warn":
      vscode.window.showWarningMessage(
        `⚠ ${filePath}: ${result.status} — ${result.reason ?? "unverified"}`,
      );
      break;
    case "block":
      vscode.window.showErrorMessage(
        `✗ ${filePath}: BLOCKED — ${result.reason ?? result.status}`,
      );
      break;
  }
}

async function verifyWorkspace(policyLevel: PolicyLevel) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) return;

  const { findProtectedFiles } = await import("@contextlock/core");
  const results: string[] = [];

  for (const folder of folders) {
    const files = await findProtectedFiles(folder.uri.fsPath, DEFAULT_PATTERNS);
    for (const file of files) {
      const fullPath = `${folder.uri.fsPath}/${file}`;
      const result = await engine.verify(fullPath);
      const icon = result.status === "trusted" ? "✓" : result.status === "modified" ? "✗" : "?";
      results.push(`${icon} ${file} — ${result.status}`);
    }
  }

  const panel = vscode.window.createOutputChannel("ContextLock");
  panel.clear();
  panel.appendLine("ContextLock Verification Report");
  panel.appendLine("=".repeat(40));
  for (const line of results) {
    panel.appendLine(line);
  }
  panel.show();
}
```

### VS Code Extension Settings (package.json)

```json
{
  "contributes": {
    "configuration": {
      "title": "ContextLock",
      "properties": {
        "contextlock.trustStorePath": {
          "type": "string",
          "default": "~/.contextlock/truststore.json",
          "description": "Path to the TCV trust store file"
        },
        "contextlock.policyLevel": {
          "type": "string",
          "enum": ["strict", "balanced", "audit"],
          "default": "balanced",
          "description": "Verification policy level"
        },
        "contextlock.protectedPatterns": {
          "type": "array",
          "default": [
            "**/SKILL.md",
            "**/CLAUDE.md",
            "**/RULES.md",
            "**/*.prompt.md",
            "**/*.policy.md"
          ],
          "description": "Glob patterns for files that require verification"
        }
      }
    },
    "commands": [
      {
        "command": "contextlock.verifyFile",
        "title": "ContextLock: Verify Current File"
      },
      {
        "command": "contextlock.verifyAll",
        "title": "ContextLock: Verify All Protected Files"
      }
    ]
  }
}
```

### VS Code + GitHub Copilot Workspace Instructions

GitHub Copilot reads `.github/copilot-instructions.md` for workspace-level instructions. Protect this file with ContextLock:

```typescript
// In your VS Code extension, add this pattern:
const COPILOT_PATTERNS = [
  ...DEFAULT_PATTERNS,
  "**/.github/copilot-instructions.md",
];

const adapter = new ClaudeCodeAdapter({
  trustStorePath: "~/.contextlock/truststore.json",
  cachePath: "~/.contextlock/cache.json",
  policyLevel: "balanced",
  protectedPatterns: COPILOT_PATTERNS,
});
```

### VS Code + Continue / Cody / Other Assistants

Any AI assistant that reads local `.md` files for instructions can be protected. Add the relevant file patterns:

```json
{
  "contextlock.protectedPatterns": [
    "**/SKILL.md",
    "**/CLAUDE.md",
    "**/RULES.md",
    "**/*.prompt.md",
    "**/*.policy.md",
    "**/.github/copilot-instructions.md",
    "**/.continue/config.md",
    "**/.cody/instructions.md",
    "**/.kiro/steering/*.md"
  ]
}
```

### MCP Server Integration

For AI assistants that support MCP (Model Context Protocol), ContextLock can be exposed as an MCP tool server:

```typescript
// contextlock-mcp-server.ts
// Expose verification as MCP tools that any compatible AI assistant can call

import { VerificationEngine, DEFAULT_PATTERNS, TrustStore } from "@contextlock/core";

// Tool: verify_file
// Input: { filePath: string }
// Output: { status, publisher, keyId, reason }
async function verifyFile(args: { filePath: string }) {
  const engine = new VerificationEngine({
    trustStorePath: "~/.contextlock/truststore.json",
    cachePath: "~/.contextlock/cache.json",
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel: "balanced",
  });

  const result = await engine.verify(args.filePath);
  return {
    status: result.status,
    publisher: result.publisher,
    keyId: result.keyId,
    reason: result.reason,
    fileHash: result.fileHash,
    expectedHash: result.expectedHash,
  };
}

// Tool: list_trusted_publishers
// Input: {}
// Output: { publishers: [...] }
async function listTrustedPublishers() {
  const store = new TrustStore();
  await store.load("~/.contextlock/truststore.json");
  return {
    publishers: store.listPublishers().map((p) => ({
      name: p.publisher,
      keyId: p.key_id,
      fingerprint: p.fingerprint,
      revoked: p.revoked,
    })),
  };
}

// Tool: is_protected
// Input: { filePath: string }
// Output: { protected: boolean }
function isFileProtected(args: { filePath: string }) {
  const engine = new VerificationEngine({
    trustStorePath: "~/.contextlock/truststore.json",
    cachePath: "~/.contextlock/cache.json",
    protectedPatterns: DEFAULT_PATTERNS,
    policyLevel: "balanced",
  });
  return { protected: engine.isProtected(args.filePath) };
}
```

Register these as MCP tools in your `mcp.json`:

```json
{
  "mcpServers": {
    "contextlock": {
      "command": "node",
      "args": ["./contextlock-mcp-server.js"],
      "autoApprove": ["verify_file", "list_trusted_publishers", "is_protected"]
    }
  }
}
```

---

## Protected File Patterns

Default patterns that trigger verification:

| Pattern | Matches |
|---------|---------|
| `**/SKILL.md` | AI skill definition files |
| `**/CLAUDE.md` | Claude-specific instruction files |
| `**/RULES.md` | Rule and constraint files |
| `**/*.prompt.md` | Prompt template files |
| `**/*.policy.md` | Policy definition files |

Add custom patterns for your tool's instruction files as needed.

---

## Verification Statuses

| Status | Meaning | Typical Action |
|--------|---------|----------------|
| `trusted` | Signature valid, rollback + expiry checks pass, hash matches | Allow |
| `sealed` | Locally pinned via Mode 0 (trust-on-first-use), bytes unchanged | Allow |
| `sealed+trusted` | Both a valid local seal and a valid publisher signature | Allow |
| `modified` | File content (or length) changed since sealing/signing | Block |
| `untrusted` | No envelope, unknown signer, or file not listed in manifest | Warn or block |
| `revoked` | Signing key has been revoked in trust store | Block |
| `expired` | Manifest past its `expires_at` date | Warn or block (configurable) |
| `rollback` | Manifest version older than the highest already seen (T7) | Block |
| `error` | Parse failure, I/O error, bad payloadType, corrupt local state | Block |
| `seal-store-unavailable` | Seal store corrupt or signature-invalid (possible tampering) | Block |

---

## File Formats (v2)

### Package Layout

```
my-package/
├── SKILL.md               # Protected file
├── RULES.md               # Protected file
└── contextlock.dsse.json  # DSSE envelope containing the contextlock/2 manifest
```

One file replaces v1's two. Use `contextlock inspect` to pretty-print the payload.

### contextlock.dsse.json (DSSE v1.0.2 envelope)

```json
{
  "payload": "<base64(manifest JSON bytes)>",
  "payloadType": "application/vnd.contextlock.manifest+json",
  "signatures": [{ "keyid": "cl-acme-2026", "sig": "<base64>" }]
}
```

The signature is Ed25519 over `PAE(payloadType, payload)`. The `keyid` is an
unauthenticated hint — trust resolution tries pinned keys; the hint only
orders candidates. Verifiers consume the manifest from the verified payload
bytes, never from a sidecar file.

### Manifest payload (`contextlock/2`)

```json
{
  "spec_version": "contextlock/2",
  "package": "acme-secure-skills",
  "version": 7,
  "display_version": "1.2.0",
  "publisher": { "name": "Acme Security", "key_id": "cl-acme-2026" },
  "published_at": "2026-07-14T12:00:00Z",
  "expires_at": "2027-07-14T12:00:00Z",
  "files": [
    { "path": "SKILL.md",  "sha256": "a3f5c9...", "length": 18432 },
    { "path": "RULES.md",  "sha256": "c18be2...", "length": 7221 }
  ],
  "lints": { "unicode_tags": "absent", "bidi_controls": "absent", "zero_width": "absent" }
}
```

Hard validation failures: non-integer `version`, missing `expires_at`, path
traversal / absolute / backslash / duplicate paths, malformed hashes, missing
`length`. Unknown fields are ignored (forward compatibility).

### Root of trust (`contextlock-root/1`, in a DSSE envelope)

```json
{
  "spec_version": "contextlock-root/1",
  "version": 2,
  "expires_at": "2028-01-01T00:00:00Z",
  "keys": { "cl-acme-2026": { "alg": "ed25519", "pub": "<base64url raw 32B>" } },
  "threshold": 1
}
```

Rotation: version exactly N+1, signed by a threshold of BOTH the old and new
root's keys (the DSSE envelope carries multiple signatures natively). Rotation
resets the anti-rollback baseline for the publisher (fast-forward recovery).

### truststore.json (`contextlock-truststore/2`, local state)

```json
{
  "schema": "contextlock-truststore/2",
  "roots": { "Acme Security": { "spec_version": "contextlock-root/1", "...": "..." } },
  "trusted_publishers": [
    {
      "publisher": "Acme Security",
      "key_id": "cl-acme-2026",
      "public_key": "base64-encoded-ed25519-public-key",
      "fingerprint": "c8e4b7d5f9c2...",
      "revoked": false,
      "policy": {
        "default_action": "block",
        "allow_expired_manifest": false,
        "allow_offline_cached_manifest": true
      }
    }
  ],
  "sig": { "key_fingerprint": "…", "signature": "…" }
}
```

Local state (trust store, seal store, anti-rollback state) lives in
`~/.contextlock/` and is signed with the machine-local key; a corrupt or
hand-edited store fails CLOSED and loud. Legacy `tcv-truststore/v1` stores
load with a warning and upgrade on the next save.

---

## Security Model

### What ContextLock defends against

- Local tampering of instruction files after download or review
- Prompt-injection persistence (an agent editing its own instruction files)
- Malicious mirrors serving altered files
- Repository compromise (without signing key compromise)
- Rollback: replaying an older, vulnerable signed release (monotonic version + local state)
- Freeze: withholding updates indefinitely (mandatory `expires_at`)
- Mix-and-match: combining files from different releases (one manifest per trust boundary)
- Cross-package confusion and manifest path abuse (bounded discovery, path validation)
- Manifest stripping (protected files without evidence are loud, never silent)
- Invisible Unicode smuggling (exact-byte hashing + sign-time content lints)
- Accidental file corruption
- Spoofed files impersonating trusted publishers

The full threat model, including what each mechanism does and does not
guarantee, is SPEC.md section 4.

### What ContextLock does not defend against

- Compromised publisher private keys (mitigated by rotation and revocation, not prevented)
- Malicious content signed by a trusted publisher
- Tool bypasses that disable verification hooks
- OS-level compromise on the user's machine

### Key principle

Verified means authentic and unmodified — not necessarily safe. A trusted publisher could still publish harmful instructions. ContextLock establishes provenance, not content safety.

---

## License

See LICENSE file for details.
