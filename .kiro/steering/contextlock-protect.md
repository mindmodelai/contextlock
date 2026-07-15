---
inclusion: manual
---

# Skill: ContextLock Protect

Protect files in a package directory so they can be verified for integrity and authenticity by users and AI tools.

## When to use

Use this skill when a user asks to:
- Protect files, sign files, or make files verifiable
- Publish a skill pack, prompt pack, or instruction files
- Set up content verification for a package
- Hash-protect a file or embed a hash in a filename

## Two protection modes

### Mode 1: Hash (lightweight, no keys)

Embeds a SHA-256 prefix in the filename. Quick, no setup, but advisory only — does not prove publisher identity.

```typescript
import { protect } from "@contextlock/cli-publisher";

const result = await protect({
  directory: "./my-package",
  mode: "hash",
});
// SKILL.md → SKILL.a3f5c9e8d1f24a6c.md
```

Or for a single file:

```typescript
import { hashFilename } from "@contextlock/cli-publisher";

const result = await hashFilename({ filePath: "./SKILL.md" });
// result.hashedPath → "./SKILL.a3f5c9e8d1f24a6c.md"
```

### Mode 2: Sign (full trust, Ed25519)

Generates a keypair (if needed), builds a manifest with SHA-256 hashes of all protected files, and signs it. Proves both integrity and publisher identity.

```typescript
import { protect } from "@contextlock/cli-publisher";

const result = await protect({
  directory: "./my-package",
  mode: "sign",
  packageName: "my-skills",
  version: "1.0.0",
  publisherName: "My Name",
});
// Creates: manifest.json, manifest.sig.json, tcv-private.key, tcv-public.key
```

Or step by step:

```typescript
import { initKey, buildManifest, signManifest } from "@contextlock/cli-publisher";

const keys = await initKey({ output: "./keys" });
const build = await buildManifest({
  directory: "./my-package",
  packageName: "my-skills",
  version: "1.0.0",
  publisherName: "My Name",
  keyId: keys.fingerprint,
  fingerprint: keys.fingerprint,
});
const sig = await signManifest({
  manifestPath: build.manifestPath,
  privateKeyPath: keys.privateKeyPath,
});
```

## What gets protected

Files matching these default glob patterns:
- `**/SKILL.md`
- `**/CLAUDE.md`
- `**/RULES.md`
- `**/*.prompt.md`
- `**/*.policy.md`

Custom patterns can be passed via the `patterns` option.

## What to distribute

- Hash mode: the hash-embedded files (e.g., `SKILL.a3f5c9e8.md`)
- Sign mode: the package directory with `manifest.json` and `manifest.sig.json`, plus the public key (`tcv-public.key`) shared through a separate trusted channel

## Key files reference

- `#[[file:packages/cli-publisher/src/commands/protect.ts]]` — unified protect command
- `#[[file:packages/cli-publisher/src/commands/hash-filename.ts]]` — filename hash command
- `#[[file:packages/cli-publisher/src/commands/build-manifest.ts]]` — manifest builder
- `#[[file:packages/cli-publisher/src/commands/sign-manifest.ts]]` — manifest signer
- `#[[file:packages/cli-publisher/src/commands/init-key.ts]]` — keypair generator
