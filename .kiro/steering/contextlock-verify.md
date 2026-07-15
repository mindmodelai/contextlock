---
inclusion: manual
---

# Skill: ContextLock Verify

Verify the integrity and authenticity of protected files before they are loaded or used by AI tools.

## When to use

Use this skill when a user asks to:
- Verify a file, check a file, or validate a file
- Check if a file has been tampered with
- Trust or untrust a publisher
- Manage the trust store
- Check a filename hash

## Verification flow

The verify command performs a layered check:

1. **Manifest + signature verification** (full trust) — Locates `manifest.json` and `manifest.sig.json`, verifies the Ed25519 signature against the trust store, then compares the file's SHA-256 hash against the manifest entry.

2. **Filename-hash extraction** (advisory fallback) — If the filename matches `<name>.<hex-hash>.<ext>`, extracts the embedded hash and compares it against the computed content hash. This is always advisory and never produces `trusted` status.

Both checks run on every verify call. The manifest result is primary; the filename-hash result is supplementary info shown alongside it.

## Usage

### Verify a file

```typescript
import { userVerify } from "@contextlock/cli-user";

const result = await userVerify({
  filePath: "./my-package/SKILL.md",
  trustStorePath: "./tcv-truststore.json",
});

console.log(result.displayMessage);
// ✓ ./my-package/SKILL.md — trusted (publisher: Acme, key: c8e4b7...)

// If the file has an embedded filename hash, it's also reported:
// ✓ ... — trusted (publisher: Acme, key: c8e4b7...)
//   ℹ filename hash matches (advisory — does not prove publisher identity)

console.log(result.result.status);     // "trusted" | "modified" | "untrusted" | ...
console.log(result.filenameHash);      // { hasEmbeddedHash, matches, embeddedHash, computedHashPrefix }
```

### Trust a publisher first

```typescript
import { trustAdd, trustList } from "@contextlock/cli-user";

await trustAdd({
  publicKeyPath: "./publisher-public.key",
  publisherName: "Acme Security",
  trustStorePath: "./tcv-truststore.json",
});

const { publishers } = await trustList({ trustStorePath: "./tcv-truststore.json" });
```

### Revoke a compromised key

```typescript
import { trustRevoke } from "@contextlock/cli-user";

await trustRevoke({
  keyId: "c8e4b7d5f9c2...",
  trustStorePath: "./tcv-truststore.json",
});
// All files signed with this key will now return status: "revoked"
```

## Verification statuses

| Status | Meaning |
|--------|---------|
| `trusted` | Signature valid, hash matches, publisher in trust store |
| `modified` | Valid signature but file content changed since signing |
| `untrusted` | No manifest, unknown signer, or invalid signature |
| `revoked` | Signing key revoked in trust store |
| `expired` | Manifest past its `expires_at` date |
| `error` | Parse failure, I/O error, or other problem |

## Filename-hash results (supplementary)

| Field | Meaning |
|-------|---------|
| `hasEmbeddedHash` | Whether the filename matches `<name>.<hex>.<ext>` |
| `matches` | Whether the embedded hash matches the computed content hash prefix |
| `embeddedHash` | The hex string extracted from the filename |
| `computedHashPrefix` | The first N chars of the actual SHA-256 |

Filename hash alone never produces `trusted`. It's informational only.

## Key files reference

- `#[[file:packages/cli-user/src/commands/verify.ts]]` — verify command with filename-hash fallback
- `#[[file:packages/cli-user/src/commands/trust-add.ts]]` — trust add
- `#[[file:packages/cli-user/src/commands/trust-remove.ts]]` — trust remove
- `#[[file:packages/cli-user/src/commands/trust-revoke.ts]]` — trust revoke
- `#[[file:packages/cli-user/src/commands/trust-list.ts]]` — trust list
- `#[[file:packages/core/src/engine.ts]]` — verification engine
- `#[[file:packages/core/src/filename-hash.ts]]` — filename hash extractor
