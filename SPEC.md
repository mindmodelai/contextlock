# ContextLock Specification v2 (Draft)

**Status:** Draft for review - 2026-07-14
**Supersedes:** `trusted_content_verification_plugin_project_spec.md` (v1) and the crypto-format portions of `.kiro/specs/contextlock/`
**Implementation baseline:** the existing `packages/*` monorepo (v1 engine, 213 tests). Section 13 maps every v2 change to the v1 code it modifies.

---

## 1. One-sentence mission

ContextLock makes the mutable verifiable: it gives AI agent instruction files (SKILL.md, CLAUDE.md, rules, prompt packs, agent configs) the same authenticity and integrity guarantees the software world already expects of packages and binaries, enforced before those files influence model behavior.

## 2. Why this must exist

Instruction files are executable in effect but treated as data. A SKILL.md or CLAUDE.md steers an agent with something close to system-prompt privilege, yet it ships as plain markdown that anything with write access can silently alter. Four structural gaps make this a real attack surface, not a hypothetical:

1. **Git proves history, not provenance.** A commit proves "this content entered this repo at this time." It says nothing about who authored the content or whether it matches what a publisher released. Once a skill is copy-pasted from a gist, marketplace, or blog post, chain of custody is gone.
2. **The highest-value files live outside any repo.** `~/.claude/CLAUDE.md`, global skills, plugin caches. No git, no diff, no review. Mutable, invisible, implicitly trusted.
3. **Working-tree edits are invisible until someone looks.** Agents load the file on disk, not the file at HEAD. Between commits, a tampered file is only detectable if a human happens to run `git diff`.
4. **Prompt injection can persist.** An injected agent can edit its own instruction files ("append this line to CLAUDE.md") so the compromise survives across sessions - the agent-world equivalent of malware writing to a startup script. Integrity verification breaks this persistence loop even when it cannot stop the initial injection.

### The incident record (2026)

This is no longer speculative. As of mid-2026:

- **ClawHavoc** (Jan-Feb 2026): 341 malicious skills on ClawHub (~11.9% of the registry, ~1,184 historical across repos), ~300k OpenClaw users exposed, delivering the AMOS macOS stealer. (CSA "Poisoned Foundations", 2026-06-30; Unit 42 analysis.)
- **ToxicSkills** (Snyk, 2026-02-05): of 3,984 scanned skills, 36.8% had at least one flaw, 534 critical; 91% of confirmed-malicious skills used prompt injection.
- **Claude Code config-file CVEs**: CVE-2025-59536 and CVE-2026-21852 (repo-controlled config files triggering command execution / credential theft), plus "Clinejection" in Cline.
- **Invisible Unicode Tag injection** (U+E0000-E007F) demonstrated inside SKILL.md files (CSA research note).

Meanwhile the ecosystem's own standards ask for exactly this control: **OWASP Agentic Skills Top 10, AST01 "Malicious Skills"** recommends verbatim: *"Require cryptographic signatures (ed25519) on all published skills; reject unsigned installs"* - with the crucial caveat that *"a signature proves authorship, not safety."* The Agent Skills open spec (agentskills.io, adopted by 40+ clients) defines **no integrity or signing mechanism at all**. That silence is the gap this project fills.

### Why prevention beats detection here

Scanning-based defenses (Snyk mcp-scan, Heeler, HiddenLayer) are detection: they judge content. Published adaptive-attack research reports 78-93% bypass rates against detection-based prompt-injection defenses (Maloyan and Namiot, arXiv 2601.17548). Integrity and provenance are prevention: they do not judge content, they make tampering and impersonation detectable regardless of how clever the payload is. The two compose - ContextLock deliberately does only the prevention half.

## 3. What ContextLock is, and is not

**Is:** an opt-in authenticity and integrity layer for AI instruction files. It answers two questions before a file influences an agent: *who published this?* and *has it changed since?*

**Is not:** malware scanning, content moderation, encryption, or a safety guarantee. Verified means authentic and unmodified, not benign. A trusted publisher can still publish harmful instructions. ContextLock establishes provenance; content safety is a separate, composable layer.

## 4. Threat model

### Defended against

| # | Threat | Mechanism |
|---|--------|-----------|
| T1 | Local tampering of instruction files after download or review | Hash mismatch vs seal or signed manifest |
| T2 | Prompt-injection persistence (agent edits its own instruction files) | Seal/manifest mismatch on next load; write-deny rules on protected paths |
| T3 | Malicious mirror or marketplace serving altered files | Signed manifest; publisher key pinning |
| T4 | Repository compromise without signing-key compromise | Signature verification fails on re-signed content |
| T5 | Spoofed packages impersonating known publishers | Explicit key/identity pinning; no trust from names or URLs |
| T6 | Manifest stripping (delete manifest to downgrade to "unverified") | Protected-class files without a seal or manifest are loud: block under strict, warn under balanced. Never silent |
| T7 | Rollback (replaying an older, vulnerable signed manifest) | Monotonic `version` counter + local highest-version-seen state |
| T8 | Freeze (withholding updates indefinitely) | Mandatory `expires_at`; bounded to re-signing cadence (see 6.4 honesty note) |
| T9 | Mix-and-match (combining files from different releases) | Single manifest per trust boundary covers all files with hashes and lengths |
| T10 | Cross-package confusion (file verified under package A presented as package B) | File binds to exactly one manifest by directory containment; bounded manifest discovery (no unbounded walk-up) |
| T11 | Manifest path abuse (`../` traversal, absolute paths, duplicates, oversize) | Schema validation rejects all four |
| T12 | Signature replay across document types | DSSE PAE: the payloadType is covered by the signature |
| T13 | Invisible Unicode smuggling surviving human review | Exact-byte hashing plus sign-time content lints (Tag block, zero-width, bidi controls) |
| T14 | Accidental corruption and drift | All modes, trivially |

### Explicitly not defended against

- **Compromised publisher private key** (mitigated by rotation, revocation, threshold roots; not prevented).
- **Malicious content signed by a trusted publisher** (provenance, not safety).
- **A same-privilege attacker with arbitrary code execution on the user's machine.** Such an attacker can edit the trust store, the seal store, and settings that register the hooks. Section 8 documents the layered mitigations (OS ACLs, managed settings, deny rules) and where the boundary honestly sits. ContextLock hardens the distribution and persistence channels; it is not an EDR.
- **Host-tool bypass**: load paths the host tool does not expose to hooks (section 7 maps exactly which paths those are in Claude Code today, so the residual risk is explicit rather than vague).
- **Runtime injection through non-file channels** (web content, tool results). Different layer.

## 5. Trust modes: a ladder, not a menu

v1 framed "filename hash" and "signed manifest" as two options. v2 defines a three-rung ladder where each rung is independently useful and upgrades cleanly to the next. The critical addition is Mode 0, which requires zero publisher adoption and is therefore the adoption path for everything else.

### Mode 0: Local Seal (TOFU) - the flagship MVP

Trust-on-first-use pinning. The user (or their org) reviews a file once and seals it:

```bash
contextlock seal ./CLAUDE.md            # seal one file
contextlock seal --all                  # seal every protected-class file found
contextlock status                      # show seal state for the workspace
contextlock reseal ./CLAUDE.md          # deliberate re-approval after an intended edit
```

Sealing records `(path, sha256, length, sealed_at, note)` in a **seal store** outside the workspace (`~/.contextlock/seals.json`), signed by a **machine-local Ed25519 key** (`~/.contextlock/local.key`, created on first run with restrictive ACLs). Any later mutation of a sealed file fails verification until deliberately resealed.

Why this is the MVP and not the signed-manifest mode:

- **It solves the persistence attack (T2) on day one** for every file the user already has, including `~/.claude/CLAUDE.md` which no publisher will ever sign.
- **It needs no ecosystem.** The publisher mode has a chicken-and-egg problem: users will not verify until publishers sign, publishers will not sign until users verify. Mode 0 delivers value unilaterally and creates the verifying installed base that makes Mode 2 worth adopting.
- **It is the honest framing of "make the mutable immutable":** mutation becomes detectable and requires a deliberate human act to accept.

Boundary honesty: the local signing key defeats an attacker who can edit `seals.json` but has not achieved code execution as the user. A same-privilege attacker can re-seal. The layered response is in section 8.

### Mode 1: Change hints (demoted from v1's "filename hash mode")

A truncated content hash embedded in a filename (`SKILL.a3f5c9e8d1f24a6c.md`). v2 keeps the existing implementation but renames and repositions it: this is a **development convenience for visible change detection and cache busting, not a security mode**. It never contributes to trust status, never appears in security messaging, and the CLI labels it "hint". Rationale: an attacker re-hashes and renames in two seconds; letting it wear a security badge manufactures false confidence.

### Mode 2: Signed manifests (publisher trust)

The full supply-chain layer: a publisher signs a manifest covering every file in a package; users pin the publisher's key or identity. Format in section 6. Two key profiles:

- **Profile A (baseline, mandatory to implement): raw Ed25519 keys.** 32-byte keys, base64url, minisign-style short key IDs. Works offline, no accounts, no OAuth ceremony, suitable for solo skill authors. This is also literally what OWASP AST01 asks for.
- **Profile B (optional, v2.1+): Sigstore keyless.** DSSE envelope inside a Sigstore bundle; identity policy expressed as `certificate-identity` + `certificate-oidc-issuer` (exactly the model npm provenance trained developers on). Ideal for CI-published packages. Verification is fully offline given a v0.3 bundle and a pinned `trusted_root.json` shipped with CLI releases. Signing is never offline (OIDC + Fulcio + Rekor round-trips), which is why Profile A remains the baseline.

The engine treats modes as evidence sources feeding one verdict: `sealed`, `trusted` (signed), `sealed+trusted`, `modified`, `untrusted`, `revoked`, `expired`, `rollback` (an older signed manifest replayed after a newer one was seen - blocks under strict and balanced, like `revoked`), `error`, or `unprotected`.

## 6. Cryptographic format (v2)

### 6.1 Hashing: exact bytes, canonicalize at sign time

**Breaking change from v1.** v1 normalized CRLF to LF and stripped BOMs at *verify* time. That creates a parser differential: the tool consumes the bytes on disk, but ContextLock verified a transformed version - two byte streams that hash identically after normalization are a smuggling channel, and the thing you attested is not the thing the model read.

v2 rule:

- **The hash is SHA-256 over the exact bytes on disk.** No transformation, ever, at verify time.
- **The publisher CLI and `seal` command normalize at signing time**: rewrite the file to UTF-8, LF, no BOM (with a warning), *then* hash what was written. Cross-platform predictability is achieved by fixing the artifact once, not by reinterpreting it on every read.
- Verifier UX: on mismatch, the engine additionally computes the LF-normalized hash purely to improve the error message ("difference is line-endings only; re-seal or re-download with LF endings"). This diagnostic never changes the verdict.
- `.gitattributes` guidance ships with the publisher CLI (`*.md text eol=lf`) so git checkout does not undo normalization.

### 6.2 Envelope: DSSE, not a bespoke signature file

v1's `tcv-signature/v1` (raw Ed25519 over SHA-256 of manifest bytes) is replaced by **DSSE v1.0.2** (secure-systems-lab/dsse), the envelope used by in-toto, SLSA, npm provenance, and Sigstore bundles:

```json
{
  "payload": "<base64(manifest JSON bytes)>",
  "payloadType": "application/vnd.contextlock.manifest+json",
  "signatures": [{ "keyid": "cl-acme-2026", "sig": "<base64>" }]
}
```

- Signature is computed over `PAE(payloadType, payload)` where `PAE(type, body) = "DSSEv1" || SP || LEN(type) || SP || type || SP || LEN(body) || SP || body`. Length-prefixing is injective and the payloadType is covered, killing cross-protocol replay (T12).
- **`keyid` is an unauthenticated hint** (per the DSSE spec it "MUST NOT be used for security decisions"). Trust resolution walks the trust store and tries pinned keys; keyid only narrows the candidate set.
- **Verify-then-parse the same bytes**: the manifest consumed by the engine is the decoded `payload` from the verified envelope, never a re-read of a sidecar file.
- One file replaces v1's two: the package ships `contextlock.dsse.json` (envelope containing the manifest). A `contextlock inspect` command pretty-prints the payload, answering the "base64 is not human-readable" objection.
- Multiple signatures are supported by the envelope natively (future multi-sig / reviewer attestations, converging with SkillSeal's reviewer-attestation idea).
- DSSE + PAE over `node:crypto` is roughly 50 lines; no new dependency is required.

### 6.3 Manifest: `contextlock/2` (TUF-inspired, deliberately minimal)

One signed manifest per trust boundary, fusing TUF's targets and snapshot roles so intra-package mix-and-match (T9) is structurally impossible:

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

Validation rules (all hard failures):

- `version` is a **monotonic integer**, not semver. The verifier keeps per-`(package, key)` highest-version-seen state and rejects `version < last_seen` (T7 rollback; equality is accepted so the installed release re-verifies on every load). The state file (`~/.contextlock/state.json`) is signed local state per section 8: corrupt or hand-edited state fails closed. `display_version` is informational only.
- `expires_at` is **required** (T8 freeze). See 6.4.
- `path` entries: relative, forward slashes, no `..` segments, no absolute paths, no duplicates, must resolve inside the manifest's directory (T10, T11).
- `length` is enforced before hashing (endless-data defense, free with the read).
- Unknown fields are ignored (DSSE consumer rule), enabling forward compatibility.

**Manifest discovery is bounded.** v1 walked up the directory tree to the filesystem root; a file could bind to any ancestor manifest (T10). v2: discovery walks up at most to the workspace boundary (repo root, or the configured protected-root), stops at the **first** envelope found, and the file's relative path must appear in that manifest. Deeper manifests shadow shallower ones.

### 6.4 Freshness honesty

Without an online timestamp service, `expires_at` bounds staleness only to the re-signing cadence publishers tolerate. The spec says this plainly rather than implying more: recommended validity is 90-365 days, and the failure mode being prevented is "signed once in 2026, blindly trusted in 2029". A transparency log or timestamp role is explicitly future work (section 14), not quietly assumed.

### 6.5 Root of trust and rotation (minimal, chained)

Publishers who outgrow a single key publish a minimal root file (TUF root role, stripped to essentials):

```json
{
  "spec_version": "contextlock-root/1",
  "version": 2,
  "expires_at": "2028-01-01T00:00:00Z",
  "keys": { "cl-acme-2026": { "alg": "ed25519", "pub": "<base64url raw 32B>" } },
  "threshold": 1
}
```

- The root ships inside a DSSE envelope (`contextlock.root.dsse.json`, payloadType `application/vnd.contextlock.root+json`); the envelope's native multi-signature support carries the rotation signatures.
- A new root version must be signed by a **threshold of both the old and the new keys**, version exactly N+1 (the TUF rotation chain). Threshold defaults to 1 so solo authors feel no ceremony; orgs raise it. The initial pin (`contextlock trust root add`) is trust-on-first-use and verifies self-consistency (the root's own threshold with its own keys).
- **Fast-forward recovery**: on key rotation, the verifier resets its highest-version-seen baseline for that publisher (the TUF §5.3.11 escape hatch). `contextlock trust reset <publisher>` exposes the same manually.
- Key hygiene guidance: root key offline and rare; manifest signing key routine. Solo authors may use one key; the format does not force the split, the docs recommend it.
- Deliberately **not** adopted from TUF: snapshot/timestamp as separate roles (meaningless without a repository server), delegations, consistent snapshots. Precedent: Sigstore uses full TUF only to update one file; Go's sumdb rejected TUF outright for a simpler design. Minimal on purpose, with the reasoning recorded.

### 6.6 Keys and algorithms

- **Ed25519 + SHA-256 only in v1 of the format.** No algorithm agility, no `alg` headers (the verifier's trust config decides the algorithm; this kills alg-confusion by construction, one of DSSE's design points).
- Key format: **raw 32-byte Ed25519 keys, base64url**, with short minisign-style key IDs. PEM/JWK are import/export conveniences in tooling, never the wire format.
- Reference implementation: `node:crypto` (`crypto.sign(null, ...)`, `crypto.verify(null, ...)`, `createHash('sha256')`), zero runtime dependencies, baseline **Node >= 22.13.0** (WebCrypto Ed25519 stable). `@noble/ed25519` (already a dependency) remains the portability fallback for non-Node runtimes. *Implementation status (Phase B): the shipped code still uses `@noble/ed25519`+`@noble/hashes` end to end - swapping the primitive layer to `node:crypto` is a self-contained cleanup, not a format change, since keys, signatures, and hashes are byte-identical.*

### 6.7 Sign-time content lints

Signing is the right moment to catch content-level smuggling that survives human review. `build-manifest` / `protect` scan every covered file for:

- Unicode Tag block characters (U+E0000-E007F) - the demonstrated SKILL.md injection vector,
- zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner),
- bidirectional override controls (U+202A-202E, U+2066-2069).

Default: **block signing** with an override flag (`--allow-lint <rule>` recorded in the manifest's `lints` field so verifiers and humans can see the exception). Verifiers may additionally warn when a manifest lacks lint attestations. This does not make signatures mean "safe" - it removes the cheapest known way to make malicious content look reviewed.

## 7. Enforcement architecture: Claude Code

Grounded in the actual extension surface (researched against official docs, 2026-07-14). The v1 spec imagined a "before context assembly" hook; **no such hook exists**. Enforcement therefore layers four real mechanisms, ordered by strength.

### 7.1 What Claude Code actually provides (confirmed vs unverified)

Confirmed:

- **`PreToolUse` hooks can hard-deny** tool calls (`permissionDecision: "deny"` via JSON or exit code 2), with matchers per tool. This blocks the `Skill` tool (unverified skill invocation) and `Read`/`Edit`/`Write` on matched paths.
- **`SessionStart` hooks** run at session initialization and can inject `additionalContext`, but have **no documented blocking capability**.
- **Managed settings** (`managed-settings.json` / server-managed) are the enforcement anchor: managed hooks cannot be removed by project or user settings; `allowManagedPermissionRulesOnly: true` makes managed permission rules the only ones evaluated; `permissions.deny` path rules (e.g. `Edit(~/.contextlock/**)`) are enforced regardless of model intent.
- **No content verification exists anywhere in the pipeline today**: plugin marketplaces pin git commit SHAs at best; CLAUDE.md, skills, and rules have no signing, no hashes, no install-time validation hook.
- **Nested CLAUDE.md files load lazily** (when the agent reads files in that directory) with no before-load hook.
- The `FileChanged` hook event exists (informational) and can drive seal-state invalidation.

Resolved empirically on 2026-07-14 against Claude Code 2.1.210 (full method and evidence: `docs/claude-code-surface.md`). These are undocumented behaviors and must be re-tested per release:

- U1 **resolved, favorable**: the `SessionStart` hook runs *before* the root project CLAUDE.md is ingested into context (confirmed on cold start and resume). A sweep that quarantines a tampered CLAUDE.md therefore protects the *current* session, not just the next one. Nested, lazily loaded CLAUDE.md files remain uncovered by the sweep at load time.
- U2 **resolved, split**: SKILL.md body loading is harness-internal to the `Skill` tool - no `Read` tool event fires, so `PreToolUse(Read)` cannot see skill bodies. However, a `PreToolUse` hook with matcher `Skill` hard-denies the invocation (confirmed). Skill enforcement lives on the `Skill` matcher, not the `Read` matcher.
- U3 **resolved**: hook definitions are snapshotted at process start; mid-session edits to settings.json are inert until restart. (Security upside: a mid-session attacker cannot un-register verification hooks without a restart. Operational note: ContextLock config changes need a session restart.)
- U4 **resolved, with a scope caveat**: installed plugin cache content is never re-validated - and for *local-source* marketplaces the cache is bypassed entirely: content is served live from the source directory. Write-deny and sweep coverage must therefore include marketplace source directories, not just `~/.claude/plugins/cache/**`. The git/remote-source marketplace path (where the cache is the load path) was not tested and remains open.

### 7.2 The four enforcement layers

**Layer 1 - Write-time and install-time (strongest, always available).**
Verification where ContextLock controls the moment: `contextlock install <source>` verifies packages before placing files into skill/plugin directories; `seal` pins files at review time. For CLAUDE.md - which has no load hook - write-time is the *primary* control: seal it, then deny unauthorized writes (Layer 3). TOCTOU note: verify-at-install plus write-deny closes the gap that verify-at-load alone leaves open.

**Layer 2 - Session-start sweep.**
A `SessionStart` hook runs `contextlock sweep`: verify every protected-class file reachable from the workspace and the user scope. Failures quarantine the file (move aside + placeholder) where policy allows, and always inject a status report via `additionalContext` so the model and user both see it. Confirmed on Claude Code 2.1.210 (U1): the hook runs before the root CLAUDE.md is ingested, so sweep-plus-quarantine is effective for the current session for root instruction files. This ordering is undocumented, so the plugin treats it as an optimization, not a guarantee: write-time sealing (Layer 1) remains the primary CLAUDE.md control, and nested lazily loaded CLAUDE.md files are covered only by seal plus write-deny.

**Layer 3 - Read/invoke/write-time denial.**
`PreToolUse` hooks (shipped in the plugin's `hooks/hooks.json`):

- matcher `Skill`: deny invocation when the skill's files fail verification. This is the *only* interception point for skill content: SKILL.md bodies load harness-internally and never surface as `Read` events (U2),
- matcher `Read`: deny explicit reads of protected-class files in `modified`/`revoked` state (does not cover skill bodies, per U2),
- matcher `Edit|Write`: deny writes to sealed files, to ContextLock's own state (`~/.contextlock/**`), and to plugin marketplace source directories (U4: local-source marketplaces serve content live from source, bypassing the cache), turning T2 persistence attempts into visible permission denials.
- `FileChanged`: mark seal state dirty for re-verification.

**Layer 4 - Managed policy (teams and enterprises).**
A shipped `managed-settings.json` template registers the hooks and deny rules at the managed tier with `allowManagedPermissionRulesOnly: true`, so a repo-controlled `.claude/settings.json` (the exact vector of CVE-2025-59536 / CVE-2026-21852) cannot unregister verification. For individuals, the same file works via the OS-admin path, making "attacker must escalate past user level to disable verification" achievable on a single machine.

### 7.3 Packaging

The adapter stops being a TypeScript class nobody calls (v1's `ClaudeCodeAdapter.onFileLoad` has no caller) and becomes an installable **Claude Code plugin**:

```
contextlock-plugin/
  .claude-plugin/plugin.json
  hooks/hooks.json            # SessionStart sweep, PreToolUse matchers above
  bin/contextlock             # CLI (seal, sweep, verify, trust, inspect, install)
  skills/status/SKILL.md      # /contextlock:status - human-readable report
  settings.json               # recommended deny rules (advisory tier)
  managed-settings.template.json
```

Bootstrap honesty: the plugin verifies content, but the plugin itself is distributed through the unverified channel it exists to fix. Interim answer: publish signed release artifacts + a one-line install verifier script, pin the marketplace entry to commit SHAs, and document the residual risk. Long-term answer: section 14 (upstream signed plugins).

### 7.4 Empirical results (U1-U4)

The test plan was executed on 2026-07-14 against Claude Code 2.1.210 on Windows 11; verdicts are folded into 7.1 and 7.2 above. Full method, commands, fixtures, and trimmed transcripts: `docs/claude-code-surface.md` and `docs/evidence/`. Because none of these behaviors is documented, the surface doc is version-stamped and the tests are designed to be re-run per Claude Code release (they cost roughly a dozen haiku-priced headless invocations).

Remaining open experiment: cache re-validation for git/remote-source marketplaces, where the cache *is* the load path (needs a hosted test repo; U4 only covered local-source marketplaces).

## 8. Self-protection: the trust store is also a mutable file

Turtles all the way down: anything that can tamper with SKILL.md can try to tamper with `truststore.json`, `seals.json`, or the settings that register the hooks. v2 addresses this explicitly instead of ignoring it:

1. **State lives outside the workspace** (`~/.contextlock/`), never in the repo an agent is working on. Nothing repo-controlled can add a trusted key (this also rules out the v1 README's `.contextlock.json`-in-project-root pattern for trust configuration; per-project config may *narrow* policy, never widen it - the nono trust-policy rule "project policy cannot weaken user policy" is adopted verbatim).
2. **Local state is signed** with the machine-local key; a corrupt or hand-edited store fails closed (verification unavailable, which is distinct from untrusted, and loud).
3. **Restrictive ACLs** on `~/.contextlock/` at init (Windows: DACL to the user + admins; POSIX: 0700).
4. **The agent is denied write access** to `~/.contextlock/**` and `~/.claude/settings.json`-class files via the Layer 3/4 deny rules, so the most common attacker (an injected agent at user privilege inside the tool) hits a wall the harness enforces.
5. **The honest boundary**: an attacker with arbitrary code execution as the user, outside the tool, wins against user-level state. The managed tier (Layer 4) moves the goalposts to admin privilege; beyond that is EDR territory, and the spec says so.

## 9. Trust policy

Converging deliberately with nono's `trust-policy.json` shape (same problem, same author-community; divergence needs a reason):

```json
{
  "spec_version": "contextlock-policy/1",
  "defaults": { "mode": "warn" },
  "rules": [
    { "match": "~/.claude/**/CLAUDE.md",   "require": "seal",   "mode": "deny" },
    { "match": "**/skills/**/SKILL.md",    "require": "signed", "mode": "deny",
      "publishers": ["cl-acme-2026", "github:acme-org/*"] },
    { "match": "**/*.prompt.md",           "require": "any",    "mode": "warn" },
    { "match": "./experiments/**",         "require": "none",   "mode": "audit" }
  ]
}
```

- `require`: `seal` | `signed` | `any` (either) | `none`. `publishers` pins Profile A key IDs or Profile B identities (`issuer:identity` globs).
- `mode`: `deny` | `warn` | `audit` (maps onto v1's policy engine, which survives mostly intact).
- Policy layering: managed > user > project, and lower layers can only tighten. First-match wins within a layer.
- v1's per-publisher `default_action` folds into rules; the v1 policy matrix remains as the default rule set.

## 10. File classes under protection (default)

| Class | Examples | Primary mechanism |
|-------|----------|-------------------|
| Agent memory/instructions | `CLAUDE.md`, `AGENTS.md`, `~/.claude/CLAUDE.md` | Seal + write-deny (no load hook exists) |
| Skills | `SKILL.md` + bundled files | Signed manifest; PreToolUse(Skill) deny |
| Rules/policies | `.claude/rules/*.md`, `RULES.md`, `*.policy.md` | Seal or signed; sweep |
| Prompt packs | `*.prompt.md` | Signed manifest |
| Hook/agent configs | `hooks.json`, `agents/*`, `.mcp.json` | Seal + write-deny (config-CVE class) |
| Plugin content | `~/.claude/plugins/cache/**` | Verify at install; sweep (pending U4) |

Patterns are configurable; these defaults ship enabled in `warn` mode and `deny` for the seal-required rows.

## 11. Prior art and positioning

Between February and June 2026 this space went from empty to three implementations. ContextLock's lane must be chosen against them, not asserted in a vacuum:

| Project | What it is | Relationship |
|---------|-----------|--------------|
| **nono skills attestation** (Luke Hinds, Sigstore's creator) | DSSE + in-toto + Sigstore bundles for SKILL.md/CLAUDE.md, trust-policy.json, runtime-coupled to the nono sandbox (Rust) | Closest prior art. **Align, don't compete**: same envelope, compatible policy shape. ContextLock's difference: vendor-neutral spec + TS reference implementation, not tied to a sandbox runtime |
| **NVIDIA Verified Agent Skills** | OMS/X.509 detached signatures, NVIDIA as sole root, catalog-centric | Validates demand; single-publisher model is the opposite of an open trust store |
| **SkillSeal** (mcyork) | GPG/SSH signing CLI + a Claude Code PreToolUse hook, beta, one maintainer | Validates hook-based enforcement and reviewer attestations; ad-hoc envelope, no spec |
| **ETDI** (arXiv 2506.01333) | Signed MCP tool definitions + OAuth policy | Adjacent layer (tools, not instruction files); cite as the analogue |
| **OWASP AST01 / CSA best practices** | Normative demand for ed25519 skill signing | The standards tailwind; quote directly |
| **VS Code Marketplace signing, npm provenance** | Mainstream precedents (extension signing; DSSE/SLSA attestations) | The "this is how mature ecosystems ended up" argument |

**ContextLock's specific claim:** the vendor-neutral spec and reference implementation for the *whole instruction-file layer* - not just marketplace skills but CLAUDE.md, rules, prompt packs, and agent configs - with a local-seal mode nobody else offers (nono has no TOFU; NVIDIA and SkillSeal are publisher-side only), enforcement mappings for real host tools, and a format built from DSSE + a minimal TUF subset so Sigstore bundles and in-toto statements are a compatible upgrade rather than a rewrite. The proposal to agentskills.io (whose spec is silent on integrity) is the standardization endgame.

## 12. Naming risk (decision needed before anything ships publicly)

Research verdict: **CONFLICTED, mitigated by owned assets.**

- npm `contextlock` was published **2026-07-13** (the day before this spec) by an unrelated author: "local-first MCP safety layer" - the same problem space. The unscoped npm name is gone.
- A Dec 2025 Zero2One whitepaper claims "Context Lock" for essentially this exact mechanism.
- Domains: **Mind Model AI owns contextlock.net** (project home). contextlock.dev/.io/.ai/.com are taken or parked by others; contextlock.org appeared unregistered at research time.
- Security audiences may hear a ransomware echo in "-Lock" (ESET's "PromptLock", Aug 2025).

Working decision: **keep the name**, anchored on contextlock.net and `@contextlock/*` scoped npm packages, with a disambiguation note in the README (this project is not the unscoped npm `contextlock` MCP tool, and predates awareness of the Zero2One whitepaper). Remaining prerequisites before public launch: trademark search (USPTO/CIPO), and consider also registering contextlock.org defensively.

## 13. Migration map: v2 spec vs the implemented v1 code

| v2 change | v1 code affected | Nature |
|-----------|-----------------|--------|
| Exact-byte hashing; sign-time normalization | `core/canonicalize.ts`, callers in `engine.ts`, `cli-publisher` | Move canonicalize into publisher/seal write path; verifier hashes raw bytes; keep normalized-hash diagnostic |
| DSSE envelope | `core/manifest.ts` (`DetachedSignature`), `core/signature.ts`, `cli-publisher/sign-manifest.ts` | Replace `tcv-signature/v1` with DSSE + PAE; single `contextlock.dsse.json`; verify-then-parse payload bytes |
| Manifest `contextlock/2` | `core/manifest.ts` schema + validation | Add `version` (int), require `expires_at`, add `length` enforcement, path traversal/duplicate/absolute rejection, `lints` |
| Bounded manifest discovery | `engine.ts` `locateManifestDir` | Stop at workspace boundary; first-found shadows; containment check |
| Anti-rollback state | new `core/state.ts` | Highest-version-seen per (package, key); reset on rotation |
| Mode 0 seal | new `core/seal.ts`, CLI commands | New; signs seal store with machine-local key |
| Trust store hardening | `core/trust-store.ts`, CLI init | Move default location to `~/.contextlock/`, sign store, ACLs on init, corrupt-store fails loud |
| Root file + rotation | new `core/root.ts` | New, minimal chained root |
| Real Claude Code plugin | `adapter-claude-code/*` | Replace uncalled class with plugin package (hooks.json + CLI shim); keep the engine API it wraps |
| Policy rules | `core/policy.ts` | Extend matrix engine with rule matching + layering; matrix survives as defaults |
| Content lints | new `core/lints.ts`, `cli-publisher` | New |
| Rename "filename hash mode" to "change hints" | `core/filename-hash.ts`, README, CLI copy | Copy/positioning only; code survives |

Everything not listed (hashing primitives, Ed25519 via noble, trust-store CRUD, policy matrix, property-test harness) carries forward. The 19 correctness properties in `.kiro/specs/contextlock/design.md` remain valid except Properties 1-2 (canonicalization), which move to the publisher/seal side, and gain new siblings: seal round-trip, rollback rejection, PAE vector conformance, path-abuse rejection, policy layering monotonicity ("lower layers only tighten").

## 14. Roadmap

**Phase A - Local Seal + real enforcement (the credibility release). SHIPPED 2026-07-15.**
Mode 0 end to end: seal store, machine-local key, `seal/reseal/status/sweep`, the actual Claude Code plugin (hooks.json, deny-rule templates, managed template), exact-byte hashing migration, trust-store hardening, U1-U4 empirical results published. Acceptance: the demo where an "injected" agent appends a line to CLAUDE.md and the next session blocks, quarantines, and reports it. (Passed live.)

**Phase B - Signed manifests v2. SHIPPED 2026-07-15.**
DSSE envelope, `contextlock/2` manifest, anti-rollback state, root/rotation, content lints, publisher CLI updates, `contextlock install`. Acceptance: v1's five MVP criteria re-run on the v2 format (`tests/integration/mvp-v2.test.ts`), plus rollback, manifest-stripping, mix-and-match, cross-package, sidecar-differential, and keyid-spoofing red-team tests (`tests/integration/redteam-v2.test.ts`).

**Phase C - Ecosystem profiles. SHIPPED 2026-07-15 (with two explicitly open validation items).**
Sigstore Profile B (bundle verification against pinned trusted root), OpenClaw adapter (highest urgency given ClawHavoc), reviewer multi-signatures, CI signing recipes (GitHub Actions). Implementation notes:

- Profile B: offline verification of `contextlock.sigstore.json` bundles via the official sigstore-js libraries against a pinned `trusted_root.json` shipped at `packages/core/assets/`; identity policy = pinned (certificate-identity glob, exact issuer) pairs (`contextlock trust identity add`); anti-rollback keyed by sha256(issuer, SAN). Tested against a REAL npm-provenance bundle (production trusted root, full thresholds) and a SYNTHETIC contextlock-manifest bundle generated with @sigstore/mock (mock Fulcio CA + CT log + RFC3161 TSA, `tlogThreshold: 0`; regenerate with `scripts/generate-sigstore-fixture.mjs`).
- Reviewer multi-signatures: `contextlock-publisher countersign` appends a signature over the exact payload bytes; verification collects every distinct trusted key; `requiredSigners` / `verify --min-signers N` enforces the threshold. Rollback state is checked and recorded against EVERY verified signer.
- OpenClaw adapter: Layer 1 = `security.installPolicy` gate, Layer 2 = `before_agent_run` hard block, Layer 3 = `before_tool_call` write/read deny; there is NO verify-before-context-injection hook in OpenClaw, and no managed tier (openclaw.json itself joins the sealed set). Full surface mapping: `docs/openclaw-surface.md`.
- OPEN validation items: (1) OpenClaw hook payload field names and the installPolicy stdin/stdout schema need live-gateway verification; (2) the Profile B keyless-signing recipe (`recipes/github-actions/`) follows the sigstore-js API but has not been executed with real OIDC.

**Phase D - Standardization.**
Integrity-extension proposal to the agentskills.io spec; interop tests against nono's attestation format; transparency-log / timestamp exploration (the honest fix for 6.4); upstream conversations about signed plugins in host tools.

## 15. Open questions

Carried forward, now with owners in the process rather than rhetorical status:

1. ~~U1-U4~~ Resolved 2026-07-14 (section 7.4, `docs/claude-code-surface.md`). Follow-up: remote-source marketplace cache behavior; re-run the surface tests per Claude Code release.
2. ~~Keep or rename~~ Resolved: keep (section 12); trademark search still outstanding.
3. ~~Sign in-toto Statements vs bare manifest payload~~ Resolved in Phase B (2026-07-15): **bare manifest payload** with the dedicated payloadType, as normatively specified in 6.2/6.3. Rationale: (a) an in-toto Statement duplicates the file list in `subject`, creating a second authority that must be cross-validated against the predicate - new attack surface for zero security gain; (b) the DSSE payloadType makes the formats cleanly distinguishable, so a Statement profile can be ADDED later without breaking existing verifiers (old verifiers reject the unknown payloadType loudly, never silently); (c) the natural home for Statement interop is Phase C's Sigstore Profile B, where bundles carry Statements natively and nono compatibility can be tested against a real counterparty rather than guessed at. This resolution reverses the earlier "leaning Statement" note - revisit at Phase C with concrete nono interop tests.
4. Quarantine UX: move-aside + placeholder vs rename-in-place - Phase A usability test.
5. Seal-store scaling (JSON vs SQLite) once seals exceed ~10^3 files - defer until real.
6. Phase C follow-ups (2026-07-15): live-gateway verification of the OpenClaw hook payloads and installPolicy schema; CI execution of the Profile B keyless recipe; OpenClaw plugin packaging + distribution (bootstrap question, 7.3 applies); trusted-root update cadence for the shipped Sigstore root (currently a pinned snapshot - releases must refresh it, and a TUF-updater integration is the honest long-term fix, pairs with the 6.4 transparency-log work).

---

*This specification is provenance, not safety: a signature proves authorship, not that content is benign (OWASP AST01). Every guarantee above is scoped by the threat model in section 4, including the ones it declines to make.*
