# nono interop

**Status:** read-compat implemented and tested (Phase D, 2026-07-15).
**Counterparty:** nono (github.com/nolabs-ai/nono, Luke Hinds - Sigstore's
creator; formerly lukehinds/nono then always-further/nono). Rust, Apache-2.0,
v0.68.0 era, actively maintained, pre-1.0 (format still churning: the
trust-policy `version` field was deprecated in 0.66.0; org/branding renamed
twice). SPEC 11 names it the closest prior art with an "align, don't
compete" posture - this document is that alignment, made concrete.

All wire-format facts below were confirmed from nono's source on 2026-07-15
(`crates/nono/src/trust/{dsse,signing,bundle,types}.rs`,
`crates/nono-cli/src/{trust_cmd,trust_scan}.rs`, docs at nono.sh).

## 1. Format comparison

| | nono | ContextLock |
|---|---|---|
| Outer carrier | Sigstore bundle v0.3 (always, both key modes) | bare DSSE envelope (Profile A) or Sigstore bundle (Profile B) |
| DSSE payloadType | `application/vnd.in-toto+json` (hard-enforced) | `application/vnd.contextlock.manifest+json` (hard-enforced) |
| Payload | in-toto Statement v1; predicateType `https://nono.sh/attestation/{instruction-file\|multi-file\|trust-policy}/v1` | contextlock/2 manifest |
| File binding | Statement subjects: `{name, digest.sha256}`; basename (single-file) or scan-root-relative (multi-file); max 1,000 | manifest `files`: `{path, sha256, length}`; max 4,096 |
| Sidecar names | `<file>.bundle` (per file), `.nono-trust.bundle` (multi-file - the skill shape) | `contextlock.dsse.json`, `contextlock.sigstore.json` |
| Keyed mode | ECDSA **P-256 only**, key in OS keychain, pubkey pinned in trust-policy.json; bundle carries `publicKey.hint`, no tlog | raw **Ed25519**, pinned in truststore; optional roots for rotation |
| Keyless mode | Fulcio + Rekor (CI-only, GitHub/GitLab ambient OIDC); identity from cert OIDs | same machinery (Profile B); identity pins = (SAN glob, exact issuer) |
| Anti-rollback | none in the format (registry pull pins signer identity in a lockfile) | monotonic `version` + signed local highest-seen state (T7) |
| Expiry / freshness | none in the format | required `expires_at` (T8) |
| Length enforcement | none | per-file `length` before hashing |
| Policy | trust-policy.json (itself signed; includes globs, publisher matching keyed `key_id` / keyless issuer-exact + repo/workflow/ref wildcards, digest blocklist, enforcement deny/warn/audit) | truststore (signed local state) + policy levels |
| Enforcement point | pre-exec scan + Linux runtime `openat` interception (sandbox-coupled) | host-tool hooks (Claude Code plugin, OpenClaw adapter) + install gate + sweeps |

## 2. What interops TODAY (implemented)

**ContextLock consumes nono keyless skill attestations.** `verifyNonoBundle`
(`core/src/intoto.ts`) runs the same offline Sigstore verification and
identity pinning as Profile B, then parses the in-toto Statement with nono's
predicateType allowlist and subject path-safety rules (no absolute paths, no
`..` - mirroring nono's own verifier), yielding per-file `(path, sha256)`
entries. Tested against a byte-shape-accurate fixture
(`tests/fixtures/sigstore/nono-pkg/.nono-trust.bundle`, regenerable via
`scripts/generate-nono-fixture.mjs`) plus negative tests: tampered payloads,
unpinned signers, foreign predicateTypes (a real SLSA provenance statement is
rejected), and the payloadType gates in both directions.

**Reduced guarantees, stated loudly.** The nono format carries no monotonic
version, no expiry, and no byte length, so consuming it gives authenticity +
integrity only - no anti-rollback (T7), no freeze defense (T8), no
length-before-hash. Every successful `verifyNonoBundle` result carries a
warning saying exactly that. This is why the result is a distinct API and is
NOT wired into the engine's `trusted` verdict path: `trusted` means the full
contextlock/2 guarantee set, and a reduced-evidence source must not wear
that badge silently. (Engine integration as an explicit lower tier - e.g. a
`attested` status - is a product decision deferred to a future phase.)

## 3. What does NOT interop, and why

**ContextLock consuming nono KEYED bundles: not implemented.** Two gaps:
(1) nono's keyed mode is ECDSA P-256 only, and ContextLock's key plumbing is
Ed25519-only by design (SPEC 6.6: no algorithm agility); (2) keyed bundles
carry `publicKey.hint` verification material, which needs the
`toTrustMaterial(root, keys)` key-map path we don't currently populate.
Both are tractable; neither is justified before a real demand signal.

**nono consuming ContextLock attestations: impossible today.** Four
independent hard gates in their verifier: sidecar discovery only finds
`<file>.bundle` / `.nono-trust.bundle`; the sidecar must parse as a Sigstore
bundle; `extract_statement` rejects any payloadType except in-toto; the
predicateType must be one of their three URIs. There is no extension point
for foreign payload types. Realistic paths, in order:

1. **nono-native emission target** (Phase E candidate): a
   `contextlock-publisher` flag that ALSO writes a `.nono-trust.bundle` in
   their exact shape next to our artifact - the filenames don't collide, so
   dual attestation coexists cleanly. Keyless works with today's machinery;
   keyed would require a P-256 signing option first.
2. **Upstream PR** for a pluggable predicateType (their predicate is already
   an opaque JSON value, so the change is contained) - worth raising in the
   alignment conversation, not worth blocking on.

## 4. OQ3 revisited (the Phase B decision, now with interop facts)

SPEC 15 OQ3 chose a bare contextlock/2 payload over an in-toto Statement,
deferring the Statement question to "concrete nono interop tests". Those
tests now exist, and the decision is **reaffirmed**:

- Unifying on in-toto Statements would NOT have bought interop: nono's
  verifier also rejects foreign predicateTypes, so a
  Statement-with-ContextLock-predicate fails their gate exactly like a bare
  manifest does. Interop lives at the **emission** layer (write their shape
  next to ours), not the payload layer.
- The guarantee gap runs the other way too: Statements cannot carry our
  rollback/expiry/length semantics in `subject`, so a Statement-based
  ContextLock would have needed all the load-bearing fields in the predicate
  anyway - the wrapper would be pure ceremony, plus a second file-list
  authority to cross-validate (the original OQ3 objection).
- Meanwhile READ-compat (this phase) gets full ecosystem reach: the same
  ~200-line module consumes any sha256-subject Statement, nono's included.

## 5. Follow-ups

1. ~~Capture a golden vector from a real nono run~~ **Done 2026-07-15**: ran
   `nolabs-ai/agent-sign@v0.1.0` in a live GitHub Actions workflow; the
   resulting bundle (real Fulcio cert + Rekor entry) is vendored at
   `tests/fixtures/sigstore/nono-real-pkg/.nono-trust.bundle` and verifies
   through `verifyNonoBundle` at FULL default thresholds
   (`packages/core/src/ci-golden.test.ts`). The wire shape matched this
   document exactly. Bonus finding for the alignment conversation: agent-sign
   v0.1.0's artifact-upload path is broken for its own default output - the
   `./**/*.bundle` glob misses the hidden `.nono-trust.bundle` file
   ("No files were found with the provided path"), so `upload-artifacts:
   true` uploads nothing in multi-subject mode; only the commit path works.
   Worth reporting upstream when going public.
2. Track nono's pre-1.0 churn before investing in emission: predicate/policy
   fields moved as recently as 0.66.0, and the org renamed twice.
3. The alignment conversation with the nono project (sharing this mapping,
   the pluggable-predicateType idea, and the agent-sign bug above) is a
   go-public act - same gate as the proposals in `docs/proposals/`.
4. Decide the engine-tier question (an explicit reduced-guarantee status)
   only if/when users actually hold nono-attested skills.
