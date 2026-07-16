# ContextLock CI recipes

Signing recipes for publishing verified instruction-file packages from CI
(SPEC v2 Phase C). Two profiles:

| | Profile A (raw Ed25519) | Profile B (Sigstore keyless) |
|---|---|---|
| Recipe | `github-actions/sign-profile-a.yml` | `github-actions/sign-profile-b.yml` + `keyless-sign.mjs` |
| Key management | repo secret holds the private key | none - the workflow OIDC identity signs |
| What users pin | your public key (`trust add`) | your workflow identity (`trust identity add`) |
| Verification | offline | offline (against the pinned Sigstore trusted root) |
| Signing | offline-capable | requires Fulcio/Rekor network |
| Evidence file | `contextlock.dsse.json` | `contextlock.sigstore.json` |

## Shared guidance

- **Monotonic version**: use `github.run_number` for `--version` - the
  anti-rollback counter must strictly increase; put the human version in
  `--display-version`.
- **`.gitattributes`**: commit `*.md text eol=lf` in the signed package
  directory so checkouts do not undo sign-time LF normalization (SPEC v2 6.1).
- **Content lints**: `build-manifest`/`protect` BLOCK on Unicode Tag,
  zero-width, and bidi-control characters. If a hit is intentional, add
  `--allow-lint <rule>` - the exception is recorded in the manifest for
  verifiers to see. Do not blanket-allow.
- **Expiry cadence**: `--expires-days 365` means you must re-sign (re-release)
  at least yearly; shorter is stronger (SPEC v2 6.4).
- **Verify-on-PR gate**: run `contextlock-publisher verify ./package-dir` in a
  PR check so tampered or lint-failing content never reaches a release.

## Profile A notes

- Never commit `contextlock-private.key`. The recipe writes the secret to
  `/tmp` with `umask 077` and shreds it in an `always()` step.
- Publish the public key's fingerprint through a second channel (website,
  README) so users can check what they pin.
- Rotation: publish a `contextlock-root/1` file and rotate via
  `contextlock trust root update` (SPEC v2 6.5) instead of asking users to
  re-pin raw keys.

## Profile B notes

- The identity users pin is the **workflow ref**:
  `https://github.com/ORG/REPO/.github/workflows/FILE.yml@refs/heads/main`.
  Renaming the workflow file changes your identity - treat it like a key
  rotation and tell your users (glob pins like
  `https://github.com/ORG/REPO/**` trade precision for resilience).
- `keyless-sign.mjs` uses the `sigstore` npm package's `attest()` so the DSSE
  payloadType is exactly `application/vnd.contextlock.manifest+json`. Do NOT
  substitute `cosign attest-blob` (wraps payloads in an in-toto Statement) or
  `cosign sign-blob` (message signature, not DSSE) - ContextLock rejects both
  by design.
- **Status: CI-validated 2026-07-15.** Executed in a live GitHub Actions
  workflow; the produced bundle verifies offline at full default thresholds
  (real Rekor entry + SCT) against the shipped trusted root, and is vendored
  as a permanent golden-vector fixture
  (`tests/fixtures/sigstore/ci-real-pkg`, tests in
  `packages/core/src/ci-golden.test.ts`).
- **Privacy note:** keyless signing writes the signing repo/workflow identity
  into the PUBLIC, append-only Rekor log. Running the recipe from a private
  repo discloses that repo's name permanently - validate from a neutral repo
  if the project is not public yet.
