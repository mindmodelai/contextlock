# Contributing

Thanks for your interest. Ground rules that keep this project reviewable:

## Before you start

- **SPEC.md is authoritative.** Behavior changes need a spec change first (or
  in the same PR). If the code and SPEC.md disagree, that is a bug in one of
  them - say which.
- Security-relevant design changes should engage the threat model (SPEC.md
  section 4): say which threats (T1-T14) your change affects and how.
- For vulnerabilities, see [SECURITY.md](./SECURITY.md) - do not open public
  issues.

## Development

```bash
git clone <repo> && cd contextlock
npm install
npm test          # vitest, all packages
npm run build     # tsc project references
```

- Node >= 22. Plain npm workspaces - no pnpm/yarn-specific syntax.
- Tests are the contract: red-team tests (`tests/integration/redteam-*.test.ts`)
  and property tests must stay green; a PR that weakens a red-team test needs
  an explicit justification in its description.
- Signed fixtures under `tests/fixtures/` are byte-exact (hash-attested);
  `.gitattributes` protects them from EOL conversion - do not "fix" their
  line endings. Regeneration scripts live in `scripts/`.
- Exact-byte hashing is a design invariant (SPEC.md 6.1): normalization
  happens at SIGN time only, never at verify time.

## Pull requests

- Keep PRs scoped to one concern; reference the SPEC section they implement.
- Disclose AI assistance in the PR description (we do the same).
- New wire-format surface (fields, files, statuses) needs: spec text,
  validation with hard failures, tests including at least one adversarial
  case, and forward-compatibility reasoning (unknown-field behavior).
