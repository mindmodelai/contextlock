# Transparency log / timestamp exploration

**Status:** design exploration (SPEC v2 Phase D; the honest fix for SPEC 6.4).
**Date:** 2026-07-15. No implementation in this phase; the recommendation at
the end is scoped for a future phase.

## 1. The residual gaps this addresses

SPEC 6.4 is deliberately honest: without an external time source,
`expires_at` bounds staleness only to the publisher's re-signing cadence.
Three residuals remain after Phases A-C:

| Gap | Scenario | Current state |
|-----|----------|---------------|
| **Unproven signing time** (Profile A) | `published_at` is a claimed field inside the signed payload; a compromised key can back-date | Profile B gets real timestamps for free (Rekor integrated time / TSA); Profile A has nothing |
| **First-contact rollback** (T7 residual) | Anti-rollback state is highest-version-SEEN. A victim who never saw v5 can be served the vulnerable v4 forever | Local state helps only after first contact with the newer version |
| **Freeze inside the validity window** (T8 residual) | A mirror withholding v5 while serving still-unexpired v4 is undetectable | `expires_at` bounds this to the validity window, nothing tighter |

A fourth, related property - **equivocation detection** (serving different
"v5" bytes to different victims under the same version number) - is only
addressable with a public log.

## 2. Options

### Option 1 - RFC3161 TSA countersignature for Profile A

At sign time, request a timestamp token over the DSSE signature bytes from a
public TSA (FreeTSA, DigiCert, Sigstore's TSA). Verifiers check the token
offline against a pinned TSA cert chain.

- **Proves:** signed-no-later-than T (kills back-dating; strengthens expiry
  reasoning: `published_at` becomes evidence, not a claim).
- **Does not prove:** freshness, non-freeze, non-equivocation.
- **Cost:** one HTTP round-trip at sign time; verification is offline. The
  verification machinery already exists in this codebase - the Profile B
  path verifies RFC3161 tokens via `@sigstore/core` today, and the synthetic
  test fixture is TSA-anchored.
- **Carrier question:** the bare DSSE envelope has no standard timestamp
  slot. See "carrier convergence" below.

### Option 2 - Rekor transparency log for Profile A envelopes

Publishers log the DSSE envelope to the public Rekor instance at publish
time (Rekor accepts `dsse`/`intoto` entry kinds) and ship the inclusion
proof with the package. Verifiers check the proof offline - this is exactly
what Profile B bundles already carry.

- **Proves:** signed-no-later-than (integrated time) AND public existence:
  anyone can monitor the log for a package's version stream.
- **Enables (with monitoring):** equivocation and freeze *detection* - a
  monitor that watches "package X by key K" sees every published version, so
  serving an old version to newcomers becomes detectable by third parties,
  which is the strongest property available without an online check.
- **Does not prove by itself:** the verifier still can't tell locally that a
  NEWER version exists (that needs a monitor or an online query; split-view
  attacks against the log itself need witnessing/gossip - Rekor's ecosystem
  problem, not ours).
- **Cost:** network at sign time; ~1KB proof shipped; verification offline.
  Free auditing infrastructure that already exists and that Profile B users
  already depend on.

### Option 3 - TUF-style timestamp role (freshness tokens)

The publisher (or a registry) signs a tiny `{package, latest_version,
generated_at}` statement on a short cadence with an online key; verifiers
reject when the token is older than a freshness window.

- **Proves:** freshness and latest-version (actually fixes T7-first-contact
  and T8 within the window).
- **Cost:** the exact costs SPEC 6.5 rejected for now - an online signing
  key, publisher availability requirements, and effectively a server. This
  is the TUF snapshot/timestamp design we deliberately excluded "without a
  repository server". Revisit trigger: a ContextLock registry or an
  agentskills.io-blessed skill registry existing at all.

### Option 4 - Dedicated ContextLock log + witness network

A purpose-built transparency log for instruction-file manifests with witness
co-signing (sumdb/armored-witness style).

- Strictly dominates Option 2 on paper; wildly disproportionate to the
  project's adoption stage. Not further considered; recorded so the
  reasoning isn't re-litigated from scratch later.

## 3. Carrier convergence (the design insight worth keeping)

Options 1 and 2 both need somewhere to PUT timestamps/proofs. Inventing
sidecar files (`contextlock.tsr`, `contextlock.rekor.json`) grows bespoke
surface. The Sigstore **bundle** format already carries all of it:
`verificationMaterial.timestampVerificationData.rfc3161Timestamps`,
`verificationMaterial.tlogEntries`, and - crucially - it supports
**public-key verification material** (`publicKey` hint), not just
certificates.

So the convergence path is: **when a Profile A publisher opts into
timestamps or Rekor logging, the evidence file becomes a Sigstore bundle
whose DSSE envelope is signed by the publisher's raw Ed25519 key** (keyid
hint -> trust-store lookup, exactly today's resolution), with the timestamp/
proof in the bundle's standard slots. `@sigstore/verify` supports this
today (`toTrustMaterial(root, keys)` second parameter), and ContextLock
already ships the bundle-verification path. One format, three evidence
levels: bare envelope (today) < +TSA < +Rekor.

## 4. Recommendation

1. **Adopt Option 1 + 2 via the bundle carrier, publisher-opt-in, in a
   future phase** (Phase E candidate): `sign-manifest --timestamp[-url]` and
   `--rekor` flags on the publisher CLI; verifier prefers bundle evidence
   when present and surfaces "signed at T (TSA/Rekor-proven)" in results.
   Policy knob: `require_timestamp: true` per publisher for high-assurance
   setups.
2. **Do not build Option 3** until a registry exists; note the revisit
   trigger in SPEC 15.
3. **Spec change when implemented:** SPEC 6.4 drops the "no online timestamp
   service" framing in favor of "timestamps are opt-in evidence carried in
   the bundle; expires_at remains the floor".
4. **What stays honest:** even with 1+2, a local verifier cannot prove
   "nothing newer exists" - only monitors can. Any future wording must keep
   that distinction (detection by third parties, not prevention at the
   verifier).
