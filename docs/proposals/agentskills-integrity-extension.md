# Agent Skills integrity extension - proposal draft

**Status: SUBMITTED 2026-07-16.**
Posted into discussion #393: https://github.com/agentskills/agentskills/discussions/393#discussioncomment-17656138
Companion comment on PR #254: https://github.com/agentskills/agentskills/pull/254#issuecomment-4987831141
(The submitted text was this draft adapted with live repo/npm links. Research
basis: agentskills.io spec + repo ground truth, 2026-07-15 - 44 adopting
clients; spec silent on integrity; three prior integrity RFCs closed or
converted to discussions.)

## How to submit (this matters more than the content)

The repo's change process and enforcement history dictate the form:

1. **Do NOT open a new issue or spec PR.** CONTRIBUTING.md routes proposals
   to Discussions; all three prior integrity issues (#247, #358, #418) were
   closed or converted. Community-authored normative PRs do not merge - the
   only substantive spec expansion in flight (PR #254, `.well-known` URI) is
   maintainer-authored.
2. **Post into the EXISTING discussion #393** ("optional provenance
   attestation fields") as a concrete, implemented instantiation - it is the
   closest design (sidecar + directory digest) and is open and unresolved.
   Read #393 and #252 in full first (the research summarized them; the post
   must respond to their actual points). Also check Agent-Card/ai-catalog
   first - the maintainer points people there.
3. **Follow up with a comment on PR #254** showing how a DSSE attestation
   composes with its per-artifact `digest` field (attestation rides the
   distribution index).
4. Maintainer constraints to respect verbatim (from jonathanhefner's own
   comments): verification belongs at the **distribution layer**, signatures
   must **cover all bundled files including frontmatter** (the description is
   itself a prompt-injection surface), and integrity / attestation /
   "safe-to-run" are **three separate concerns** - the spec will never take
   the third.
5. The realistic ask is NOT a frontmatter change: it is (a) an optional
   companion/extension document (the `.well-known` page is the precedent for
   optional spec surface), (b) a reserved sidecar filename convention, and
   (c) a Security Considerations cross-reference. The stated bar for even a
   "best practice" mention is community adoption and battle testing - which
   means shipping first and proposing second.
6. If any text is PR'd: the repo requires disclosure of AI assistance.
7. Do not add a top-level frontmatter key in any variant: the reference
   validator (`skills-ref` `ALLOWED_FIELDS`) hard-rejects unknown fields.
   The sanctioned pointer location is the `metadata` map (string keys and
   values, "reasonably unique" names).

---

## Draft post for discussion #393

> ### A shipped instantiation: DSSE attestation sidecar, verified at the distribution layer
>
> We have been building exactly the layer this discussion describes and have
> it working end to end, so I want to offer it as concrete input - both the
> format choices and what we learned implementing them. (Naming/links
> withheld until public release; happy to share the verifier and test suite.)
>
> **Shape.** One sidecar file per skill directory, next to SKILL.md:
> a [DSSE](https://github.com/secure-systems-lab/dsse) envelope whose payload
> is a manifest covering **every file in the skill, SKILL.md and its
> frontmatter included** - per-file `sha256` + byte `length`, publisher
> identity, a monotonic integer `version` for anti-rollback, and a required
> `expires_at`. This is deliberately spec-conformant *today*: the layout
> already permits "any additional files or directories", the sidecar costs
> zero context tokens under progressive disclosure, and clients that don't
> know about it lose nothing. An optional pointer can ride the `metadata`
> map; no new top-level frontmatter field is needed (and the reference
> validator would reject one).
>
> **Why an envelope rather than a signature field.** Three properties fell
> out of implementation experience rather than theory:
> 1. *Frontmatter coverage.* A signature inside the frontmatter cannot cover
>    the frontmatter (the circularity @jonathanhefner raised in #252, and the
>    description IS injectable surface). A sidecar over exact file bytes
>    covers everything, trivially.
> 2. *Cross-protocol safety.* DSSE's PAE binds the payload type into the
>    signature, so a skill attestation cannot be replayed as some other kind
>    of signed document. This closed a real attack in our red-team tests.
> 3. *Key-model neutrality.* The same envelope verifies with raw pinned
>    Ed25519 keys (solo authors, fully offline - the OWASP AST01 ask) and,
>    wrapped in a Sigstore bundle, with keyless CI identities
>    (`certificate-identity` + `certificate-oidc-issuer`, the model npm
>    provenance already taught this ecosystem). Reviewer countersignatures
>    are native (multiple signatures per envelope).
>
> **Where it verifies.** At the distribution layer, agreeing with the
> maintainer position: install-time verification before files land, plus
> re-verification sweeps by local tooling. Nothing about this needs loader
> or spec changes, and "verified" here means *authentic and unmodified*,
> never *safe* - integrity and attestation only; scanning stays a separate,
> composable layer.
>
> **Digest bridging.** On the #358 directory-digest vs #254 artifact-digest
> question: we found per-file digests (not one directory digest) worth the
> verbosity - they localize failures ("RULES.md modified" beats "tree hash
> mismatch"), enforce length-before-hash cheaply, and compose with #254
> unchanged: the `.well-known` index's `digest` covers the shipped archive,
> and the in-archive envelope covers the files after extraction. The two
> mechanisms are complementary layers (transport integrity vs content
> provenance), not competitors.
>
> **Anti-rollback and lock files (#46).** A monotonic integer version in the
> signed manifest plus verifier-side highest-seen state rejects replay of an
> older signed release. This slots into the lock-file direction naturally: a
> lock entry can pin `(publisher key/identity, version, envelope digest)`
> across GitHub / `.well-known` / OCI distribution alike.
>
> **Concrete asks**, all optional-surface:
> 1. Reserve a conventional sidecar filename for integrity attestations (we
>    use one name; any agreed name works - what matters is that registries
>    and CLIs can find it).
> 2. An optional companion document (same status as the `.well-known` page)
>    describing the envelope + manifest shape, so implementations converge
>    instead of inventing N formats - #252, #393, vercel-labs/skills#617,
>    and the OCI/cosign track (#292) are four parallel inventions today.
> 3. A sentence in the client guide's Trust considerations pointing to it.
>
> We'll publish the verifier, red-team suite (rollback, manifest stripping,
> mix-and-match, cross-package confusion), and CI signing recipes; happy to
> run interop tests against `@agentlair/spa-verifier` and the OCI track.

---

## Appendix: companion-document skeleton (if the maintainer invites spec text)

Title: "Skill integrity attestations (optional)". Sections: sidecar filename
and discovery; DSSE envelope requirements (alg set, PAE, payloadType);
manifest payload schema (per-file sha256+length, publisher, monotonic
version, expires_at; unknown-field tolerance); verification requirements
(exact-byte hashing, fail-loud on stripped sidecars for opted-in clients);
key models (raw Ed25519 pinning; Sigstore keyless identity pinning);
Security Considerations (provenance is not safety; frontmatter coverage;
rollback; expiry cadence); relationship to `.well-known` digests and lock
files. Base it on SPEC.md sections 6.1-6.7 stripped of ContextLock-specific
CLI/product references.
