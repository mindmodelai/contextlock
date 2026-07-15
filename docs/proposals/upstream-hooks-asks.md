# Upstream asks: verification hooks in host tools

**Status: DRAFT - NOT FILED.** Ready-to-adapt issue text for upstream
conversations (SPEC v2 Phase D). Filing these is a go-public act: it reveals
the project and its design. Do not file before the naming/trademark
prerequisites (SPEC 12) are closed and Sam signs off.

Each ask is grounded in the empirical surface docs
(`claude-code-surface.md`, `openclaw-surface.md`) - the asks are precisely
the gaps those documents proved exist. They are written vendor-neutrally
(the ask is a verification *interface*, not ContextLock adoption).

---

## Ask 1 - Claude Code: a blocking before-context-load hook

**To:** anthropics/claude-code (issue)
**Gap (empirical, vs 2.1.210):** `SessionStart` runs before the root
CLAUDE.md is ingested (favorable but undocumented ordering, U1) and cannot
block; nested CLAUDE.md files load lazily with NO hook; SKILL.md bodies load
harness-internally and only the whole `Skill` invocation can be denied (U2).
There is no point where a policy can verify instruction-file CONTENT before
it enters model context.

**Proposed interface (minimal):** a `PreContextLoad` hook event, fired
before any instruction-class file (CLAUDE.md, SKILL.md, rules, agent/plugin
configs) is added to context, with the file path + content hash in the
payload and `permissionDecision: "deny"` semantics identical to PreToolUse.
A stable ordering guarantee for `SessionStart` (documented "runs before
initial context ingestion") would be a meaningful subset on its own.

**Fallbacks we use today (works, but weaker):** install/write-time
verification + SessionStart sweep with quarantine + PreToolUse(Skill/Read/
Edit/Write) denials + managed-settings anchoring. The hook would close the
lazy-nested-CLAUDE.md gap that none of these cover at load time.

## Ask 2 - Claude Code: signed plugins / marketplace content verification

**To:** anthropics/claude-code (issue)
**Gap (empirical, U4):** installed plugin cache content is never
re-validated, and local-source marketplaces bypass the cache entirely
(served live from the source dir). Marketplace entries pin git SHAs at best.
CLAUDE.md/skills/rules have no signing or install-time validation hook
anywhere in the pipeline.

**Proposed interface:** (a) an install-time verification hook (the exact
shape OpenClaw already ships as `security.installPolicy`: operator command,
staged-content path in, allow/block out, fail closed); (b) longer term,
DSSE-signed plugin/skill artifacts with client-side signature verification -
the OWASP AST01 recommendation verbatim. Precedent to cite: VS Code
Marketplace extension signing, npm provenance.

## Ask 3 - OpenClaw: skill/workspace load gate (RFC #10890 follow-up)

**To:** openclaw/openclaw (comment on closed RFC #10890 or fresh issue)
**Gap (confirmed from docs, 2026.7.1):** `security.installPolicy` and the
blocking plugin hooks (`before_tool_call`, `before_agent_run`) are strong,
but nothing gates workspace-file or skill-snapshot compilation into the
system prompt, and `skills.load.watch` hot-reloads changed SKILL.md into the
next turn - so content that passed install-time review can be swapped before
injection with no check.

**Proposed interface:** a blocking `before_skill_load` /
`before_workspace_inject` plugin hook carrying `{path, sha256}` per file
with block semantics matching `before_tool_call`. Alternative smaller ask:
document whether `before_prompt_build`'s payload exposes the composed system
prompt per-source, which would let plugins approximate this today.

**Positioning note:** RFC #10890 proposed full signing infrastructure and
closed. The load-gate hook is deliberately smaller - it enables EXTERNAL
integrity tooling without OpenClaw building any crypto, which is the lesson
from `security.installPolicy`'s design.

## Ask 4 - OpenClaw: managed / non-hot-reloadable policy tier

**To:** openclaw/openclaw (issue)
**Gap:** `openclaw.json` hot-reloads and controls `tools.allow/deny`,
`plugins.*`, sandbox mode, and `security.installPolicy` itself - so any
config write (the CVE-2026-25253 class) disables every protection layer,
and there is no equivalent of Claude Code's managed-settings tier.

**Proposed interface:** an admin-owned config layer (separate file with OS
admin ACLs, or a `--locked-config` flag) whose hook registrations, deny
rules, and installPolicy setting cannot be overridden by the user-level
`openclaw.json`. Cite Claude Code `managed-settings.json` +
`allowManagedPermissionRulesOnly` as prior art.

---

## Sequencing recommendation

File Ask 3 first (OpenClaw, smallest, clear post-ClawHavoc motivation,
concrete CVE citations), then Ask 1 (Claude Code hook - the U1-U4 evidence
pack makes it unusually well-grounded for an external issue), then 2 and 4.
Each issue should link a public write-up of the corresponding surface doc
once the repo is public - the empirical method is the credibility.
