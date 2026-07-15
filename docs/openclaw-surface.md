# OpenClaw enforcement surface

**Researched:** 2026-07-15 against OpenClaw 2026.7.1 (docs.openclaw.ai; docs
source mirrored in the openclaw/openclaw repo). Companion to
`claude-code-surface.md`. Every claim is labeled **CONFIRMED** (official
docs/repo), **REPORTED** (third-party), or **UNKNOWN**. Unlike the Claude Code
surface doc, these mappings have **not yet been exercised against a live
OpenClaw gateway** - payload field names follow the docs and need live
verification before the plugin ships.

## 1. Instruction-file classes (CONFIRMED: docs.openclaw.ai/concepts/agent-workspace)

| File | Default path | Injected | Origin |
|------|--------------|----------|--------|
| SOUL.md | `~/.openclaw/workspace/SOUL.md` | every session, first | user-edited |
| AGENTS.md | `~/.openclaw/workspace/AGENTS.md` | every session | user-edited |
| USER.md | `~/.openclaw/workspace/USER.md` | every session | user-edited |
| IDENTITY.md | `~/.openclaw/workspace/IDENTITY.md` | every session | agent-written |
| TOOLS.md | `~/.openclaw/workspace/TOOLS.md` | every session (guidance only) | user-edited |
| HEARTBEAT.md / BOOT.md / BOOTSTRAP.md | same dir | heartbeat / startup runs | user-edited |
| MEMORY.md + `memory/YYYY-MM-DD.md` | same dir | long-term memory | agent-written |
| SKILL.md | six discovery locations, ≤6 levels deep | eligible skills compiled into system prompt | user or ClawHub |
| openclaw.json | `~/.openclaw/openclaw.json` | hot-reloaded config (JSON5) | user-edited |
| cron/jobs.json | `~/.openclaw/cron/` | scheduled prompts | user-edited |
| hooks/ | `~/.openclaw/hooks/`, `<ws>/hooks/` | HOOK.md + handler.ts run in-process | user-installed |

Multi-agent: `<state>/workspace-<agentId>`; profile variants
`~/.openclaw/workspace-<profile>`; env override `OPENCLAW_WORKSPACE_DIR`.
Workspace .md files are injected every session **with no integrity check**
(CONFIRMED absence in docs). Injection caps: 20k chars/file, 60k total.

**Config is attack surface** (the config-CVE class): `openclaw.json`
hot-reloads and controls `tools.allow/deny`, `plugins.*`, sandbox mode, and
`security.installPolicy` - a config write defeats every other layer.
CVE-2026-25253 (1-click RCE via Control UI `?gatewayUrl=` -> token exfil ->
config modification, fixed 2026.1.29, GHSA-g8p2-7wf7-98mq) is exactly this
class (CONFIRMED). ContextLock therefore treats `openclaw.json`,
`cron/jobs.json`, `hooks/**`, and plugin dirs as protected-class alongside
the .md files.

## 2. Skill installation and existing integrity measures

- Install: `openclaw skills install @owner/<slug>` (ClawHub), `git:`, local
  path; workspace `skills/` by default, `--global` -> `~/.openclaw/skills`.
  Separate `clawhub` CLI records versions in `.clawhub/lock.json` +
  `origin.json`. (CONFIRMED)
- **`security.installPolicy`** (CONFIRMED, docs/gateway/security): an
  operator-supplied local command runs after staging, before install, for
  ClawHub/git/local/uploaded skills, dependency installers, AND plugins.
  JSON in on stdin (`protocolVersion`, `targetType`, `targetName`,
  `sourcePath`), JSON allow/block out, **fails closed**, not bypassable by
  legacy unsafe flags. This is OpenClaw's only sanctioned operator gate.
- `openclaw skills verify` checks installed skills against the version and
  registry recorded at install; whether it compares full content hashes is
  UNKNOWN.
- ClawHub server-side: VirusTotal Code Insight scans on publish
  (CONFIRMED, official blog 2026-02-07). Detection, not provenance.
- **No cryptographic skill signing has shipped.** RFC #10890 ("Skill
  Security Framework": manifests, GPG signing, hash verification,
  sandboxing) is a closed proposal, not shipped (CONFIRMED). Third-party
  claims that ClawHub "requires code signing" are inaccurate (REPORTED,
  contradicted by official docs).
- ClawHavoc scale: 341 malicious skills named by Koi Security 2026-02-01,
  later tallies 824-1,184 across repos, AMOS stealer payloads (REPORTED:
  Koi, Unit42, TheHackerNews).
- Nearest ecosystem neighbors: prompt-security/clawsec (SOUL.md drift
  detection + skill integrity), ClawSecure, openclaw-security-monitor (all
  CONFIRMED to exist, efficacy unaudited). Post-ClawHavoc, security-themed
  skills were themselves an attack lure (REPORTED) - ContextLock ships as a
  plugin + CLI, not a skill.

## 3. Hook surface (two distinct systems)

**Plugin hooks - in-process, CAN block** (CONFIRMED,
docs.openclaw.ai/plugins/hooks). Registered via `api.on(name, handler)` from
a plugin (`openclaw.plugin.json`; configured under `plugins.entries.<id>`):

| Event | Can block? | ContextLock use |
|-------|-----------|------------------|
| `before_tool_call` | YES (`{block: true, blockReason}`; payload has `toolName`, `params`, `derivedPaths`) | Layer 3 write-deny + read-deny |
| `before_agent_run` | YES (`{outcome: "block", reason}`) | Layer 2 run gate on a swept workspace |
| `before_prompt_build` / `agent_turn_prepare` | modify only (prepend/append context, override systemPrompt) | status report injection; per-file coverage of payload UNKNOWN |
| `before_install` | YES, but runs after `security.installPolicy` and only in gateway-backed installs | secondary; prefer installPolicy |
| `before_message_write`, `message_sending`, `tool_result_persist` | modify/cancel | not used |
| `session_start/end`, `gateway_start/stop`, `llm_input/output`, `after_tool_call` | observe only | logging, watcher bootstrap |

**Automation hooks** (`~/.openclaw/hooks/` HOOK.md + handler.ts) are
**observe-only** - docs are explicit that they cannot block (CONFIRMED). They
are themselves an instruction-execution surface (a dropped handler.ts runs
in-process), so ContextLock protects those paths rather than building on
them.

**No hook gates workspace-file or skill-body compilation into the system
prompt** (CONFIRMED absence). `skills.load.watch` (default true) hot-reloads
changed SKILL.md into the next turn, so out-of-band sweeps race live pickup -
sweeps must pair with the tool-gate deny, not replace it.

## 4. ContextLock -> OpenClaw layer mapping (implemented in `@contextlock/adapter-openclaw`)

| ContextLock layer | OpenClaw mechanism | Status |
|-------------------|--------------------|--------|
| Layer 1 install-time verify | `security.installPolicy` -> `installPolicy()` (allow verified; block tampered/rollback; unsigned per policy level: strict blocks, balanced allows) | Implemented; payload field names need live verification |
| Layer 2 session sweep | `before_agent_run` -> `handleBeforeAgentRun()` (hard block on violations) | Implemented; stronger than Claude Code's non-blocking SessionStart |
| Layer 3 read/write deny | `before_tool_call` -> `handleBeforeToolCall()` (deny writes to sealed/trusted files; deny any tool touching policy-blocked files) | Implemented; write-tool detection is name-based (configurable) |
| Layer 4 managed policy | none - `openclaw.json` is user-writable and hot-reloaded | NOT available; mitigation: openclaw.json in the sealed set + `openclaw security audit --fix` file permissions |
| Verify-before-context-injection | none exists | NOT implementable today; documented honestly |

Honest boundary: on OpenClaw, "verified" means **verified at run start plus
write-denied at the tool gate**, not verified at prompt injection. A
same-privilege process outside the tool (or a config edit that disables the
plugin) defeats the plugin layers; the sealed set therefore includes
`openclaw.json` itself, and the bootstrap problem is the same one documented
for Claude Code (SPEC v2 7.3).

## 5. Open items before shipping the plugin

1. Live-verify hook payload field names (`derivedPaths`, `outcome` shape) and
   the exact `security.installPolicy` stdin/stdout schema against a running
   gateway.
2. Decide plugin packaging (`openclaw.plugin.json` + entry registering the
   two hooks) and ClawHub vs npm distribution - blocked on the bootstrap
   question (SPEC v2 7.3 applies verbatim).
3. Test `before_prompt_build` payload coverage: if the full composed system
   prompt is visible per-file, a verify-at-injection approximation becomes
   possible.
4. Watch prompt-security/clawsec for convergence (same niche, sealing
   SOUL.md).
