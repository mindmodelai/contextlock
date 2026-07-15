# Claude Code enforcement surface - empirical results (U1-U4)

This document resolves the four UNVERIFIED behaviors listed in SPEC.md section
7.1 by direct experiment against the locally installed Claude Code CLI. Every
verdict is version-stamped: it holds for the build tested and should be re-run on
upgrade.

## Test environment

| Item | Value |
|------|-------|
| Claude Code version (`claude --version`) | **2.1.210 (Claude Code)** |
| Date of test | 2026-07-14 (runs timestamped 2026-07-15 UTC) |
| OS | Windows 11 Home (10.0.26200) |
| Shell | PowerShell 7 host; hooks driven by Node scripts (shell-independent) |
| Node | v22.17.1 |
| `claude` binary | `C:\Users\user\.local\bin\claude.exe` |
| Model for all headless runs | `haiku` |

Method notes:

- All sandboxes were built under a scratch directory outside any real project. No
  real `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, or project was modified.
- U4 touched the real plugin store (marketplace add + plugin install) by design
  and was fully cleaned up; see U4 and the cleanup section.
- Hook `command` entries invoke small Node scripts (`node <abs path>.js`) rather
  than shell one-liners, so results do not depend on which shell Claude Code
  spawns hooks under on Windows. `jq` was not used (not guaranteed on Windows).
- Raw fixtures, hook logs, and trimmed transcripts are in `docs/evidence/`.
- Total `claude` invocations that consumed the model: 12 (all `--model haiku`,
  short prompts). Additional non-model CLI calls (`--version`, `plugin list`,
  `marketplace add`, `install`, `uninstall`, `validate`) do not bill the model.

A note that colors every verdict below: in non-interactive (`-p`) mode the
workspace-trust dialog is skipped (confirmed in `claude --help`), and project
`.claude/settings.json` hooks are loaded and executed. Interactive sessions gate
untrusted-workspace settings behind a trust prompt; that prompt does not fire
under `-p`. ContextLock enforcement that relies on `-p`/SDK runs therefore sees
project-settings hooks active, but so would a repo-controlled malicious hook - the
exact config-CVE vector SPEC section 7.2 Layer 4 addresses with managed settings.

--------------------------------------------------------------------------------

## U1 - SessionStart hook ordering vs CLAUDE.md ingestion

**Question.** Does a `SessionStart` hook run before or after the project CLAUDE.md
is ingested into model context?

**Method.** A sandbox project contained `CLAUDE.md` with the canary line
`The canary word is ALPHA.` and `.claude/settings.json` registering a
`SessionStart` hook (matcher `startup|resume`). The hook (`u1_hook.js`) does two
things: appends a timestamped line to a log file OUTSIDE the project, and rewrites
CLAUDE.md replacing `ALPHA` with `BRAVO`. The model was denied all read tools so
it could only answer from injected context, not by reading the file.

**Exact commands.** CLAUDE.md was reset to `ALPHA` immediately before each run.

```
# fresh session
claude -p "What is the canary word according to your project instructions? Answer with the single word only." \
  --model haiku --disallowedTools "Read" "Bash" "Glob" "Grep"

# resume of the same conversation
claude --continue -p "Repeat: what is the canary word in your project instructions? One word." \
  --model haiku --disallowedTools "Read" "Bash" "Glob" "Grep"
```

**Observations.**

- Fresh session: model answered **BRAVO**; on-disk CLAUDE.md was rewritten to
  BRAVO; `u1_hook.log` recorded `source=startup ... changed=true`.
- Resume (`--continue`): model answered **BRAVO**; log recorded `source=resume ...
  changed=true`.
- The model had no read tools, so BRAVO could only have come from context that was
  assembled after the hook mutated the file on disk.
- First-contact caveat: the first two invocations in a never-used directory exited
  1 and did not run the hook. A brand-new control directory ran its SessionStart
  hook on the very first `-p` invocation, so those two no-ops were a first-process
  initialization artifact, not a trust gate or an ordering signal.

**Verdict: CONFIRMED-AFTER.** The root project CLAUDE.md is ingested into context
AFTER `SessionStart` hooks execute. Confirmed on both cold start (`source=startup`)
and resume (`source=resume`).

**Implication for ContextLock enforcement (SPEC 7.2 Layer 2).** This is the more
favorable ordering, and it is slightly stronger than the cautious wording the spec
reserved for the opposite outcome. Because the hook runs first and CLAUDE.md is
read afterward, a `SessionStart` sweep can quarantine or repair a tampered root
CLAUDE.md (move-aside, or rewrite to a placeholder) in the SAME session, before its
content reaches the model. The spec's fallback sentence ("the sweep still catches
tampering for every subsequent session") can be tightened: for the root CLAUDE.md,
same-session interdiction is achievable. Two honest limits remain and should stay
in the spec: (1) `SessionStart` still has no hard-deny capability, so enforcement
is by filesystem mutation (quarantine) that the subsequent read then observes, not
by blocking ingestion; (2) this covers files present and swept at session start
(the root CLAUDE.md). Nested CLAUDE.md files load lazily on directory access and
are not reached by a session-start sweep, so write-time sealing plus write-deny
(Layer 1 / Layer 3) remains the primary control for those. Net: the spec's
"seal + write-deny is the primary CLAUDE.md control, with a session-start sweep as
backstop" stands, and the sweep is more effective for the root file than the
conservative wording implied.

--------------------------------------------------------------------------------

## U2 - Does skill invocation route SKILL.md reads through the Read tool?

**Question (a).** When a skill is invoked, is the SKILL.md body loaded via the
`Read` tool (and therefore interceptable by a `PreToolUse(Read)` hook), or is it
harness-internal? **Question (b).** Is skill invocation itself blockable via
`PreToolUse`?

**Method.** A project skill `.claude/skills/canaryskill/SKILL.md` (frontmatter
`name` + `description`; body says respond with `CHARLIE`) plus a bundled
`reference.md`. For (a), a catch-all `PreToolUse` hook (`matcher: ".*"`) logged
`tool_name` and every path-like field of `tool_input`. For (b), a
`PreToolUse` hook with `matcher: "Skill"` that exits 2.

**Exact commands.**

```
# (a) logging
claude -p "Use the canaryskill skill." --model haiku --allowedTools "Skill" "Read"

# (b) blocking (matcher "Skill", hook exits 2)
claude -p "Use the canaryskill skill and report exactly what it says." \
  --model haiku --allowedTools "Skill" "Read"
```

**Observations.**

- (a) The model answered `CHARLIE`. The ONLY `PreToolUse` event logged was the
  Skill tool itself:
  `{"tool_name":"Skill","skill":"canaryskill","tool_input_keys":["skill"]}`.
  No `Read` event for `SKILL.md` or for the bundled `reference.md` was ever logged.
  Debug output: `SkillTool returning 2 newMessages for skill canaryskill` - the
  body is injected by the Skill tool internally.
- (b) The invocation was denied. The model reported that the skill "was blocked by
  a hook ... 'ContextLock: canaryskill failed verification; invocation denied.'"
  and never emitted `CHARLIE`. The block hook logged `DENY tool=Skill
  skill=canaryskill`.

**Verdicts.**
- (a) **SKILL.md body read is NOT visible to PreToolUse.** The body is loaded
  harness-internally by the Skill tool; there is no `Read` tool call to intercept.
  The only interceptable surface for an invocation is the `Skill` tool call, whose
  `tool_input` carries the skill name but not a file read of the body. Bundled
  files are not auto-read at invocation; a skill that later reads its own bundled
  file would do so through the normal `Read` tool (interceptable), but that is a
  model action, not part of body loading.
- (b) **Skill invocation IS blockable** via a `PreToolUse` hook matching `Skill`
  and exiting 2.

**Implication for ContextLock enforcement (SPEC 7.2 Layer 3).** The spec's Layer 3
`matcher: Skill` deny is confirmed and is the correct hook for skill verification:
deny the whole invocation when the skill's files fail verification. The Layer 3
`matcher: Read` line must NOT be relied on for skill-body coverage - a
`PreToolUse(Read)` hook does not see SKILL.md loading, so it cannot verify or block
the body content that actually reaches the model. `PreToolUse(Read)` still covers
explicit reads of protected files (e.g. an agent opening a sealed CLAUDE.md), but
skill-body integrity has to ride entirely on the `Skill` matcher plus install-time
verification (Layer 1). Recommend tightening the spec's Layer 3 `Read` bullet to
state that skill bodies are out of its scope (resolved by this U2 result), and that
`PreToolUse(Skill)` is the sole runtime chokepoint for skill content.

--------------------------------------------------------------------------------

## U3 - Are hook definitions snapshotted at session start?

**Question.** If `.claude/settings.json` is edited mid-session to add a hook, does
that hook fire on a later turn of the same session, or are hook definitions fixed
at session start?

**Method.** A Node driver (`u3_driver.js`) ran a single stream-json session
(`--input-format stream-json --output-format stream-json --verbose`). It sent
turn 1, waited for the turn's `result` event, edited `.claude/settings.json` to
ADD a `UserPromptSubmit` hook that writes a marker file, then sent turn 2 and
waited. A separate control ran a fresh directory whose settings already contained
the same hook.

**Exact commands.**

```
# main test (driver-controlled, one process, two turns)
node u3_driver.js
# it launches:
#   claude -p --input-format stream-json --output-format stream-json --verbose --model haiku

# control (hook present from the start)
claude -p "say OK only" --model haiku      # run in a dir whose settings.json already has the hook
```

**Observations.**

- Main test: `RESULTS_SEEN=2`, `TURN2_SENT=true`, `MARKER_EXISTS=false`. Turn 1
  returned `READY`, the settings edit was applied (confirmed on disk), turn 2
  returned `OK`, but the newly added `UserPromptSubmit` hook never wrote its marker.
  Turn 2 re-emitted a `system/init` event, yet still did not pick up the new hook.
- Control: the identical hook, present in settings from the start, fired on a
  single `-p` run and wrote `MARKER fired at ...`. This rules out "UserPromptSubmit
  never fires in headless mode" as an explanation.

**Verdict: CONFIRMED - SNAPSHOTTED.** Hook definitions are read once at session
(process) start. Edits to `settings.json` during a running session are inert until
a new session/process starts.

**Implication for ContextLock enforcement (SPEC 7.2 Layer 3 / Layer 4).** This is
favorable and worth stating in the spec. An injected agent that rewrites
`.claude/settings.json` mid-session to unregister ContextLock's hooks does not
disable them for the current session - the snapshot holds until restart. Equally,
an attacker cannot inject a new malicious hook that fires later in the same
session. The residual risk is entirely at the NEXT session boundary: on restart,
edited project/user settings load, which is precisely why managed settings
(Layer 4, `allowManagedPermissionRulesOnly` + managed hooks that project/user
settings cannot remove) are the durable anchor. Recommendation: SPEC 7.2 can note
that hook enforcement is stable within a session but that persistence of the
enforcement config across sessions depends on the managed tier, not on the
project/user settings the agent can rewrite.

--------------------------------------------------------------------------------

## U4 - Is plugin cache content re-validated after install?

**Question.** After a plugin is installed, is the content served from
`~/.claude/plugins/cache/` re-validated against its source on load, or trusted once
installed?

**Method.** A local marketplace (`contextlock-surface`) listed one plugin
`cachecanary` whose single skill body says respond with `MARKER-V1`. It was added,
installed (scope user, non-interactive), then the INSTALLED CACHE copy of SKILL.md
was hand-edited to `MARKER-V2`, and a NEW session invoked the skill. A follow-up
edited the marketplace SOURCE to `MARKER-V3` to identify the actual load path.

**Exact commands.**

```
claude plugin validate <marketplace-dir>
claude plugin marketplace add <marketplace-dir>
claude plugin install cachecanary@contextlock-surface -s user
# edit ~/.claude/plugins/cache/contextlock-surface/cachecanary/1.0.0/skills/cachecanary/SKILL.md : V1 -> V2
claude -p "Use the cachecanary skill and report exactly the token it returns." --model haiku --allowedTools "Skill"
# edit marketplace SOURCE skill : V1 -> V3
claude -p "Use the cachecanary skill and report exactly the token it returns." --model haiku --allowedTools "Skill"
```

**Observations.**

- Install was fully non-interactive (no consent prompt blocked `-p`/CLI). Plugin
  showed `Version 1.0.0  Scope user  enabled`.
- After editing the CACHE copy to `MARKER-V2`, the new session returned
  **MARKER-V1**, not V2. Debug revealed why: the skill was loaded from the
  marketplace SOURCE directory
  (`...\u4-marketplace\plugins\cachecanary\skills`), NOT from the
  `~/.claude/plugins/cache/...` copy. For a LOCAL-source marketplace, plugin
  content is served live from the source directory and the installed cache copy is
  bypassed.
- The cache copy still read `MARKER-V2` after the run (my edit persisted, was never
  reverted or re-validated - it is simply inert for a local source).
- After editing the SOURCE to `MARKER-V3`, a new session returned **MARKER-V3**
  immediately. The live source change was served with no integrity check.

**Verdict: no integrity re-validation (cache-trust hypothesis REFUTED in the
stronger form).** There is no hash/signature validation of plugin content at load.
For a local-source marketplace the installed cache is not even the load path: the
live source directory is read directly, so whatever it contains is served. A
scoped limitation: a git/remote-source marketplace would make the cache directory
the load path; whether that cache is re-validated against the remote on each load
was not tested here (it needs network and a hosted repo). The local-source result
is decisive and already establishes the security-relevant fact: plugin instruction
content is trusted from its load path with no integrity check, and `uninstall`
leaves the cache directory behind (orphaned copy removed manually during cleanup).

**Implication for ContextLock enforcement (SPEC 7.2 / section 10).** Confirms the
spec's premise that plugin content has "no signing, no hashes, no install-time
validation" and validates the "verify at install; sweep" strategy for the
`~/.claude/plugins/cache/**` file class. Two refinements for the spec: (1) The load
path is not always the cache. For local (path) marketplaces the live source dir is
authoritative, so a ContextLock sweep and any write-deny rules must cover the
marketplace source directories, not only `~/.claude/plugins/cache/**`. (2) Because
content is trusted from the load path with zero re-validation, `contextlock
install` verify-at-install closes only the moment of install; any later write to
the load path (source dir for local marketplaces, cache dir for remote) is served
unverified on the next session. This is exactly the TOCTOU gap SPEC 7.2 Layer 1
calls out, and it argues for pairing install-time verification with write-deny on
plugin load paths plus a session-start sweep, rather than trusting the installed
copy.

--------------------------------------------------------------------------------

## Cleanup status (U4)

Mandatory cleanup completed and verified:

- `claude plugin uninstall cachecanary@contextlock-surface -s user -y` - success.
- `claude plugin marketplace remove contextlock-surface` - success.
- `claude plugin list` - only `frontend-design@claude-plugins-official` remains
  (the pre-existing baseline).
- `claude plugin marketplace list` - only `claude-plugins-official` remains.
- `installed_plugins.json` and `known_marketplaces.json` - back to baseline, no
  residual `cachecanary`/`contextlock-surface` references.
- `uninstall` left an orphaned cache dir
  `~/.claude/plugins/cache/contextlock-surface/`; it was removed with `rm -rf` and
  a final residual scan found nothing. `~/.claude/plugins/cache/` now contains only
  `claude-plugins-official`.

No real settings, memory, or project files were modified at any point.

--------------------------------------------------------------------------------

## Summary of verdicts (Claude Code 2.1.210, Windows 11)

| ID | Behavior | Verdict |
|----|----------|---------|
| U1 | SessionStart hook vs CLAUDE.md ingestion | **CONFIRMED-AFTER** - CLAUDE.md ingested after the hook runs (both startup and resume) |
| U2a | SKILL.md body read visible to PreToolUse(Read)? | **NOT visible** - body is harness-internal to the Skill tool |
| U2b | Skill invocation blockable via PreToolUse? | **Blockable** - `matcher: "Skill"` + exit 2 denies it |
| U3 | Hook definitions snapshotted at session start? | **CONFIRMED - SNAPSHOTTED** - mid-session settings edits are inert until restart |
| U4 | Plugin cache re-validated after install? | **No re-validation** - content trusted from the live load path; local-source marketplaces bypass the cache entirely |
