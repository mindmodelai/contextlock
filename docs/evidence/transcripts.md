# Trimmed command transcripts - Claude Code surface tests

Environment: Windows 11, PowerShell host, Git Bash tool. Claude Code `2.1.210`.
Node `v22.17.1`. All headless runs used `--model haiku`. Sandbox root:
`...\scratchpad\surface-tests\`. Hook commands invoke small Node scripts (see
sibling `*.js` fixtures) so behaviour is shell-independent on Windows.

--------------------------------------------------------------------------------
## U1 - SessionStart hook ordering vs CLAUDE.md ingestion
--------------------------------------------------------------------------------

Hook `u1_hook.js` (SessionStart) appends to a log OUTSIDE the project and
rewrites the project CLAUDE.md, replacing ALPHA with BRAVO. CLAUDE.md canary line:
`The canary word is ALPHA.` The model is denied Read/Bash/Glob/Grep so it can only
answer from injected context.

Command (fresh session; CLAUDE.md reset to ALPHA immediately before):

    claude -p "What is the canary word according to your project instructions? Answer with the single word only." \
      --model haiku --disallowedTools "Read" "Bash" "Glob" "Grep"

    stdout           => BRAVO
    CLAUDE.md ondisk => "The canary word is BRAVO."   (hook rewrote it)
    u1_hook.log      => SessionStart hook fired source=startup / rewrote CLAUDE.md ALPHA->BRAVO changed=true

Command (resume of the same conversation; CLAUDE.md reset to ALPHA first):

    claude --continue -p "Repeat: what is the canary word in your project instructions? One word." \
      --model haiku --disallowedTools "Read" "Bash" "Glob" "Grep" </dev/null

    stdout           => BRAVO
    u1_hook.log tail => SessionStart hook fired source=resume / rewrote CLAUDE.md ALPHA->BRAVO changed=true

Interpretation: the model reports BRAVO (the hook-mutated value) with no read
tools available, so the CLAUDE.md content it saw was assembled AFTER the hook ran.

Note on first-contact: the first two invocations in a never-before-used project
directory exited 1 and did NOT run the hook (no log, CLAUDE.md unchanged). A
brand-new control directory (u1b-project) ran its SessionStart hook on the very
first `-p` invocation, so the two no-op runs were a first-process initialization
artifact, not a trust gate. In `-p` mode the workspace-trust dialog is skipped
(per `claude --help`), and project `.claude/settings.json` hooks do load and run.

--------------------------------------------------------------------------------
## U2 - Does skill invocation route SKILL.md reads through the Read tool?
--------------------------------------------------------------------------------

Project skill `.claude/skills/canaryskill/SKILL.md` body: respond with CHARLIE.
Catch-all PreToolUse hook (`matcher: ".*"`) logs tool_name + path-like fields.

(a) Logging run:

    claude -p "Use the canaryskill skill." --model haiku --allowedTools "Skill" "Read"

    stdout => CHARLIE
    u2_pretooluse.log (the ONLY event logged):
      {"event":"PreToolUse","tool_name":"Skill","skill":"canaryskill","tool_input_keys":["skill"]}
    debug => tool_dispatch_start tool=Skill ...
             SkillTool returning 2 newMessages for skill canaryskill

    No Read event for SKILL.md or the bundled reference.md appeared. The skill body
    is loaded harness-internally by the Skill tool, not via the Read tool.

(b) Blocking run (PreToolUse matcher "Skill", hook exits 2):

    claude -p "Use the canaryskill skill and report exactly what it says." \
      --model haiku --allowedTools "Skill" "Read"

    stdout => "The canaryskill invocation was blocked by a hook at block_skill.js with
               the error: 'ContextLock: canaryskill failed verification; invocation denied.'"
    u2b_block.log => DENY tool=Skill skill=canaryskill

    The invocation was denied; the model never emitted CHARLIE.

--------------------------------------------------------------------------------
## U3 - Are hook definitions snapshotted at session start?
--------------------------------------------------------------------------------

Driver `u3_driver.js` runs ONE stream-json session (--input-format stream-json
--output-format stream-json --verbose). Turn 1 -> wait for result -> edit
.claude/settings.json to ADD a UserPromptSubmit hook that writes a marker file ->
Turn 2 -> check the marker.

    CHILD_EXIT=0  RESULTS_SEEN=2  TURN2_SENT=true  MARKER_EXISTS=false

    u3_events.log (abridged):
      --- spawned; sending turn 1 ---
      EVENT type=result subtype=success  => result #1 result_text="READY"
      --- edited settings.json to add UserPromptSubmit hook ---
      --- sent turn 2 ---
      EVENT type=system subtype=init          (turn 2 re-emits an init...)
      EVENT type=result subtype=success  => result #2 result_text="OK"
      (marker file never created)

Control (fresh dir u3b-project with the UserPromptSubmit hook present from the
start, single `-p`):

    claude -p "say OK only" --model haiku
    stdout => OK
    u3_marker_control.txt => "MARKER fired at 2026-07-15T02:12:41Z"   (hook DID fire)

Interpretation: UserPromptSubmit hooks do fire in headless mode (control), but a
hook ADDED to settings.json mid-session did not fire on the subsequent turn.
Hook definitions are snapshotted at session start.

--------------------------------------------------------------------------------
## U4 - Is plugin cache content re-validated after install?
--------------------------------------------------------------------------------

Local marketplace `contextlock-surface` with one plugin `cachecanary` (single
skill; body says respond with MARKER-V1). Marketplace source is a LOCAL PATH.

    claude plugin validate <mkt>         => Validation passed with warnings
    claude plugin marketplace add <mkt>  => Successfully added marketplace: contextlock-surface (user settings)
    claude plugin install cachecanary@contextlock-surface -s user
                                          => Successfully installed (scope: user)
    claude plugin list                   => cachecanary@contextlock-surface  Version 1.0.0  enabled

Installed cache copy located at:
    ~/.claude/plugins/cache/contextlock-surface/cachecanary/1.0.0/skills/cachecanary/SKILL.md
    (original content: MARKER-V1)

Hand-edited the CACHE copy MARKER-V1 -> MARKER-V2, then a NEW session:

    claude -p "Use the cachecanary skill and report exactly the token it returns." \
      --model haiku --allowedTools "Skill"
    stdout => MARKER-V1                    (NOT the edited V2)
    debug  => Attempting to load skills from plugin cachecanary default skillsPath:
              ...\surface-tests\u4-marketplace\plugins\cachecanary\skills

    The load path was the marketplace SOURCE dir, not the cache. The cache edit was
    ignored because a local-source marketplace is served live from source.

Confirmation - cache still held the edit; then edited SOURCE MARKER-V1 -> MARKER-V3:

    cache SKILL.md marker => MARKER-V2      (my cache edit persisted, never re-validated)
    (edit source to V3)
    claude -p "Use the cachecanary skill and report exactly the token it returns." ...
    stdout => MARKER-V3                     (live source change served immediately)

Interpretation: no integrity re-validation exists. For a local-source marketplace
the installed cache copy is bypassed entirely; content is loaded live from source
and whatever it says is served. The cache copy is neither the authority nor
re-validated.

Cleanup:
    claude plugin uninstall cachecanary@contextlock-surface -s user -y
                                          => Successfully uninstalled plugin: cachecanary
    claude plugin marketplace remove contextlock-surface
                                          => Successfully removed marketplace
    claude plugin list        => only frontend-design@claude-plugins-official
    claude plugin marketplace list => only claude-plugins-official
    installed_plugins.json / known_marketplaces.json => back to baseline (no residual refs)
    NOTE: uninstall left an orphaned cache dir ~/.claude/plugins/cache/contextlock-surface/;
    it was removed manually (rm -rf) to complete cleanup. Final residual check: none.
