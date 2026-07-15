# @contextlock/plugin-claude-code

The ContextLock enforcement layer for Claude Code, packaged as an installable
plugin. It verifies the authenticity and integrity of AI instruction files
(CLAUDE.md, SKILL.md, rules, prompt packs, hook and agent configs) before and
while they influence the model, and it makes tampering a visible, blocked
action rather than a silent one.

ContextLock proves that a file is authentic and unmodified. It does not judge
whether the content is safe. A trusted publisher can still ship harmful
instructions. This is provenance, not safety.

## What the plugin does: the four enforcement layers

Claude Code has no "before context assembly" hook, so ContextLock does not
pretend to intercept every load. Instead it layers four real mechanisms,
ordered from strongest to weakest.

**Layer 1 - Write-time and install-time.** The strongest control, because it is
the moment ContextLock owns. Files are pinned at review time with
`contextlock seal`, and packages are verified before their files are placed
into skill or plugin directories. For CLAUDE.md, which has no load hook,
write-time is the primary control: seal the file once, then deny unauthorized
writes to it (Layer 3). Verify-at-install plus write-deny closes the
time-of-check-to-time-of-use gap that verify-at-load alone would leave open.

**Layer 2 - Session-start sweep.** The plugin's `SessionStart` hook runs a
sweep that verifies every protected-class file reachable from the workspace and
the user scope. Failures are quarantined where policy allows (moved aside with a
placeholder), and a status report is always injected via `additionalContext` so
both the model and the user see it. SessionStart hooks cannot block, so this is
detection plus quarantine, not load-time interception: it catches tampering for
every subsequent session and removes the offending file before the next one.

**Layer 3 - Read, invoke, and write-time denial.** The plugin's `PreToolUse`
hooks turn verification into hard denials. A `Skill` matcher denies invoking a
skill whose files fail verification. A `Read` matcher denies reads of
protected-class files in a modified or revoked state. An `Edit`/`Write` matcher
denies writes to sealed files and to ContextLock's own state under
`~/.contextlock/`, which is what turns a prompt-injection persistence attempt
(an agent editing its own instruction files) into a visible permission denial.

**Layer 4 - Managed policy.** For teams and single machines that want a real
boundary, the shipped managed-settings template registers the same hooks and
deny rules at the managed tier with `allowManagedPermissionRulesOnly: true`.
A repo-controlled `.claude/settings.json` (the exact vector of CVE-2025-59536
and CVE-2026-21852) then cannot unregister verification or widen permissions.
Disabling ContextLock now requires OS-admin privilege, not just write access to
the repository the agent is already editing.

## Package contents

```
packages/plugin-claude-code/
  .claude-plugin/
    plugin.json                    # plugin manifest
    marketplace.json               # single-plugin marketplace (source: "./")
  hooks/hooks.json                 # SessionStart sweep + PreToolUse matchers
  scripts/hook.mjs                 # dependency-free hook wrapper (see below)
  skills/status/SKILL.md           # /contextlock:status skill
  settings.template.json           # advisory deny rules (user scope)
  managed-settings.template.jsonc  # managed hooks + deny rules + lockdown
  src/hook.test.ts                 # vitest suite for the wrapper
```

### The hook wrapper (`scripts/hook.mjs`)

The hooks do not call the CLI directly. They call this small, dependency-free
(node builtins only) shim, which:

1. reads the Claude Code hook JSON from stdin,
2. resolves the ContextLock user CLI, in this order:
   - `CONTEXTLOCK_CLI` if set (a path to a JS bin file),
   - `@contextlock/cli-user` resolved by walking up `node_modules` from
     `${CLAUDE_PLUGIN_ROOT}` (works in-workspace via npm workspaces), then its
     declared bin,
   - a `contextlock` JS entry found on `PATH`,
3. spawns it as `node <binpath> hook <event>`, piping stdin through,
4. forwards the CLI's stdout and exit code verbatim.

It is Windows-safe: the CLI is always launched with the current node executable
(`process.execPath`), never through a shebang, a `.cmd` shim, or a shell.

## Fail-open vs `CONTEXTLOCK_STRICT`

By default the wrapper fails **open**. If the CLI cannot be resolved or fails to
spawn, the hook exits 0 and prints a single diagnostic line to stderr:

```
[ContextLock] hook could not run (CLI not found or not built - run npm install && npm run build): <detail>
```

A broken or not-yet-built install therefore never blocks the user. This is the
right default for a verification layer people are trying out.

Set `CONTEXTLOCK_STRICT=1` to fail **closed** instead:

- on `pre-tool-use`, the wrapper emits a `PreToolUse` deny decision
  (`permissionDecision: "deny"`) so an unverifiable tool call is blocked,
- on `session-start`, it cannot block, so it injects a warning via
  `additionalContext` telling the model and user that files were not verified
  this session.

Strict mode is intended for the managed tier and for environments where "we
could not verify" should be treated the same as "verification failed".

## Local install for development

The plugin lives inside this monorepo, so `node_modules` resolution finds the
workspace copy of `@contextlock/cli-user`. From the repository root:

```bash
npm install
npm run build     # builds the CLI the hooks call
```

### Option A - load the plugin directly (recommended for iteration)

No marketplace needed. Point Claude Code at the plugin directory:

```bash
claude --plugin-dir ./packages/plugin-claude-code
```

Then use the status skill and re-run after edits:

```
/contextlock:status
/reload-plugins
```

### Option B - install through the local marketplace

The plugin doubles as a single-plugin marketplace
(`.claude-plugin/marketplace.json`, plugin source `"./"`). Add it and install
from it. In an interactive session:

```
/plugin marketplace add ./packages/plugin-claude-code
/plugin install contextlock@contextlock-plugins
```

Or from the shell:

```bash
claude plugin marketplace add ./packages/plugin-claude-code
claude plugin install contextlock@contextlock-plugins
```

Note the difference between the two options for CLI resolution: `--plugin-dir`
keeps the plugin in place inside the workspace, so the wrapper resolves
`@contextlock/cli-user` through the workspace `node_modules`. A marketplace
install copies the plugin into a cache outside the workspace, so the wrapper
falls back to a `contextlock` binary on `PATH` (install `@contextlock/cli-user`
globally) or to `CONTEXTLOCK_CLI`.

Validate the manifest and hook config before sharing:

```bash
claude plugin validate ./packages/plugin-claude-code
```

## Settings templates

Two templates ship with the plugin. Copy the one that fits your tier.

### `settings.template.json` (advisory, user scope)

Copy its `permissions.deny` entries into `~/.claude/settings.json`. Each rule
protects one thing from agent writes:

| Rule | Protects |
| ---- | -------- |
| `Edit/Write(~/.contextlock/**)` | ContextLock's own state: the seal store, the machine-local signing key, and the trust store. Blocks an agent from re-sealing a file it just tampered with. |
| `Edit/Write(~/.claude/CLAUDE.md)` | User-scope agent memory. It steers every session and has no load-time hook, so write-deny is its primary control. |
| `Edit/Write(~/.claude/settings.json)` | The file that registers hooks. Denying writes stops the agent unregistering ContextLock's own hooks. |

User settings are advisory: a user-privileged attacker can rewrite them. That is
the honest boundary of this tier, and the reason the managed template exists.

### `managed-settings.template.jsonc` (managed / enterprise or single-machine)

A JSONC file (inline comments explain every line and the attack it blocks).
Remove the comments if your build requires strict JSON, then deploy to the
OS-admin managed path:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux and WSL: `/etc/claude-code/managed-settings.json`
- Windows: `C:\Program Files\ClaudeCode\managed-settings.json`

It adds, on top of the advisory deny rules:

- `allowManagedPermissionRulesOnly: true`, which makes the managed permission
  rules the only ones Claude Code evaluates, so a repo-controlled
  `.claude/settings.json` cannot add an `allow` rule to re-enable a denied write
  (the CVE-2025-59536 / CVE-2026-21852 class),
- the same `SessionStart` and `PreToolUse` hooks, registered at managed scope so
  user and project settings cannot remove them,
- deny rules for the config-CVE class (project `.claude/settings.json`,
  `.mcp.json`, hook configs).

The managed hooks call `contextlock hook <event>` directly and so require the
`contextlock` binary on the system `PATH`. If it is not on PATH, replace the
command with an absolute node invocation, for example
`node /opt/contextlock/packages/cli-user/bin/contextlock.mjs hook session-start`.

## Tests

```bash
npm test --workspace @contextlock/plugin-claude-code
```

The suite (`src/hook.test.ts`) runs the wrapper as a child process with fixture
stdin and does not require the `@contextlock/cli-user` build: it forces
resolution to fail for the fail-open and strict-mode cases, and points
`CONTEXTLOCK_CLI` at a fake CLI written at runtime for the pass-through case.
The root `npm test` picks this file up through the existing vitest include glob
(`packages/*/src/**/*.test.ts`).

## Bootstrap honesty

This plugin verifies instruction content, but the plugin itself is distributed
through exactly the unverified channel it exists to fix. A marketplace pins a
git commit SHA at best; nothing signs the plugin's own files. We do not hide
that.

The interim answer is to publish signed release artifacts plus a one-line
install verifier script, pin the marketplace entry to commit SHAs, and document
the residual risk (here). The long-term answer is upstream support for signed
plugins in the host tool. Until then, treat installing ContextLock the way you
should treat installing any plugin: from a source you trust, verified out of
band where you can.
