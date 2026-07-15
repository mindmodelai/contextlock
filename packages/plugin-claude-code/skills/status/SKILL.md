---
name: status
description: Report the ContextLock verification state of the current workspace. Use when the user asks about ContextLock status, whether instruction files are sealed or verified, whether a protected file was tampered with, or after editing a CLAUDE.md / SKILL.md / rules file to check what needs resealing.
---

# ContextLock status

Report the current ContextLock verification state to the user in plain language.

## Steps

1. Run the ContextLock user CLI to get machine-readable status. Use the Bash tool:

   ```
   contextlock status --json
   ```

   If the `contextlock` binary is not on PATH (for example during local
   development from this monorepo), fall back to the workspace bin:

   ```
   node ./packages/cli-user/bin/contextlock.mjs status --json
   ```

   If neither resolves, tell the user ContextLock is installed as a plugin but
   the CLI is not built or linked, and suggest `npm install && npm run build`
   from the repo root. Do not guess a status.

2. Parse the JSON output. Expect per-file records with a verification state and
   a summary. The states that matter:
   - `verified` / `sealed` / `trusted`: authentic and unmodified.
   - `modified`: the file changed since it was sealed or signed.
   - `unsealed` / `unprotected`: a protected-class file with no seal or
     signature yet.
   - `revoked`, `expired`, `error`: verification could not confirm the file.

3. Summarize for the user:
   - Give the counts: how many verified, how many modified, how many unsealed.
   - List every file that is `modified`, `revoked`, `expired`, or `error`, one
     per line, with its path.

4. Give a recommendation for each violation:
   - If a file is `modified` and the user made the change on purpose, recommend
     resealing it: `contextlock reseal <path>`.
   - If a file is `modified` and the change was not intended, treat it as a
     possible tampering or prompt-injection persistence attempt. Recommend the
     user investigate the diff before resealing, and do not reseal on their
     behalf.
   - If a file is `unsealed` and the user wants it protected, recommend
     `contextlock seal <path>`.

Keep the summary short and factual. ContextLock proves that a file is authentic
and unmodified, not that its contents are safe, so never describe a verified
file as "safe" - only as verified.
