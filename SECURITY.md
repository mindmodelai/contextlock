# Security policy

ContextLock is a security tool; reports about its own weaknesses are the
most valuable contributions it can receive.

## Reporting a vulnerability

Please report vulnerabilities privately via **GitHub private vulnerability
reporting** on this repository (Security tab -> "Report a vulnerability"),
or by email to **security@mindmodel.ai**. Please do not open public issues
for exploitable weaknesses.

You can expect an acknowledgment within 72 hours. Coordinated disclosure is
appreciated; we will credit reporters unless you prefer otherwise.

## Scope notes that matter for triage

- **Verified means authentic and unmodified, not safe.** A trusted publisher
  shipping harmful instructions is out of scope by design (SPEC.md section 3).
- The **threat model** (SPEC.md section 4) states explicitly what ContextLock
  defends against and what it does not (e.g. a same-privilege attacker with
  arbitrary code execution outside the host tool). Reports that break a
  *claimed* defense (T1-T14) are in scope and serious - especially anything
  that makes verification pass on modified bytes, bypasses anti-rollback, or
  silently downgrades a protected file to unverified.
- The enforcement mappings for host tools document known residual gaps
  (`docs/claude-code-surface.md`, `docs/openclaw-surface.md`). Reports that
  find NEW gaps in those surfaces are welcome.

## Supported versions

Pre-1.0: only the latest published release receives fixes.
