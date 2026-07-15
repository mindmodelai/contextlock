// Policy Engine - evaluates verification results against configured policy levels
// Requirements: 7.1, 7.2, 7.3, 7.4, 7.7

import type { PublisherPolicy } from "./trust-store.js";

// ---- Types ----

export type PolicyLevel = "strict" | "balanced" | "audit";

export type PolicyDecision = "allow" | "warn" | "block" | "quarantine" | "audit";

export type VerificationStatus =
  | "trusted"
  | "sealed"
  | "sealed+trusted"
  | "modified"
  | "untrusted"
  | "revoked"
  | "expired"
  | "error"
  | "seal-store-unavailable";

export interface PolicyInput {
  level: PolicyLevel;
  verificationResult: { status: VerificationStatus };
  publisherPolicy?: PublisherPolicy;
}

// ---- Policy matrix ----

// Mode 0 evidence (SPEC v2 5): a valid seal behaves as trusted; a
// seal-store-unavailable error behaves exactly like `error` (block under
// strict/balanced) so a tampered/corrupt store never silently downgrades to
// "unsealed".
const POLICY_MATRIX: Record<PolicyLevel, Record<VerificationStatus, PolicyDecision>> = {
  strict: {
    trusted: "allow",
    sealed: "allow",
    "sealed+trusted": "allow",
    modified: "block",
    untrusted: "block",
    revoked: "block",
    expired: "block",
    error: "block",
    "seal-store-unavailable": "block",
  },
  balanced: {
    trusted: "allow",
    sealed: "allow",
    "sealed+trusted": "allow",
    modified: "block",
    untrusted: "warn",
    revoked: "block",
    expired: "warn",
    error: "block",
    "seal-store-unavailable": "block",
  },
  audit: {
    trusted: "allow",
    sealed: "allow",
    "sealed+trusted": "allow",
    modified: "audit",
    untrusted: "audit",
    revoked: "audit",
    expired: "audit",
    error: "audit",
    "seal-store-unavailable": "audit",
  },
};

// Statuses that always allow, regardless of per-publisher overrides.
const ALWAYS_ALLOW: ReadonlySet<VerificationStatus> = new Set([
  "trusted",
  "sealed",
  "sealed+trusted",
]);

// ---- evaluatePolicy ----

export function evaluatePolicy(input: PolicyInput): PolicyDecision {
  const { level, verificationResult, publisherPolicy } = input;
  const status = verificationResult.status;

  // Trusted / sealed statuses always return "allow" regardless of overrides
  if (ALWAYS_ALLOW.has(status)) {
    return "allow";
  }

  // Per-publisher policy override takes precedence for non-trusted statuses
  if (publisherPolicy) {
    return publisherPolicy.default_action;
  }

  // Fall back to global policy matrix
  return POLICY_MATRIX[level][status];
}
