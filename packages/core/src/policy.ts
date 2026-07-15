// Policy Engine — evaluates verification results against configured policy levels
// Requirements: 7.1, 7.2, 7.3, 7.4, 7.7

import type { PublisherPolicy } from "./trust-store.js";

// ---- Types ----

export type PolicyLevel = "strict" | "balanced" | "audit";

export type PolicyDecision = "allow" | "warn" | "block" | "quarantine" | "audit";

export type VerificationStatus =
  | "trusted"
  | "modified"
  | "untrusted"
  | "revoked"
  | "expired"
  | "error";

export interface PolicyInput {
  level: PolicyLevel;
  verificationResult: { status: VerificationStatus };
  publisherPolicy?: PublisherPolicy;
}

// ---- Policy matrix ----

const POLICY_MATRIX: Record<PolicyLevel, Record<VerificationStatus, PolicyDecision>> = {
  strict: {
    trusted: "allow",
    modified: "block",
    untrusted: "block",
    revoked: "block",
    expired: "block",
    error: "block",
  },
  balanced: {
    trusted: "allow",
    modified: "block",
    untrusted: "warn",
    revoked: "block",
    expired: "warn",
    error: "block",
  },
  audit: {
    trusted: "allow",
    modified: "audit",
    untrusted: "audit",
    revoked: "audit",
    expired: "audit",
    error: "audit",
  },
};

// ---- evaluatePolicy ----

export function evaluatePolicy(input: PolicyInput): PolicyDecision {
  const { level, verificationResult, publisherPolicy } = input;
  const status = verificationResult.status;

  // Trusted status always returns "allow" regardless of overrides
  if (status === "trusted") {
    return "allow";
  }

  // Per-publisher policy override takes precedence for non-trusted statuses
  if (publisherPolicy) {
    return publisherPolicy.default_action;
  }

  // Fall back to global policy matrix
  return POLICY_MATRIX[level][status];
}
