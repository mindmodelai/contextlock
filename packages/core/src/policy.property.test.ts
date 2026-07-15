// Feature: contextlock, Property 10: Policy engine evaluation
// **Validates: Requirements 7.2, 7.3, 7.4, 7.7**

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { evaluatePolicy } from "./policy.js";
import type { PolicyLevel, VerificationStatus, PolicyDecision } from "./policy.js";
import type { PublisherPolicy } from "./trust-store.js";

// ---- Expected policy matrix ----

const EXPECTED_MATRIX: Record<PolicyLevel, Record<VerificationStatus, PolicyDecision>> = {
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

// ---- Arbitraries ----

const policyLevelArb: fc.Arbitrary<PolicyLevel> = fc.constantFrom("strict", "balanced", "audit");

const verificationStatusArb: fc.Arbitrary<VerificationStatus> = fc.constantFrom(
  "trusted",
  "modified",
  "untrusted",
  "revoked",
  "expired",
  "error",
);

const publisherPolicyArb: fc.Arbitrary<PublisherPolicy> = fc.record({
  default_action: fc.constantFrom("block" as const, "warn" as const, "allow" as const),
  allow_expired_manifest: fc.boolean(),
  allow_offline_cached_manifest: fc.boolean(),
});

// ---- Property 10: Policy engine evaluation ----

describe("Property 10: Policy engine evaluation", () => {
  it("decisions match the policy matrix for all status/level combinations (no override)", () => {
    fc.assert(
      fc.property(policyLevelArb, verificationStatusArb, (level, status) => {
        const decision = evaluatePolicy({
          level,
          verificationResult: { status },
        });
        const expected = EXPECTED_MATRIX[level][status];
        expect(decision).toBe(expected);
      }),
      { numRuns: 100 },
    );
  });

  it("per-publisher overrides take precedence over global policy for non-trusted statuses", () => {
    // Only test non-trusted statuses since trusted always returns "allow"
    const nonTrustedStatusArb: fc.Arbitrary<VerificationStatus> = fc.constantFrom(
      "modified",
      "untrusted",
      "revoked",
      "expired",
      "error",
    );

    fc.assert(
      fc.property(
        policyLevelArb,
        nonTrustedStatusArb,
        publisherPolicyArb,
        (level, status, publisherPolicy) => {
          const decision = evaluatePolicy({
            level,
            verificationResult: { status },
            publisherPolicy,
          });
          expect(decision).toBe(publisherPolicy.default_action);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("trusted status always returns 'allow' even with publisher override", () => {
    fc.assert(
      fc.property(policyLevelArb, publisherPolicyArb, (level, publisherPolicy) => {
        const decision = evaluatePolicy({
          level,
          verificationResult: { status: "trusted" },
          publisherPolicy,
        });
        expect(decision).toBe("allow");
      }),
      { numRuns: 100 },
    );
  });
});
