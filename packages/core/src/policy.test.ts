// Unit tests for Policy Engine
// Requirements: 7.1, 7.2, 7.3, 7.4, 7.7

import { describe, it, expect } from "vitest";
import { evaluatePolicy } from "./policy.js";
import type { PolicyLevel, VerificationStatus, PolicyDecision } from "./policy.js";
import type { PublisherPolicy } from "./trust-store.js";

// ---- Policy matrix tests ----

describe("evaluatePolicy — policy matrix", () => {
  const matrixCases: Array<[PolicyLevel, VerificationStatus, PolicyDecision]> = [
    // strict
    ["strict", "trusted", "allow"],
    ["strict", "modified", "block"],
    ["strict", "untrusted", "block"],
    ["strict", "revoked", "block"],
    ["strict", "expired", "block"],
    ["strict", "error", "block"],
    // balanced
    ["balanced", "trusted", "allow"],
    ["balanced", "modified", "block"],
    ["balanced", "untrusted", "warn"],
    ["balanced", "revoked", "block"],
    ["balanced", "expired", "warn"],
    ["balanced", "error", "block"],
    // audit
    ["audit", "trusted", "allow"],
    ["audit", "modified", "audit"],
    ["audit", "untrusted", "audit"],
    ["audit", "revoked", "audit"],
    ["audit", "expired", "audit"],
    ["audit", "error", "audit"],
  ];

  it.each(matrixCases)(
    "%s + %s → %s",
    (level, status, expected) => {
      const decision = evaluatePolicy({
        level,
        verificationResult: { status },
      });
      expect(decision).toBe(expected);
    },
  );
});

// ---- Per-publisher override tests ----

describe("evaluatePolicy — per-publisher overrides", () => {
  const basePolicy: PublisherPolicy = {
    default_action: "allow",
    allow_expired_manifest: false,
    allow_offline_cached_manifest: false,
  };

  it("override 'allow' overrides strict block for modified status", () => {
    const decision = evaluatePolicy({
      level: "strict",
      verificationResult: { status: "modified" },
      publisherPolicy: { ...basePolicy, default_action: "allow" },
    });
    expect(decision).toBe("allow");
  });

  it("override 'warn' overrides strict block for untrusted status", () => {
    const decision = evaluatePolicy({
      level: "strict",
      verificationResult: { status: "untrusted" },
      publisherPolicy: { ...basePolicy, default_action: "warn" },
    });
    expect(decision).toBe("warn");
  });

  it("override 'block' overrides balanced warn for untrusted status", () => {
    const decision = evaluatePolicy({
      level: "balanced",
      verificationResult: { status: "untrusted" },
      publisherPolicy: { ...basePolicy, default_action: "block" },
    });
    expect(decision).toBe("block");
  });

  it("override 'block' overrides audit for error status", () => {
    const decision = evaluatePolicy({
      level: "audit",
      verificationResult: { status: "error" },
      publisherPolicy: { ...basePolicy, default_action: "block" },
    });
    expect(decision).toBe("block");
  });

  it("trusted status returns 'allow' even with override set to 'block'", () => {
    const decision = evaluatePolicy({
      level: "strict",
      verificationResult: { status: "trusted" },
      publisherPolicy: { ...basePolicy, default_action: "block" },
    });
    expect(decision).toBe("allow");
  });

  it("trusted status returns 'allow' even with override set to 'warn'", () => {
    const decision = evaluatePolicy({
      level: "audit",
      verificationResult: { status: "trusted" },
      publisherPolicy: { ...basePolicy, default_action: "warn" },
    });
    expect(decision).toBe("allow");
  });

  it("no override falls back to global policy matrix", () => {
    const decision = evaluatePolicy({
      level: "balanced",
      verificationResult: { status: "expired" },
    });
    expect(decision).toBe("warn");
  });

  it("override applies to revoked status", () => {
    const decision = evaluatePolicy({
      level: "audit",
      verificationResult: { status: "revoked" },
      publisherPolicy: { ...basePolicy, default_action: "block" },
    });
    expect(decision).toBe("block");
  });

  it("override applies to expired status", () => {
    const decision = evaluatePolicy({
      level: "strict",
      verificationResult: { status: "expired" },
      publisherPolicy: { ...basePolicy, default_action: "warn" },
    });
    expect(decision).toBe("warn");
  });
});
