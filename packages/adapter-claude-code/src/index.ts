/**
 * Claude Code adapter — Intercepts file load events and enforces TCV policy.
 * Requirements: 17.1, 17.2, 17.3, 17.5, 7.5, 7.6
 */

import {
  VerificationEngine,
  evaluatePolicy,
  DEFAULT_PATTERNS,
} from "@contextlock/core";
import type {
  ToolAdapter,
  VerificationResult,
  VerificationEngineConfig,
  PolicyLevel,
  PolicyDecision,
} from "@contextlock/core";

export interface ClaudeCodeAdapterConfig {
  trustStorePath: string;
  cachePath: string;
  policyLevel: PolicyLevel;
  protectedPatterns?: string[];
}

/**
 * Generates a user-facing block message explaining why a file was blocked.
 */
export function formatBlockMessage(filePath: string, result: VerificationResult): string {
  switch (result.status) {
    case "modified":
      return `[ContextLock] Blocked: ${filePath} has been modified since signing (expected: ${result.expectedHash}, got: ${result.fileHash})`;
    case "untrusted":
      return `[ContextLock] Blocked: ${filePath} is untrusted — ${result.reason}`;
    case "revoked":
      return `[ContextLock] Blocked: ${filePath} was signed with a revoked key (key: ${result.keyId})`;
    case "expired":
      return `[ContextLock] Blocked: ${filePath} manifest has expired (expires_at: ${result.expiresAt})`;
    case "error":
      return `[ContextLock] Blocked: ${filePath} verification error — ${result.reason}`;
    default:
      return `[ContextLock] Blocked: ${filePath} — ${result.status}`;
  }
}

export class ClaudeCodeAdapter implements ToolAdapter {
  private engine: VerificationEngine;
  private policyLevel: PolicyLevel;

  constructor(config: ClaudeCodeAdapterConfig) {
    const engineConfig: VerificationEngineConfig = {
      trustStorePath: config.trustStorePath,
      cachePath: config.cachePath,
      protectedPatterns: config.protectedPatterns ?? DEFAULT_PATTERNS,
      policyLevel: config.policyLevel,
    };
    this.engine = new VerificationEngine(engineConfig);
    this.policyLevel = config.policyLevel;
  }

  async onFileLoad(filePath: string): Promise<PolicyDecision> {
    if (!this.engine.isProtected(filePath)) {
      return "allow";
    }

    const result = await this.engine.verify(filePath);
    return evaluatePolicy({
      level: this.policyLevel,
      verificationResult: result,
    });
  }

  async getVerificationStatus(filePath: string): Promise<VerificationResult> {
    return this.engine.verify(filePath);
  }
}
