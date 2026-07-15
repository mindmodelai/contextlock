/**
 * ToolAdapter interface — Standard interface for tool-specific adapters.
 * Requirements: 17.1, 17.2, 17.3, 17.4
 */

import type { VerificationResult } from "./engine.js";
import type { PolicyDecision } from "./policy.js";

export interface ToolAdapter {
  /**
   * Intercepts a file load event, invokes the verification engine,
   * and returns a policy decision (allow/warn/block).
   */
  onFileLoad(filePath: string): Promise<PolicyDecision>;

  /**
   * Returns the full verification result for a file.
   */
  getVerificationStatus(filePath: string): Promise<VerificationResult>;
}
