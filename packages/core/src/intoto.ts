/**
 * in-toto Statement read-compatibility (SPEC v2 Phase D: nono interop).
 *
 * nono (nolabs-ai/nono, Luke Hinds) attests skills as:
 *   Sigstore bundle v0.3 -> DSSE (payloadType application/vnd.in-toto+json)
 *   -> in-toto Statement v1 with predicateType
 *   https://nono.sh/attestation/{instruction-file|multi-file}/v1 and
 *   subjects = { name, digest.sha256 }. Sidecars: `<file>.bundle` (single)
 *   and `.nono-trust.bundle` (multi-file, the skill shape).
 *
 * This module lets ContextLock CONSUME those attestations: the Sigstore
 * bundle crypto + identity pinning is shared with Profile B; here we parse
 * the Statement payload and map subjects to file integrity entries.
 *
 * REDUCED GUARANTEES, on purpose: an in-toto Statement carries no monotonic
 * version, no expires_at, and no byte length - so anti-rollback (T7), freeze
 * (T8), and length-before-hash do NOT apply to this evidence. Callers get
 * authenticity + integrity only, and results say so. This asymmetry is
 * exactly why contextlock/2 keeps its own payload (SPEC 15, OQ3) - see
 * docs/nono-interop.md.
 */

import { verifySigstoreBundle } from "./sigstore.js";
import type { SigstoreVerifyOptions, TrustedIdentity } from "./sigstore.js";

// ---- Constants (nono wire format, confirmed from source 2026-07-15) ----

export const IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";

export const NONO_PREDICATE_SINGLE = "https://nono.sh/attestation/instruction-file/v1";
export const NONO_PREDICATE_MULTI = "https://nono.sh/attestation/multi-file/v1";

/** nono's multi-subject sidecar filename (the skill attestation shape). */
export const NONO_MULTI_BUNDLE_FILENAME = ".nono-trust.bundle";

/** nono enforces at most 1,000 subjects; mirror the bound. */
export const MAX_STATEMENT_SUBJECTS = 1000;

// ---- Types ----

export interface StatementSubject {
  name: string;
  digest: Record<string, string>;
}

export interface InTotoStatement {
  _type: typeof IN_TOTO_STATEMENT_TYPE;
  subject: StatementSubject[];
  predicateType: string;
  predicate?: unknown;
}

export interface StatementFileEntry {
  /** Relative path (multi-file) or basename (single-file). */
  path: string;
  sha256: string;
}

export interface NonoVerification {
  valid: boolean;
  reason?: string;
  publisher?: string;
  identity?: string;
  issuer?: string;
  predicateType?: string;
  files?: StatementFileEntry[];
  /** Always set on success: the guarantees this evidence does NOT carry. */
  warning?: string;
}

export const REDUCED_GUARANTEE_WARNING =
  "in-toto attestation: authenticity+integrity only (no version -> no anti-rollback; " +
  "no expires_at -> no freeze defense; no length field)";

// ---- Statement parsing ----

/**
 * Subject-name safety, mirroring nono's own rules: relative, no `..`
 * segments, no absolute paths (POSIX or Windows), no NUL, forward or single
 * basename form.
 */
export function statementSubjectNameError(name: string): string | undefined {
  if (name.length === 0) return "subject name must be non-empty";
  if (name.includes("\0")) return "subject name must not contain NUL";
  if (name.startsWith("/") || /^[A-Za-z]:/.test(name)) return "subject name must be relative";
  const segments = name.split(/[\\/]/);
  if (segments.some((s) => s === "..")) return 'subject name must not contain ".." segments';
  return undefined;
}

export function parseStatement(payload: Buffer | string): InTotoStatement {
  const text = typeof payload === "string" ? payload : payload.toString("utf-8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }
  const s = parsed as Partial<InTotoStatement> | null;
  if (s == null || typeof s !== "object") {
    throw new Error("Statement must be a non-null object");
  }
  if (s._type !== IN_TOTO_STATEMENT_TYPE) {
    throw new Error(`unexpected statement _type "${s._type}" (expected "${IN_TOTO_STATEMENT_TYPE}")`);
  }
  if (typeof s.predicateType !== "string" || s.predicateType.length === 0) {
    throw new Error("statement predicateType is required");
  }
  if (!Array.isArray(s.subject) || s.subject.length === 0) {
    throw new Error("statement must contain at least one subject");
  }
  if (s.subject.length > MAX_STATEMENT_SUBJECTS) {
    throw new Error(`statement exceeds ${MAX_STATEMENT_SUBJECTS} subjects`);
  }
  for (const [i, subject] of s.subject.entries()) {
    if (subject == null || typeof subject !== "object" || typeof subject.name !== "string") {
      throw new Error(`subject[${i}] is malformed`);
    }
    const nameErr = statementSubjectNameError(subject.name);
    if (nameErr) throw new Error(`subject[${i}]: ${nameErr}`);
    const sha = subject.digest?.sha256;
    if (typeof sha !== "string" || !/^[0-9a-f]{64}$/.test(sha)) {
      throw new Error(`subject[${i}] (${subject.name}) lacks a valid sha256 digest`);
    }
  }
  return parsed as InTotoStatement;
}

/** Extracts file integrity entries from a parsed Statement's subjects. */
export function statementFileEntries(statement: InTotoStatement): StatementFileEntry[] {
  return statement.subject.map((s) => ({
    path: s.name.replace(/\\/g, "/"),
    sha256: s.digest.sha256,
  }));
}

// ---- nono bundle verification (read-compat) ----

/**
 * Verifies a nono-format attestation bundle: full Sigstore verification and
 * identity pinning (shared with Profile B), then Statement parsing with the
 * nono predicateType allowlist.
 *
 * Supports the keyless shape (certificate verification material). nono's
 * KEYED shape (raw ECDSA P-256 public-key hint, no certificate) is not yet
 * supported - see docs/nono-interop.md.
 */
export async function verifyNonoBundle(
  bundleContent: Buffer | string,
  identities: TrustedIdentity[],
  options: SigstoreVerifyOptions = {},
): Promise<NonoVerification> {
  const verification = await verifySigstoreBundle(bundleContent, identities, options);
  if (!verification.valid) {
    return {
      valid: false,
      reason: verification.reason,
      identity: verification.identity,
      issuer: verification.issuer,
    };
  }

  if (verification.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    return {
      valid: false,
      reason: `unexpected payloadType "${verification.payloadType}" (expected "${IN_TOTO_PAYLOAD_TYPE}")`,
    };
  }

  let statement: InTotoStatement;
  try {
    statement = parseStatement(verification.payload!);
  } catch (e) {
    return { valid: false, reason: `invalid in-toto statement: ${(e as Error).message}` };
  }

  if (
    statement.predicateType !== NONO_PREDICATE_MULTI &&
    statement.predicateType !== NONO_PREDICATE_SINGLE
  ) {
    return {
      valid: false,
      reason: `unrecognized predicateType "${statement.predicateType}"`,
      predicateType: statement.predicateType,
    };
  }

  return {
    valid: true,
    publisher: verification.publisher,
    identity: verification.identity,
    issuer: verification.issuer,
    predicateType: statement.predicateType,
    files: statementFileEntries(statement),
    warning: REDUCED_GUARANTEE_WARNING,
  };
}
