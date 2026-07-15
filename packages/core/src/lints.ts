/**
 * Sign-time content lints (SPEC v2 6.7).
 *
 * Signing is the right moment to catch content-level smuggling that survives
 * human review. These lints do NOT make signatures mean "safe" - they remove
 * the cheapest known way to make malicious content look reviewed:
 *
 *   - unicode_tags:   U+E0000-E007F (the demonstrated SKILL.md injection vector)
 *   - zero_width:     ZWSP, ZWNJ, ZWJ, word joiner, zero-width no-break space
 *   - bidi_controls:  U+202A-202E, U+2066-2069
 *
 * Default is to BLOCK signing on a hit; `--allow-lint <rule>` records the
 * exception in the manifest's `lints` field so verifiers and humans can see it.
 */

export const LINT_RULES = ["unicode_tags", "zero_width", "bidi_controls"] as const;
export type LintRule = (typeof LINT_RULES)[number];

export interface LintHit {
  rule: LintRule;
  /** The offending code point. */
  codePoint: number;
  /** 0-based code-point index into the decoded text. */
  index: number;
  /** 1-based line number. */
  line: number;
}

const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);

function classify(cp: number): LintRule | undefined {
  if (cp >= 0xe0000 && cp <= 0xe007f) return "unicode_tags";
  if (ZERO_WIDTH.has(cp)) return "zero_width";
  if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) return "bidi_controls";
  return undefined;
}

/**
 * Scans content for smuggling-class code points. Content is decoded as UTF-8
 * when given as a Buffer (files are normalized to UTF-8 at sign time before
 * this runs, SPEC v2 6.1).
 */
export function lintContent(content: Buffer | string): LintHit[] {
  const text = typeof content === "string" ? content : content.toString("utf-8");
  const hits: LintHit[] = [];
  let line = 1;
  let index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    const rule = classify(cp);
    if (rule) {
      hits.push({ rule, codePoint: cp, index, line });
    }
    if (cp === 0x0a) line++;
    index++;
  }
  return hits;
}

/**
 * Builds the manifest `lints` attestation for a set of scanned files.
 *
 * Every known rule is attested: "absent" when no file hit it, "allowed" when
 * hits exist but the rule was explicitly allowed. Throws when hits exist for a
 * rule that was NOT allowed - the caller must not sign in that case.
 */
export function buildLintAttestation(
  hitsByFile: Map<string, LintHit[]>,
  allowedRules: ReadonlySet<LintRule> = new Set(),
): Record<string, string> {
  const rulesHit = new Set<LintRule>();
  for (const hits of hitsByFile.values()) {
    for (const h of hits) rulesHit.add(h.rule);
  }

  const blocked = [...rulesHit].filter((r) => !allowedRules.has(r));
  if (blocked.length > 0) {
    const detail = [...hitsByFile.entries()]
      .flatMap(([file, hits]) =>
        hits
          .filter((h) => blocked.includes(h.rule))
          .map(
            (h) =>
              `${file}:${h.line} ${h.rule} U+${h.codePoint
                .toString(16)
                .toUpperCase()
                .padStart(4, "0")}`,
          ),
      )
      .join("; ");
    throw new Error(
      `content lints failed (${blocked.join(", ")}): ${detail}. ` +
        `Remove the characters or re-run with --allow-lint <rule> to record the exception.`,
    );
  }

  const attestation: Record<string, string> = {};
  for (const rule of LINT_RULES) {
    attestation[rule] = rulesHit.has(rule) ? "allowed" : "absent";
  }
  return attestation;
}
