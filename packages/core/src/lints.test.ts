// Sign-time content lints (SPEC v2 6.7): Unicode Tag smuggling, zero-width
// characters, bidi overrides. Default blocks signing; --allow-lint records
// the exception in the manifest attestation.

import { describe, it, expect } from "vitest";
import { lintContent, buildLintAttestation, LINT_RULES } from "./lints.js";
import type { LintHit, LintRule } from "./lints.js";

describe("lintContent", () => {
  it("returns no hits for clean markdown", () => {
    expect(lintContent("# Title\n\nNormal **markdown** content.\n")).toEqual([]);
  });

  it("detects Unicode Tag block characters (the SKILL.md injection vector)", () => {
    // U+E0041 TAG LATIN CAPITAL LETTER A embedded mid-text
    const text = `benign${String.fromCodePoint(0xe0041)}text`;
    const hits = lintContent(text);
    expect(hits).toHaveLength(1);
    expect(hits[0].rule).toBe("unicode_tags");
    expect(hits[0].codePoint).toBe(0xe0041);
  });

  it("detects zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner, ZWNBSP)", () => {
    for (const cp of [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]) {
      const hits = lintContent(`a${String.fromCodePoint(cp)}b`);
      expect(hits.map((h) => h.rule)).toEqual(["zero_width"]);
    }
  });

  it("detects bidirectional override controls", () => {
    for (const cp of [0x202a, 0x202e, 0x2066, 0x2069]) {
      const hits = lintContent(`x${String.fromCodePoint(cp)}y`);
      expect(hits.map((h) => h.rule)).toEqual(["bidi_controls"]);
    }
  });

  it("reports line numbers", () => {
    const text = `line one\nline two${String.fromCodePoint(0x200b)}\nline three`;
    const hits = lintContent(text);
    expect(hits[0].line).toBe(2);
  });

  it("decodes Buffers as UTF-8", () => {
    const buf = Buffer.from(`a${String.fromCodePoint(0xe0041)}b`, "utf-8");
    expect(lintContent(buf).map((h) => h.rule)).toEqual(["unicode_tags"]);
  });
});

describe("buildLintAttestation", () => {
  const hit = (rule: LintRule): LintHit => ({ rule, codePoint: 0x200b, index: 0, line: 1 });

  it("attests every rule 'absent' when there are no hits", () => {
    const attestation = buildLintAttestation(new Map());
    expect(attestation).toEqual({
      unicode_tags: "absent",
      zero_width: "absent",
      bidi_controls: "absent",
    });
    expect(Object.keys(attestation).sort()).toEqual([...LINT_RULES].sort());
  });

  it("THROWS (blocks signing) when hits exist for a non-allowed rule", () => {
    const hits = new Map([["SKILL.md", [hit("zero_width")]]]);
    expect(() => buildLintAttestation(hits)).toThrow(/content lints failed.*zero_width.*SKILL\.md/s);
  });

  it("records 'allowed' when the rule was explicitly allowed", () => {
    const hits = new Map([["SKILL.md", [hit("zero_width")]]]);
    const attestation = buildLintAttestation(hits, new Set<LintRule>(["zero_width"]));
    expect(attestation.zero_width).toBe("allowed");
    expect(attestation.unicode_tags).toBe("absent");
  });

  it("still blocks other rules when only one is allowed", () => {
    const hits = new Map([["SKILL.md", [hit("zero_width"), hit("unicode_tags")]]]);
    expect(() => buildLintAttestation(hits, new Set<LintRule>(["zero_width"]))).toThrow(
      /unicode_tags/,
    );
  });
});
