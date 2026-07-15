// Feature: contextlock v2, Mode 0 (Local Seal) properties.
//
// Property S1: Seal round-trip - for arbitrary content, seal(file) then
//   verifySeal(file) = sealed.
// Property S2: Tamper detection - any single-byte flip in the sealed raw
//   content yields seal-modified.
// Property S3: Store signature tampering - editing entries without re-signing
//   makes the store loudly unavailable (never silently unsealed).
//
// All tests point CONTEXTLOCK_HOME at a fresh temp dir; the real
// ~/.contextlock is never touched.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fc from "fast-check";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SealStore } from "./seal.js";

let homeDir: string;
let workDir: string;
let savedHome: string | undefined;

beforeEach(async () => {
  savedHome = process.env.CONTEXTLOCK_HOME;
  homeDir = await mkdtemp(join(tmpdir(), "cl-seal-home-"));
  workDir = await mkdtemp(join(tmpdir(), "cl-seal-work-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
});

afterEach(async () => {
  process.env.CONTEXTLOCK_HOME = savedHome;
  await rm(homeDir, { recursive: true, force: true }).catch(() => {});
  await rm(workDir, { recursive: true, force: true }).catch(() => {});
});

// Content generator: printable strings plus explicit CRLF/BOM cases so the
// write-path normalization is exercised inside the seal flow.
const contentArb = fc
  .tuple(
    fc.string({ minLength: 1, maxLength: 200 }),
    fc.constantFrom("", "\r\n tail", "﻿"),
  )
  .map(([body, decoration]) => decoration + body);

describe("Property S1: Seal round-trip", () => {
  it("seal then verify = sealed for arbitrary content", async () => {
    let counter = 0;
    await fc.assert(
      fc.asyncProperty(contentArb, async (content) => {
        const filePath = join(workDir, `roundtrip-${counter++}.CLAUDE.md`);
        await writeFile(filePath, content, "utf-8");

        const store = new SealStore();
        await store.load();
        const entry = await store.sealFile(filePath, "prop-test");

        const fresh = new SealStore();
        await fresh.load();
        const verdict = await fresh.verifySeal(filePath);

        expect(verdict.status).toBe("sealed");
        expect(verdict.expectedHash).toBe(entry.sha256);
        expect(verdict.actualHash).toBe(entry.sha256);
      }),
      { numRuns: 40 },
    );
  });
});

describe("Property S2: Tamper detection (single byte flip)", () => {
  it("any single-byte flip in sealed raw content yields seal-modified", async () => {
    let counter = 0;
    await fc.assert(
      fc.asyncProperty(
        contentArb,
        fc.nat(),
        fc.integer({ min: 1, max: 255 }),
        async (content, idxSeed, xorMask) => {
          const filePath = join(workDir, `tamper-${counter++}.CLAUDE.md`);
          await writeFile(filePath, content, "utf-8");

          const store = new SealStore();
          await store.load();
          await store.sealFile(filePath);

          // Flip exactly one byte of the (normalized) on-disk content.
          const sealedBytes = Buffer.from(await readFile(filePath));
          const idx = idxSeed % sealedBytes.length;
          sealedBytes[idx] = sealedBytes[idx] ^ xorMask;
          await writeFile(filePath, sealedBytes);

          const verdict = await store.verifySeal(filePath);
          expect(verdict.status).toBe("seal-modified");
          expect(verdict.expectedHash).toBeDefined();
          expect(verdict.actualHash).toBeDefined();
          expect(verdict.actualHash).not.toBe(verdict.expectedHash);
        },
      ),
      { numRuns: 40 },
    );
  });
});

describe("Property S3: Seal store signature tampering is loud", () => {
  it("editing entries without re-signing makes the store unavailable", async () => {
    const filePath = join(workDir, "CLAUDE.md");
    await writeFile(filePath, "# sealed content\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    // Hand-edit the store: change the recorded hash without re-signing.
    const storePath = store.path;
    const raw = JSON.parse(await readFile(storePath, "utf-8"));
    raw.entries[0].sha256 = "0".repeat(64);
    await writeFile(storePath, JSON.stringify(raw, null, 2), "utf-8");

    const tampered = new SealStore();
    await tampered.load();
    expect(tampered.available).toBe(false);
    expect(tampered.unavailableReason).toContain("possible tampering");

    // Every file is unverifiable, not silently unsealed.
    const verdict = await tampered.verifySeal(filePath);
    expect(verdict.status).toBe("store-unavailable");

    // And write operations refuse rather than clobber.
    await expect(tampered.sealFile(filePath)).rejects.toThrow();
  });

  it("corrupt JSON store is unavailable, missing store is empty", async () => {
    const missing = new SealStore();
    await missing.load();
    expect(missing.available).toBe(true);
    expect(missing.listSeals()).toEqual([]);

    await writeFile(missing.path, "{not json", "utf-8");
    const corrupt = new SealStore();
    await corrupt.load();
    expect(corrupt.available).toBe(false);
    expect(corrupt.unavailableReason).toContain("possible tampering");
  });

  it("unseal removes the entry and persists", async () => {
    const filePath = join(workDir, "AGENTS.md");
    await writeFile(filePath, "# agents\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);
    expect((await store.verifySeal(filePath)).status).toBe("sealed");

    const removed = await store.unsealFile(filePath);
    expect(removed).toBe(true);

    const fresh = new SealStore();
    await fresh.load();
    expect((await fresh.verifySeal(filePath)).status).toBe("unsealed");
  });

  it("seal normalizes CRLF/BOM on disk before hashing (write path)", async () => {
    const filePath = join(workDir, "RULES.md");
    await writeFile(filePath, "﻿line one\r\nline two\r\n", "utf-8");

    const store = new SealStore();
    await store.load();
    await store.sealFile(filePath);

    const onDisk = await readFile(filePath);
    expect(onDisk.includes("\r")).toBe(false);
    expect(onDisk[0]).not.toBe(0xef); // BOM gone
    expect((await store.verifySeal(filePath)).status).toBe("sealed");

    // Restoring CRLF endings is a modification, flagged as line-endings-only.
    const crlf = onDisk.toString("utf-8").replace(/\n/g, "\r\n");
    await writeFile(filePath, crlf, "utf-8");
    const verdict = await store.verifySeal(filePath);
    expect(verdict.status).toBe("seal-modified");
    expect(verdict.lineEndingsOnly).toBe(true);
  });
});
