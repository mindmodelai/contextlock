// Anti-rollback state (SPEC v2 6.3, T7): highest-version-seen per
// (package, key), signed store, fail-closed on tampering, fast-forward reset.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { RollbackState } from "./state.js";

let homeDir: string;
let savedHome: string | undefined;
let storePath: string;

beforeEach(async () => {
  savedHome = process.env.CONTEXTLOCK_HOME;
  homeDir = await mkdtemp(join(tmpdir(), "cl-state-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
  storePath = join(homeDir, "state.json");
});

afterEach(async () => {
  process.env.CONTEXTLOCK_HOME = savedHome;
  await rm(homeDir, { recursive: true, force: true });
});

const FP = "f".repeat(64);

describe("RollbackState", () => {
  it("starts empty and accepts any version", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    expect(state.available).toBe(true);
    expect(state.check("pkg", FP, 1)).toEqual({ ok: true });
    expect(state.check("pkg", FP, 999)).toEqual({ ok: true });
  });

  it("rejects versions strictly below the recorded baseline (T7)", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    await state.record("pkg", FP, 7, "Acme");

    const fresh = new RollbackState(storePath);
    await fresh.load();
    expect(fresh.check("pkg", FP, 6)).toEqual({ ok: false, highestSeen: 7 });
    // Equal versions PASS: re-verifying the installed release must work.
    expect(fresh.check("pkg", FP, 7)).toEqual({ ok: true, highestSeen: 7 });
    expect(fresh.check("pkg", FP, 8)).toEqual({ ok: true, highestSeen: 7 });
  });

  it("only raises the baseline, never lowers it", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    await state.record("pkg", FP, 9, "Acme");
    await state.record("pkg", FP, 3, "Acme"); // no-op
    expect(state.check("pkg", FP, 8)).toEqual({ ok: false, highestSeen: 9 });
  });

  it("keys baselines by (package, key): other packages and keys are unaffected", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    await state.record("pkg", FP, 7, "Acme");
    expect(state.check("other-pkg", FP, 1)).toEqual({ ok: true });
    expect(state.check("pkg", "0".repeat(64), 1)).toEqual({ ok: true });
  });

  it("fails CLOSED (unavailable) on hand-edited state", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    await state.record("pkg", FP, 7, "Acme");

    // Tamper: lower the baseline directly in the JSON.
    const raw = JSON.parse(await readFile(storePath, "utf-8"));
    raw.entries[0].highest_version = 1;
    await writeFile(storePath, JSON.stringify(raw), "utf-8");

    const tampered = new RollbackState(storePath);
    await tampered.load();
    expect(tampered.available).toBe(false);
    expect(tampered.unavailableReason).toMatch(/signature invalid|tampering/);
  });

  it("fails CLOSED on malformed JSON", async () => {
    await writeFile(storePath, "{not json", "utf-8");
    const state = new RollbackState(storePath);
    await state.load();
    expect(state.available).toBe(false);
  });

  it("resetPublisher clears baselines for that publisher only (fast-forward recovery)", async () => {
    const state = new RollbackState(storePath);
    await state.load();
    await state.record("pkg-a", FP, 7, "Acme");
    await state.record("pkg-b", FP, 3, "Acme");
    await state.record("pkg-c", FP, 5, "Other");

    const removed = await state.resetPublisher("Acme");
    expect(removed).toBe(2);
    expect(state.check("pkg-a", FP, 1)).toEqual({ ok: true });
    expect(state.check("pkg-c", FP, 1)).toEqual({ ok: false, highestSeen: 5 });
  });
});
