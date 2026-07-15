// Trust store hardening (SPEC v2 8): machine-local signing, legacy migration,
// and loud failure on tampering. Never an empty-trust fallback.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { TrustStore } from "./trust-store.js";
import type { TrustedPublisher } from "./trust-store.js";

function makePublisher(overrides: Partial<TrustedPublisher> = {}): TrustedPublisher {
  return {
    publisher: "signing-test-publisher",
    key_id: "key-sign-001",
    public_key: "dGVzdC1rZXk=",
    fingerprint: "abcdef1234567890",
    revoked: false,
    policy: {
      default_action: "block",
      allow_expired_manifest: false,
      allow_offline_cached_manifest: false,
    },
    ...overrides,
  };
}

let homeDir: string;
let workDir: string;
let savedHome: string | undefined;

beforeEach(async () => {
  savedHome = process.env.CONTEXTLOCK_HOME;
  homeDir = await mkdtemp(join(tmpdir(), "cl-ts-home-"));
  workDir = await mkdtemp(join(tmpdir(), "cl-ts-work-"));
  process.env.CONTEXTLOCK_HOME = homeDir;
  process.env.CONTEXTLOCK_SKIP_ACL = "1";
});

afterEach(async () => {
  process.env.CONTEXTLOCK_HOME = savedHome;
  await rm(homeDir, { recursive: true, force: true }).catch(() => {});
  await rm(workDir, { recursive: true, force: true }).catch(() => {});
});

describe("TrustStore signing (SPEC v2 8)", () => {
  it("save() writes a machine-local signature; load() verifies it", async () => {
    const path = join(workDir, "truststore.json");
    const store = new TrustStore();
    store.addPublisher(makePublisher());
    await store.save(path);

    const raw = JSON.parse(await readFile(path, "utf-8"));
    expect(raw.sig).toBeDefined();
    expect(typeof raw.sig.signature).toBe("string");
    expect(raw.sig.key_fingerprint).toMatch(/^[0-9a-f]{64}$/);

    const loaded = new TrustStore();
    await loaded.load(path);
    expect(loaded.listPublishers()).toHaveLength(1);
    expect(loaded.getPublisher("key-sign-001")).toBeDefined();
  });

  it("tampered signed store (entries edited, no re-sign) fails LOUD, never empty-trust", async () => {
    const path = join(workDir, "truststore.json");
    const store = new TrustStore();
    store.addPublisher(makePublisher());
    await store.save(path);

    // Attacker adds a publisher without the machine-local key.
    const raw = JSON.parse(await readFile(path, "utf-8"));
    raw.trusted_publishers.push(makePublisher({ key_id: "evil-key", publisher: "Evil" }));
    await writeFile(path, JSON.stringify(raw, null, 2), "utf-8");

    const loaded = new TrustStore();
    await expect(loaded.load(path)).rejects.toThrow(/signature invalid|tampering/i);
  });

  it("unsigned legacy store loads with a one-time warning and re-signs on next save (migration)", async () => {
    const path = join(workDir, "legacy-truststore.json");
    const legacy = {
      schema: "tcv-truststore/v1",
      trusted_publishers: [makePublisher()],
    };
    await writeFile(path, JSON.stringify(legacy, null, 2), "utf-8");

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const store = new TrustStore();
      await store.load(path); // must not throw
      expect(store.listPublishers()).toHaveLength(1);
      expect(
        warnSpy.mock.calls.some((c) => String(c[0]).includes("unsigned")),
      ).toBe(true);

      // Migration: saving signs the store.
      await store.save(path);
      const raw = JSON.parse(await readFile(path, "utf-8"));
      expect(raw.sig).toBeDefined();

      // And the signed store round-trips.
      const again = new TrustStore();
      await again.load(path);
      expect(again.listPublishers()).toHaveLength(1);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("corrupt store is a loud error (no empty-trust fallback)", async () => {
    const path = join(workDir, "corrupt.json");
    await writeFile(path, "definitely { not json", "utf-8");
    const store = new TrustStore();
    await expect(store.load(path)).rejects.toThrow("Invalid JSON");
  });
});
