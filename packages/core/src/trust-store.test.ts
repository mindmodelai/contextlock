import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TrustStore, TrustedPublisher, TrustStoreData } from "./trust-store.js";
import { writeFile, readFile, mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makePublisher(overrides: Partial<TrustedPublisher> = {}): TrustedPublisher {
  return {
    publisher: "test-publisher",
    key_id: "key-001",
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

describe("TrustStore", () => {
  let store: TrustStore;

  beforeEach(() => {
    store = new TrustStore();
  });

  describe("addPublisher / getPublisher / listPublishers", () => {
    it("adds and retrieves a publisher by key_id", () => {
      const pub = makePublisher();
      store.addPublisher(pub);
      expect(store.getPublisher("key-001")).toEqual(pub);
    });

    it("returns undefined for unknown key_id", () => {
      expect(store.getPublisher("nonexistent")).toBeUndefined();
    });

    it("listPublishers returns a copy of the array", () => {
      const pub = makePublisher();
      store.addPublisher(pub);
      const list = store.listPublishers();
      expect(list).toHaveLength(1);
      // Mutating the returned list should not affect the store
      list.pop();
      expect(store.listPublishers()).toHaveLength(1);
    });

    it("supports multiple publishers", () => {
      store.addPublisher(makePublisher({ key_id: "key-001" }));
      store.addPublisher(makePublisher({ key_id: "key-002", publisher: "other" }));
      expect(store.listPublishers()).toHaveLength(2);
      expect(store.getPublisher("key-002")?.publisher).toBe("other");
    });
  });

  describe("removePublisher", () => {
    it("removes a publisher by key_id", () => {
      store.addPublisher(makePublisher({ key_id: "key-001" }));
      store.addPublisher(makePublisher({ key_id: "key-002" }));
      store.removePublisher("key-001");
      expect(store.getPublisher("key-001")).toBeUndefined();
      expect(store.listPublishers()).toHaveLength(1);
    });

    it("does nothing when key_id not found", () => {
      store.addPublisher(makePublisher());
      store.removePublisher("nonexistent");
      expect(store.listPublishers()).toHaveLength(1);
    });
  });

  describe("revokeKey", () => {
    it("sets revoked=true for matching key_id", () => {
      store.addPublisher(makePublisher({ key_id: "key-001", revoked: false }));
      store.revokeKey("key-001");
      expect(store.getPublisher("key-001")?.revoked).toBe(true);
    });

    it("does nothing when key_id not found", () => {
      store.addPublisher(makePublisher({ key_id: "key-001", revoked: false }));
      store.revokeKey("nonexistent");
      expect(store.getPublisher("key-001")?.revoked).toBe(false);
    });
  });

  describe("load / save (file I/O)", () => {
    let tmpDir: string;

    beforeEach(async () => {
      tmpDir = await mkdtemp(join(tmpdir(), "truststore-test-"));
    });

    it("saves and loads trust store data round-trip", async () => {
      const pub = makePublisher();
      store.addPublisher(pub);

      const filePath = join(tmpDir, "truststore.json");
      await store.save(filePath);

      const loaded = new TrustStore();
      await loaded.load(filePath);
      expect(loaded.listPublishers()).toEqual([pub]);
    });

    it("persists schema as contextlock-truststore/2", async () => {
      const filePath = join(tmpDir, "truststore.json");
      await store.save(filePath);

      const raw = await readFile(filePath, "utf-8");
      const parsed = JSON.parse(raw) as TrustStoreData;
      expect(parsed.schema).toBe("contextlock-truststore/2");
      expect(parsed.trusted_publishers).toEqual([]);
    });

    it("loads a legacy tcv-truststore/v1 store and upgrades on save", async () => {
      const pub = makePublisher();
      const filePath = join(tmpDir, "legacy.json");
      await writeFile(
        filePath,
        JSON.stringify({ schema: "tcv-truststore/v1", trusted_publishers: [pub] }),
        "utf-8",
      );

      const loaded = new TrustStore();
      await loaded.load(filePath);
      expect(loaded.listPublishers()).toEqual([pub]);

      await loaded.save(filePath);
      const parsed = JSON.parse(await readFile(filePath, "utf-8")) as TrustStoreData;
      expect(parsed.schema).toBe("contextlock-truststore/2");
    });

    it("rejects invalid schema", async () => {
      const filePath = join(tmpDir, "bad.json");
      await writeFile(filePath, JSON.stringify({ schema: "wrong/v1", trusted_publishers: [] }));

      const loaded = new TrustStore();
      await expect(loaded.load(filePath)).rejects.toThrow("Invalid trust store schema");
    });

    it("rejects invalid JSON", async () => {
      const filePath = join(tmpDir, "bad.json");
      await writeFile(filePath, "not json at all");

      const loaded = new TrustStore();
      await expect(loaded.load(filePath)).rejects.toThrow("Invalid JSON");
    });

    it("rejects non-existent file", async () => {
      const loaded = new TrustStore();
      await expect(loaded.load(join(tmpDir, "missing.json"))).rejects.toThrow();
    });

    // Cleanup
    afterEach(async () => {
      await rm(tmpDir, { recursive: true, force: true });
    });
  });
});
