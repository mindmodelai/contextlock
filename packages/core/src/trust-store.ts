import { readFile, writeFile } from "node:fs/promises";
import {
  signWithLocalKey,
  verifyWithLocalKey,
  canonicalJson,
} from "./localkey.js";

// ---- Interfaces ----

export interface PublisherPolicy {
  default_action: "block" | "warn" | "allow";
  allow_expired_manifest: boolean;
  allow_offline_cached_manifest: boolean;
}

export interface TrustedPublisher {
  publisher: string;
  key_id: string;
  public_key: string;       // base64-encoded Ed25519 public key
  fingerprint: string;       // SHA-256 hex of public key
  revoked: boolean;
  policy: PublisherPolicy;
}

export interface TrustStoreData {
  schema: "tcv-truststore/v1";
  trusted_publishers: TrustedPublisher[];
  /** Machine-local signature over canonicalJson({schema, trusted_publishers}). */
  sig?: { key_fingerprint: string; signature: string };
}

// Warn at most once per unsigned legacy store path.
const warnedLegacyPaths = new Set<string>();

// ---- TrustStore class ----

export class TrustStore {
  private publishers: TrustedPublisher[] = [];

  /**
   * Loads trust store data from a JSON file (SPEC v2 8: signed local state).
   *
   * - Missing file / invalid JSON / bad schema: throws (unchanged from v1).
   * - Signed store: verifies the signature against the machine-local key; a bad
   *   signature is LOUD (throws) and never falls back to empty trust.
   * - Unsigned legacy store: loads with a one-time warning and will be re-signed
   *   on the next save (migration path).
   */
  async load(path: string): Promise<void> {
    const content = await readFile(path, "utf-8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error(`Invalid JSON in trust store file: ${path}`);
    }

    if (
      parsed == null ||
      typeof parsed !== "object" ||
      (parsed as Record<string, unknown>).schema !== "tcv-truststore/v1"
    ) {
      throw new Error(
        `Invalid trust store schema: expected "tcv-truststore/v1"`
      );
    }

    const data = parsed as TrustStoreData;
    const publishers = Array.isArray(data.trusted_publishers)
      ? data.trusted_publishers
      : [];

    if (data.sig && typeof data.sig.signature === "string") {
      const payload = canonicalJson({
        schema: "tcv-truststore/v1",
        trusted_publishers: publishers,
      });
      const { valid } = await verifyWithLocalKey(
        Buffer.from(payload, "utf-8"),
        data.sig.signature,
      );
      if (!valid) {
        throw new Error(
          `Trust store signature invalid: possible tampering (${path})`,
        );
      }
    } else if (!warnedLegacyPaths.has(path)) {
      warnedLegacyPaths.add(path);
      console.warn(
        `[ContextLock] warning: trust store ${path} is unsigned (legacy); it will be signed on next save.`,
      );
    }

    this.publishers = publishers;
  }

  /**
   * Signs and saves the trust store with the machine-local key (SPEC v2 8).
   */
  async save(path: string): Promise<void> {
    const base = {
      schema: "tcv-truststore/v1" as const,
      trusted_publishers: this.publishers,
    };
    const canonical = canonicalJson(base);
    const { signature, keyFingerprint } = await signWithLocalKey(
      Buffer.from(canonical, "utf-8"),
    );
    const data: TrustStoreData = {
      ...base,
      sig: { key_fingerprint: keyFingerprint, signature },
    };
    await writeFile(path, JSON.stringify(data, null, 2), "utf-8");
  }

  /**
   * Adds a trusted publisher entry to the store.
   */
  addPublisher(entry: TrustedPublisher): void {
    this.publishers.push(entry);
  }

  /**
   * Removes a publisher entry by key_id.
   */
  removePublisher(keyId: string): void {
    this.publishers = this.publishers.filter((p) => p.key_id !== keyId);
  }

  /**
   * Finds a publisher entry by key_id.
   */
  getPublisher(keyId: string): TrustedPublisher | undefined {
    return this.publishers.find((p) => p.key_id === keyId);
  }

  /**
   * Marks a key as revoked by key_id.
   */
  revokeKey(keyId: string): void {
    const publisher = this.publishers.find((p) => p.key_id === keyId);
    if (publisher) {
      publisher.revoked = true;
    }
  }

  /**
   * Returns a shallow copy of the publishers array.
   */
  listPublishers(): TrustedPublisher[] {
    return [...this.publishers];
  }
}
