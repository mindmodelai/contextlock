import { readFile, writeFile } from "node:fs/promises";

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
}

// ---- TrustStore class ----

export class TrustStore {
  private publishers: TrustedPublisher[] = [];

  /**
   * Loads trust store data from a JSON file.
   * Validates that the schema is "tcv-truststore/v1".
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
    this.publishers = Array.isArray(data.trusted_publishers)
      ? data.trusted_publishers
      : [];
  }

  /**
   * Saves the current trust store data to a JSON file as pretty-printed JSON.
   */
  async save(path: string): Promise<void> {
    const data: TrustStoreData = {
      schema: "tcv-truststore/v1",
      trusted_publishers: this.publishers,
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
