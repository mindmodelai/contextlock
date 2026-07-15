import { readFile, writeFile } from "node:fs/promises";
import {
  signWithLocalKey,
  verifyWithLocalKey,
  canonicalJson,
} from "./localkey.js";
import type { CandidateKey } from "./dsse.js";
import { b64Decode } from "./dsse.js";
import type { RootFile } from "./root.js";
import { rootExpired } from "./root.js";
import type { TrustedIdentity } from "./sigstore.js";

// ---- Interfaces ----

export interface PublisherPolicy {
  default_action: "block" | "warn" | "allow";
  allow_expired_manifest: boolean;
  allow_offline_cached_manifest: boolean;
}

export interface TrustedPublisher {
  publisher: string;
  /** Short key label (minisign-style id, e.g. "cl-acme-2026"). */
  key_id: string;
  public_key: string;       // base64-encoded Ed25519 public key
  fingerprint: string;       // SHA-256 hex of public key
  revoked: boolean;
  policy: PublisherPolicy;
}

export const TRUST_STORE_SPEC = "contextlock-truststore/2" as const;
const LEGACY_TRUST_STORE_SPEC = "tcv-truststore/v1";

export interface TrustStoreData {
  schema: typeof TRUST_STORE_SPEC;
  trusted_publishers: TrustedPublisher[];
  /** Pinned publisher roots (SPEC v2 6.5), keyed by publisher name. */
  roots?: Record<string, RootFile>;
  /** Pinned keyless identities (SPEC v2 5, Profile B). */
  trusted_identities?: TrustedIdentity[];
  /** Machine-local signature over the canonicalJson of the data fields. */
  sig?: { key_fingerprint: string; signature: string };
}

// Warn at most once per unsigned legacy store path.
const warnedLegacyPaths = new Set<string>();

// ---- TrustStore class ----

export class TrustStore {
  private publishers: TrustedPublisher[] = [];
  private roots: Record<string, RootFile> = {};
  private identities: TrustedIdentity[] = [];

  /**
   * Loads trust store data from a JSON file (SPEC v2 8: signed local state).
   *
   * - Missing file / invalid JSON / bad schema: throws.
   * - Signed store: verifies the signature against the machine-local key; a bad
   *   signature is LOUD (throws) and never falls back to empty trust.
   * - Unsigned legacy store: loads with a one-time warning and will be re-signed
   *   on the next save (migration path).
   * - Legacy `tcv-truststore/v1` stores load (with their original signed shape)
   *   and are upgraded to `contextlock-truststore/2` on the next save.
   */
  async load(path: string): Promise<void> {
    const content = await readFile(path, "utf-8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error(`Invalid JSON in trust store file: ${path}`);
    }

    const schema =
      parsed != null && typeof parsed === "object"
        ? (parsed as Record<string, unknown>).schema
        : undefined;
    const isLegacy = schema === LEGACY_TRUST_STORE_SPEC;
    if (schema !== TRUST_STORE_SPEC && !isLegacy) {
      throw new Error(
        `Invalid trust store schema: expected "${TRUST_STORE_SPEC}"`
      );
    }

    const data = parsed as TrustStoreData;
    const publishers = Array.isArray(data.trusted_publishers)
      ? data.trusted_publishers
      : [];
    const roots =
      data.roots != null && typeof data.roots === "object" && !Array.isArray(data.roots)
        ? data.roots
        : {};
    const identities = Array.isArray(data.trusted_identities) ? data.trusted_identities : [];

    if (data.sig && typeof data.sig.signature === "string") {
      // The signed payload mirrors the fields actually present in the file so
      // stores written by earlier versions keep verifying:
      //   tcv-truststore/v1:            {schema, trusted_publishers}
      //   contextlock-truststore/2:     {schema, roots, trusted_publishers}
      //   + Profile B identities:       {schema, roots, trusted_identities, trusted_publishers}
      const payload = isLegacy
        ? canonicalJson({ schema: LEGACY_TRUST_STORE_SPEC, trusted_publishers: publishers })
        : data.trusted_identities !== undefined
          ? canonicalJson({
              schema: TRUST_STORE_SPEC,
              roots,
              trusted_identities: identities,
              trusted_publishers: publishers,
            })
          : canonicalJson({ schema: TRUST_STORE_SPEC, roots, trusted_publishers: publishers });
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
    this.roots = roots;
    this.identities = identities;
  }

  /**
   * Signs and saves the trust store with the machine-local key (SPEC v2 8).
   * Always writes the current `contextlock-truststore/2` schema.
   */
  async save(path: string): Promise<void> {
    const base = {
      schema: TRUST_STORE_SPEC,
      roots: this.roots,
      trusted_identities: this.identities,
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
   * Removes a publisher entry by key_id (label) or fingerprint.
   */
  removePublisher(keyId: string): void {
    this.publishers = this.publishers.filter(
      (p) => p.key_id !== keyId && p.fingerprint !== keyId,
    );
  }

  /**
   * Finds a publisher entry by key_id (label) or fingerprint.
   */
  getPublisher(keyId: string): TrustedPublisher | undefined {
    return this.publishers.find((p) => p.key_id === keyId || p.fingerprint === keyId);
  }

  /**
   * Finds the publisher policy that applies to a publisher display name
   * (used when the verifying key came from a pinned root).
   */
  getPublisherByName(name: string): TrustedPublisher | undefined {
    return this.publishers.find((p) => p.publisher === name);
  }

  /**
   * Marks a key as revoked by key_id (label) or fingerprint.
   */
  revokeKey(keyId: string): void {
    const publisher = this.getPublisher(keyId);
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

  // ---- Roots (SPEC v2 6.5) ----

  /** Pins or replaces the current root for a publisher. */
  setRoot(publisher: string, root: RootFile): void {
    this.roots[publisher] = root;
  }

  getRoot(publisher: string): RootFile | undefined {
    return this.roots[publisher];
  }

  removeRoot(publisher: string): boolean {
    if (this.roots[publisher] === undefined) return false;
    delete this.roots[publisher];
    return true;
  }

  listRoots(): Array<{ publisher: string; root: RootFile }> {
    return Object.entries(this.roots).map(([publisher, root]) => ({ publisher, root }));
  }

  // ---- Keyless identities (SPEC v2 5, Profile B) ----

  /** Pins a keyless identity. Duplicate (identity, issuer) pairs are replaced. */
  addIdentity(entry: TrustedIdentity): void {
    this.identities = this.identities.filter(
      (i) => !(i.identity === entry.identity && i.issuer === entry.issuer),
    );
    this.identities.push(entry);
  }

  /**
   * Removes pinned identities. With only a publisher, removes all of that
   * publisher's identities; with an identity pattern, removes that exact pin.
   * Returns the number removed.
   */
  removeIdentity(publisher: string, identity?: string): number {
    const before = this.identities.length;
    this.identities = this.identities.filter((i) => {
      if (i.publisher !== publisher) return true;
      if (identity !== undefined && i.identity !== identity) return true;
      return false;
    });
    return before - this.identities.length;
  }

  listIdentities(): TrustedIdentity[] {
    return [...this.identities];
  }

  /**
   * Resolves the candidate verification keys for DSSE envelope verification:
   * every pinned publisher key (revoked ones included, so a revoked-key
   * signature is reported as "revoked" and not "unknown") plus every key of
   * every non-expired pinned root. Keys from expired roots are excluded -
   * an expired root must be rotated or re-pinned before its keys verify.
   */
  candidateKeys(now: Date = new Date()): CandidateKey[] {
    const candidates: CandidateKey[] = [];
    for (const p of this.publishers) {
      try {
        candidates.push({
          keyid: p.key_id,
          publicKey: new Uint8Array(b64Decode(p.public_key)),
          publisher: p.publisher,
          revoked: p.revoked,
        });
      } catch {
        // Skip malformed key material rather than aborting resolution.
      }
    }
    for (const [publisher, root] of Object.entries(this.roots)) {
      if (rootExpired(root, now)) continue;
      for (const [keyid, key] of Object.entries(root.keys)) {
        try {
          candidates.push({
            keyid,
            publicKey: new Uint8Array(b64Decode(key.pub)),
            publisher,
            revoked: false,
          });
        } catch {
          // Skip malformed key material.
        }
      }
    }
    return candidates;
  }
}
