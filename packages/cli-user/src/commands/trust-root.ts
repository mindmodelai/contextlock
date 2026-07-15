/**
 * trust root add / trust root update / trust reset — root-of-trust management
 * (SPEC v2 6.5).
 *
 * - `trust root add <publisher> <root-envelope>`: pins a publisher's initial
 *   root (trust-on-first-use, out-of-band fingerprint check recommended).
 *   The envelope must be self-consistent: signed by a threshold of the root's
 *   own keys.
 * - `trust root update <publisher> <root-envelope>`: verifies the TUF rotation
 *   chain (version exactly N+1, thresholds of BOTH old and new keys), replaces
 *   the pinned root, and resets the anti-rollback baseline for the publisher
 *   (fast-forward recovery, TUF 5.3.11).
 * - `trust reset <publisher>`: manual fast-forward recovery - clears the
 *   anti-rollback baselines recorded for a publisher.
 */

import { readFile } from "node:fs/promises";
import {
  TrustStore,
  RollbackState,
  parseEnvelope,
  verifyInitialRoot,
  verifyRootTransition,
} from "@contextlock/core";
import type { RootFile } from "@contextlock/core";

export interface TrustRootOptions {
  publisher: string;
  rootEnvelopePath: string;
  trustStorePath: string;
  stateStorePath?: string;
}

export interface TrustRootResult {
  ok: boolean;
  reason?: string;
  publisher: string;
  root?: RootFile;
  /** Number of anti-rollback baselines cleared (update only). */
  baselinesReset?: number;
}

export async function trustRootAdd(options: TrustRootOptions): Promise<TrustRootResult> {
  const envelope = parseEnvelope(await readFile(options.rootEnvelopePath));
  const verdict = await verifyInitialRoot(envelope);
  if (!verdict.ok) {
    return { ok: false, reason: verdict.reason, publisher: options.publisher };
  }

  const store = new TrustStore();
  try {
    await store.load(options.trustStorePath);
  } catch {
    // Trust store doesn't exist yet — start fresh
  }
  if (store.getRoot(options.publisher)) {
    return {
      ok: false,
      reason: `a root is already pinned for "${options.publisher}"; use trust root update`,
      publisher: options.publisher,
    };
  }
  store.setRoot(options.publisher, verdict.root!);
  await store.save(options.trustStorePath);

  return { ok: true, publisher: options.publisher, root: verdict.root };
}

export async function trustRootUpdate(options: TrustRootOptions): Promise<TrustRootResult> {
  const store = new TrustStore();
  try {
    await store.load(options.trustStorePath);
  } catch (e) {
    return {
      ok: false,
      reason: `cannot load trust store: ${(e as Error).message}`,
      publisher: options.publisher,
    };
  }

  const current = store.getRoot(options.publisher);
  if (!current) {
    return {
      ok: false,
      reason: `no root pinned for "${options.publisher}"; use trust root add first`,
      publisher: options.publisher,
    };
  }

  const envelope = parseEnvelope(await readFile(options.rootEnvelopePath));
  const verdict = await verifyRootTransition(current, envelope);
  if (!verdict.ok) {
    return { ok: false, reason: verdict.reason, publisher: options.publisher };
  }

  store.setRoot(options.publisher, verdict.root!);
  await store.save(options.trustStorePath);

  // Fast-forward recovery: key rotation resets the highest-version-seen
  // baseline for this publisher (SPEC v2 6.5).
  const state = new RollbackState(options.stateStorePath);
  await state.load();
  let baselinesReset = 0;
  if (state.available) {
    baselinesReset = await state.resetPublisher(options.publisher);
  }

  return { ok: true, publisher: options.publisher, root: verdict.root, baselinesReset };
}

export interface TrustResetOptions {
  publisher: string;
  stateStorePath?: string;
}

export interface TrustResetResult {
  ok: boolean;
  reason?: string;
  publisher: string;
  baselinesReset: number;
}

export async function trustReset(options: TrustResetOptions): Promise<TrustResetResult> {
  const state = new RollbackState(options.stateStorePath);
  await state.load();
  if (!state.available) {
    return {
      ok: false,
      reason: state.unavailableReason,
      publisher: options.publisher,
      baselinesReset: 0,
    };
  }
  const baselinesReset = await state.resetPublisher(options.publisher);
  return { ok: true, publisher: options.publisher, baselinesReset };
}
