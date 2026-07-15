/**
 * inspect command — Pretty-print a DSSE envelope's payload (SPEC v2 6.2:
 * answers the "base64 is not human-readable" objection).
 *
 * Inspect DOES NOT verify the signature - it says so loudly. Use `verify`
 * or `install` for trust decisions.
 */

import { readFile } from "node:fs/promises";
import { parseEnvelope, b64Decode } from "@contextlock/core";
import type { DsseEnvelope } from "@contextlock/core";

export interface InspectOptions {
  envelopePath: string;
}

export interface InspectResult {
  envelope: DsseEnvelope;
  payloadType: string;
  /** Parsed payload when it is valid JSON; raw text otherwise. */
  payload: unknown;
  payloadText: string;
  keyIds: string[];
  signatureCount: number;
  displayMessage: string;
}

export async function inspect(options: InspectOptions): Promise<InspectResult> {
  const content = await readFile(options.envelopePath);
  const envelope = parseEnvelope(content);
  const payloadBytes = b64Decode(envelope.payload);
  const payloadText = payloadBytes.toString("utf-8");

  let payload: unknown = payloadText;
  let pretty = payloadText;
  try {
    payload = JSON.parse(payloadText);
    pretty = JSON.stringify(payload, null, 2);
  } catch {
    // Non-JSON payload: show raw text.
  }

  const keyIds = envelope.signatures
    .map((s) => s.keyid)
    .filter((k): k is string => typeof k === "string");

  const displayMessage = [
    `Envelope: ${options.envelopePath}`,
    `  payloadType: ${envelope.payloadType}`,
    `  signatures:  ${envelope.signatures.length}${keyIds.length ? ` (keyid hints: ${keyIds.join(", ")})` : ""}`,
    ``,
    `Payload (signature NOT verified by inspect - use 'contextlock verify'):`,
    pretty,
  ].join("\n");

  return {
    envelope,
    payloadType: envelope.payloadType,
    payload,
    payloadText,
    keyIds,
    signatureCount: envelope.signatures.length,
    displayMessage,
  };
}
