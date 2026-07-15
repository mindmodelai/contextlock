/**
 * Integration test: `contextlock install` (Layer 1) and trust reset.
 *
 * Verify BEFORE placing files: a valid package installs (files + envelope
 * copied); a tampered package is refused with NOTHING written; installing an
 * older signed release than previously seen is refused as rollback; and
 * `trust reset` (fast-forward recovery) makes the older release acceptable
 * again.
 */

import { describe, it, expect, afterEach } from "vitest";
import { writeFile, rm, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ENVELOPE_FILENAME } from "@contextlock/core";
import { install, trustReset, inspect } from "@contextlock/cli-user";
import {
  makeKeypair,
  writeSignedPackage,
  writeTrustStore,
  uniquePackageName,
} from "../../packages/core/src/testkit.js";
import { createTempDir } from "./helpers.js";

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true }).catch(() => {});
  dirs.length = 0;
});

async function tempDir(prefix: string): Promise<string> {
  const d = await createTempDir(prefix);
  dirs.push(d);
  return d;
}

describe("contextlock install (Layer 1)", () => {
  it("verifies then installs a valid package (files + envelope)", async () => {
    const root = await tempDir("install-ok-");
    const source = join(root, "source");
    const dest = join(root, "dest");
    const kp = await makeKeypair();
    await writeSignedPackage(source, kp, {
      packageName: uniquePackageName("inst"),
      files: { "SKILL.md": "# skill\n", "nested/RULES.md": "# rules\n" },
    });
    const storePath = join(root, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const result = await install({ source, dest, trustStorePath: storePath });

    expect(result.installed).toBe(true);
    expect(result.written.sort()).toEqual([ENVELOPE_FILENAME, "SKILL.md", "nested/RULES.md"].sort());
    expect(await readFile(join(dest, "SKILL.md"), "utf-8")).toBe("# skill\n");
    expect(await readFile(join(dest, "nested/RULES.md"), "utf-8")).toBe("# rules\n");
    expect(existsSync(join(dest, ENVELOPE_FILENAME))).toBe(true);
  });

  it("refuses a tampered package and writes NOTHING", async () => {
    const root = await tempDir("install-tamper-");
    const source = join(root, "source");
    const dest = join(root, "dest");
    const kp = await makeKeypair();
    await writeSignedPackage(source, kp, {
      packageName: uniquePackageName("inst-bad"),
      files: { "SKILL.md": "# original\n" },
    });
    await writeFile(join(source, "SKILL.md"), "# tampered\n", "utf-8");
    const storePath = join(root, "truststore.json");
    await writeTrustStore(storePath, [kp]);

    const result = await install({ source, dest, trustStorePath: storePath });

    expect(result.installed).toBe(false);
    expect(result.verification.ok).toBe(false);
    expect(existsSync(dest)).toBe(false); // nothing written, not even the dir
  });

  it("refuses an unknown-signer package", async () => {
    const root = await tempDir("install-unknown-");
    const source = join(root, "source");
    const kp = await makeKeypair();
    await writeSignedPackage(source, kp, {
      packageName: uniquePackageName("inst-unk"),
      files: { "SKILL.md": "# skill\n" },
    });
    const otherKey = await makeKeypair();
    const storePath = join(root, "truststore.json");
    await writeTrustStore(storePath, [otherKey]);

    const result = await install({ source, dest: join(root, "dest"), trustStorePath: storePath });
    expect(result.installed).toBe(false);
    expect(result.verification.status).toBe("untrusted");
  });

  it("refuses installing an older release (rollback), until trust reset", async () => {
    const root = await tempDir("install-rollback-");
    const kp = await makeKeypair();
    const pkg = uniquePackageName("inst-roll");
    const storePath = join(root, "truststore.json");
    await writeTrustStore(storePath, [kp], { publisherName: "RollPub" });

    const v3 = join(root, "v3");
    const v2 = join(root, "v2");
    await writeSignedPackage(v3, kp, {
      packageName: pkg,
      version: 3,
      publisherName: "RollPub",
      files: { "SKILL.md": "# v3\n" },
    });
    await writeSignedPackage(v2, kp, {
      packageName: pkg,
      version: 2,
      publisherName: "RollPub",
      files: { "SKILL.md": "# v2\n" },
    });

    // Install v3: baseline becomes 3.
    const first = await install({ source: v3, dest: join(root, "dest"), trustStorePath: storePath });
    expect(first.installed).toBe(true);

    // Downgrade attempt to v2: refused as rollback.
    const downgrade = await install({ source: v2, dest: join(root, "dest"), trustStorePath: storePath });
    expect(downgrade.installed).toBe(false);
    expect(downgrade.verification.status).toBe("rollback");

    // Fast-forward recovery: trust reset clears the baseline.
    const reset = await trustReset({ publisher: "RollPub" });
    expect(reset.ok).toBe(true);
    expect(reset.baselinesReset).toBeGreaterThan(0);

    const afterReset = await install({ source: v2, dest: join(root, "dest"), trustStorePath: storePath });
    expect(afterReset.installed).toBe(true);
  });
});

describe("contextlock inspect", () => {
  it("pretty-prints the payload and says the signature is NOT verified", async () => {
    const root = await tempDir("inspect-");
    const kp = await makeKeypair();
    const pkg = uniquePackageName("inspect");
    await writeSignedPackage(root, kp, {
      packageName: pkg,
      files: { "SKILL.md": "# skill\n" },
    });

    const result = await inspect({ envelopePath: join(root, ENVELOPE_FILENAME) });
    expect(result.payloadType).toBe("application/vnd.contextlock.manifest+json");
    expect(result.signatureCount).toBe(1);
    expect(result.keyIds).toEqual([kp.keyId]);
    expect((result.payload as { package: string }).package).toBe(pkg);
    expect(result.displayMessage).toContain("NOT verified");
    expect(result.displayMessage).toContain(pkg);
  });
});
