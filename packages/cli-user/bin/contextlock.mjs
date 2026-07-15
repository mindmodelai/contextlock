#!/usr/bin/env node
/**
 * `contextlock` executable - SPEC v2 Phase A user CLI.
 *
 * Thin launcher that dispatches to the compiled dist code. Build the package
 * (`npm run build`) so ./../dist/index.js exists before invoking.
 *
 * Exit codes: 0 = ok, 3 = violations found, 2 = operational error.
 */

import { runCli } from "../dist/index.js";

runCli(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err?.message ?? String(err));
    process.exit(2);
  });
