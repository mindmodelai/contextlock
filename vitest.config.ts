import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@contextlock/core": resolve(__dirname, "packages/core/src/index.ts"),
      "@contextlock/cli-publisher": resolve(__dirname, "packages/cli-publisher/src/index.ts"),
      "@contextlock/cli-user": resolve(__dirname, "packages/cli-user/src/index.ts"),
      "@contextlock/adapter-claude-code": resolve(__dirname, "packages/adapter-claude-code/src/index.ts"),
      "@contextlock/adapter-openclaw": resolve(__dirname, "packages/adapter-openclaw/src/index.ts"),
    },
  },
  test: {
    include: [
      "packages/*/src/**/*.test.ts",
      "tests/**/*.test.ts",
    ],
    testTimeout: 30000,
  },
});
