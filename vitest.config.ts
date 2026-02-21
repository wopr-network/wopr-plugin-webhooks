import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    extensions: [".ts", ".js"],
    alias: [
      {
        find: /^(\.\.?\/.*)\.(js)$/,
        replacement: "$1",
      },
    ],
  },
  test: {
    globals: true,
    environment: "node",
    testTimeout: 10000,
    include: ["tests/**/*.test.ts"],
  },
});
