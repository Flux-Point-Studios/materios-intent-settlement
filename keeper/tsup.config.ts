import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "daemon/index": "src/daemon/index.ts",
    "cli/keeper": "src/cli/keeper.ts",
    "cli/daemon": "src/cli/daemon.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: "node20",
  platform: "node",
  external: ["@meshsdk/core", "@polkadot/api", "@polkadot/keyring"],
});
