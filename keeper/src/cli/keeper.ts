#!/usr/bin/env node
/**
 * CLI entrypoint: materios-keeper
 *
 * Env vars:
 *   MATERIOS_RPC_URL       — wss://materios.fluxpointstudios.com/preprod-rpc
 *   CARDANO_OGMIOS_URL     — wss://ogmios.saturnswap.io  (preprod: wss://ogmios-preprod.saturnswap.io)
 *   CARDANO_KUPO_URL       — https://kupo.saturnswap.io  (preprod: https://kupo-preprod.saturnswap.io)
 *   KEEPER_MNEMONIC        — sr25519 mnemonic for Materios settle_claim extrinsics
 *   KEEPER_CARDANO_ADDR    — Cardano addr that receives keeper fee output
 *   POLICY_SCRIPT_CBOR     — compiled aegis-policy-v1 CBOR (hex)
 *   NETWORK                — "preprod" | "mainnet" (mainnet requires ENABLE_MAINNET=1)
 *   KEEPER_STATE_PATH      — path to persisted state (default ./keeper-state.json)
 *   DRY_RUN                — "1" to skip actual Cardano submits
 */

import { MateriosRpcClient } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { Keeper } from "../keeper.js";
import { KeeperStateStore } from "../state.js";
import { createMeshCardanoProvider } from "../cardano.js";
import { sanitizeKeyringError } from "../daemon/index.js";

async function main(): Promise<void> {
  const materiosRpcUrl = required("MATERIOS_RPC_URL");
  const ogmiosUrl = required("CARDANO_OGMIOS_URL");
  const kupoUrl = required("CARDANO_KUPO_URL");
  const keeperMnemonic = required("KEEPER_MNEMONIC");
  const keeperAddr = required("KEEPER_CARDANO_ADDR");
  const policyScriptCbor = required("POLICY_SCRIPT_CBOR") as `0x${string}`;
  const network = (process.env.NETWORK ?? "preprod") as "preprod" | "mainnet";
  const statePath = process.env.KEEPER_STATE_PATH ?? "./keeper-state.json";
  const dryRun = process.env.DRY_RUN === "1";

  const rpc = new MateriosRpcClient({ rpcUrl: materiosRpcUrl, signerUri: keeperMnemonic });
  await rpc.connect();

  const cardano = await createMeshCardanoProvider({
    network,
    ogmiosUrl,
    kupoUrl,
    enableMainnet: process.env.ENABLE_MAINNET === "1",
  });

  const state = await KeeperStateStore.load(statePath);

  const keeper = new Keeper(
    {
      materiosRpcUrl,
      cardanoOgmiosUrl: ogmiosUrl,
      cardanoKupoUrl: kupoUrl,
      keeperMnemonic,
      network,
      confirmationDepthSlots: network === "mainnet" ? 2160 : 120, // preprod: faster confirms
      feeSpikeMaxAttempts: 3,
      feeSpikeBackoffMs: 5000,
      pollIntervalMs: 6000,
      maxBatchSize: 32,
      dryRun,
    },
    {
      rpc,
      cardano,
      state,
      keeperCardanoAddr: keeperAddr,
      policyScriptCbor,
    },
  );

  process.on("SIGINT", () => {
    keeper.stop();
    rpc.disconnect().finally(() => process.exit(0));
  });

  console.log("[keeper] starting loop");
  await keeper.run();
}

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`missing env var ${name}`);
    process.exit(1);
  }
  return v;
}

main().catch((err) => {
  // Sanitize — MateriosRpcClient.connect() wraps addFromUri errors, but any
  // other layer that happens to stringify a KEEPER_MNEMONIC-containing value
  // would still leak here. Always scrub.
  console.error(`[keeper] fatal: ${sanitizeKeyringError(err)}`);
  process.exit(1);
});
