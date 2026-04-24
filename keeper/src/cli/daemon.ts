#!/usr/bin/env node
/**
 * CLI entrypoint: aegis-committee-daemon
 *
 * One instance per committee member. Env vars:
 *   MATERIOS_RPC_URL         — wss://materios.fluxpointstudios.com/preprod-rpc
 *   CARDANO_OGMIOS_URL       — Ogmios used for halt-detector heartbeats
 *   CARDANO_KUPO_URL         — Kupo used for halt-detector heartbeats
 *   SR25519_URI              — Materios signing key (mnemonic or dev URI)
 *   ED25519_URI              — ed25519 key at `//aegis` derivation (spec §6.2)
 *   DAEMON_STATE_PATH        — ./aegis-daemon-state.json
 */

import { MateriosRpcClient } from "@fluxpointstudios/materios-intent-settlement-sdk";
import { CommitteeDaemon, sanitizeKeyringError } from "../daemon/index.js";
import { createMeshCardanoProvider } from "../cardano.js";

async function main(): Promise<void> {
  const materiosRpcUrl = required("MATERIOS_RPC_URL");
  const ogmiosUrl = required("CARDANO_OGMIOS_URL");
  const kupoUrl = required("CARDANO_KUPO_URL");
  const sr25519Uri = required("SR25519_URI");
  const ed25519Uri = required("ED25519_URI");
  const daemonStatePath = process.env.DAEMON_STATE_PATH ?? "./aegis-daemon-state.json";

  const rpc = new MateriosRpcClient({ rpcUrl: materiosRpcUrl, signerUri: sr25519Uri });
  await rpc.connect();

  const cardano = await createMeshCardanoProvider({
    network: (process.env.NETWORK as "preprod" | "mainnet") ?? "preprod",
    ogmiosUrl,
    kupoUrl,
    enableMainnet: process.env.ENABLE_MAINNET === "1",
  });

  const daemon = new CommitteeDaemon(
    {
      materiosRpcUrl,
      cardanoOgmiosUrl: ogmiosUrl,
      sr25519Uri,
      ed25519Uri,
      daemonStatePath,
      haltDetectSeconds: 60,
      haltRecoverBlocks: 3,
      haltExtensionThresholdSeconds: 24 * 60 * 60,
      pollIntervalMs: 6000,
    },
    {
      rpc,
      getCardanoLatestBlockTimestamp: () => cardano.getLatestBlockTimestamp(),
    },
  );

  process.on("SIGINT", () => {
    daemon.stop();
    rpc.disconnect().finally(() => process.exit(0));
  });

  console.log("[committee-daemon] starting loop");
  await daemon.run();
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
  // Sanitize: connect()/addFromUri errors from @polkadot/keyring can include
  // suri fragments in .message; never echo the raw err to stderr/journald.
  console.error(`[committee-daemon] fatal: ${sanitizeKeyringError(err)}`);
  process.exit(1);
});
