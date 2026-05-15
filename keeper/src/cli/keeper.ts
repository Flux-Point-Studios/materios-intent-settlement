#!/usr/bin/env node
/**
 * CLI entrypoint: materios-keeper
 *
 * Env vars:
 *   MATERIOS_RPC_URL       — wss://materios.fluxpointstudios.com/preprod-rpc
 *   CARDANO_OGMIOS_URL     — wss://ogmios.saturnswap.io  (preprod: wss://ogmios-preprod.saturnswap.io)
 *   CARDANO_KUPO_URL       — https://kupo.saturnswap.io  (preprod: https://kupo-preprod.saturnswap.io)
 *   KEEPER_MNEMONIC        — sr25519 mnemonic for Materios settle_claim extrinsics.
 *                            MUST be a current committee member: pallet's
 *                            settle_claim gate requires the caller's pubkey to
 *                            appear in the signature bundle (pallet issue #7,
 *                            wave 2 W2.1). Ship as M=1 for now; multi-operator
 *                            sig collection is wave 2 W2.b follow-up.
 *   KEEPER_CARDANO_ADDR    — Cardano addr that receives keeper fee output
 *   POLICY_SCRIPT_CBOR     — compiled aegis-policy-v1 CBOR (hex)
 *   AEGIS_POLICY_V1_SCRIPT_HASH — REQUIRED, 28-byte (56-hex) blake2b_224 hash of
 *                            POLICY_SCRIPT_CBOR. Task #76a: keeper refuses to
 *                            start if `blake2b_224(0x03 || cbor) != hash`.
 *                            Operators MUST supply the deployed Aiken
 *                            blueprint hash; mainnet must NEVER silently
 *                            accept an unbound CBOR.
 *   MATERIOS_CHAIN_ID      — #73: 32-byte (66-hex incl. 0x) Materios genesis hash.
 *                            Optional; defaults to chain.getBlockHash(0) at
 *                            startup. Pinning explicitly avoids a wrong-chain
 *                            misconfig surviving an RPC swap.
 *   NETWORK_MAGIC          — Cardano protocol magic; defaults from NETWORK
 *                            (preprod=1, mainnet=764824073).
 *   SETTLEMENT_VERSION     — #73 settlement-protocol semver u32. Default 1.
 *   MAINCHAIN_GENESIS_HASH — Task #266 (mis-sec P0): 32-byte (66-hex incl.
 *                            0x) Cardano genesis hash. Pins preprod vs
 *                            mainnet on the new attested-settle path so
 *                            the keeper's `SettlementEvidence` cannot land
 *                            on the wrong network. Required.
 *   MIN_FINALITY_DEPTH     — Task #266 (mis-sec P0): minimum Cardano-block
 *                            depth before request_settle fires. Default 15
 *                            (matches the runtime constant).
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
  // Task #76a: AEGIS_POLICY_V1_SCRIPT_HASH is REQUIRED. The Keeper
  // constructor cross-checks blake2b_224(0x03||cbor) against this value
  // and refuses to start on mismatch — we surface a clear env-var error
  // here too in case of typo (otherwise the constructor's
  // PolicyScriptHashMismatchError is the only signal).
  const aegisPolicyV1ScriptHash = required("AEGIS_POLICY_V1_SCRIPT_HASH") as `0x${string}`;
  const network = (process.env.NETWORK ?? "preprod") as "preprod" | "mainnet";
  const statePath = process.env.KEEPER_STATE_PATH ?? "./keeper-state.json";
  const dryRun = process.env.DRY_RUN === "1";

  // #73 chain-identity defaults. Operators can override any of these via
  // env var; without overrides we resolve `materiosChainId` from the
  // genesis block hash (queried below after rpc.connect()) and pick
  // sensible Cardano-network-specific defaults for the rest.
  const settlementVersion = process.env.SETTLEMENT_VERSION
    ? Number.parseInt(process.env.SETTLEMENT_VERSION, 10)
    : 1;
  const networkMagic = process.env.NETWORK_MAGIC
    ? Number.parseInt(process.env.NETWORK_MAGIC, 10)
    : network === "mainnet"
      ? 764824073
      : 1;
  // Task #266 (mis-sec P0): Cardano genesis pin + finality floor for
  // the new attested-settle pair. The genesis hash is REQUIRED — there
  // is no sensible default because preprod and mainnet have distinct
  // values and a misconfig could send evidence to the wrong runtime.
  const mainchainGenesisHash = required("MAINCHAIN_GENESIS_HASH") as `0x${string}`;
  const minFinalityDepth = process.env.MIN_FINALITY_DEPTH
    ? Number.parseInt(process.env.MIN_FINALITY_DEPTH, 10)
    : 15;

  const rpc = new MateriosRpcClient({ rpcUrl: materiosRpcUrl, signerUri: keeperMnemonic });
  await rpc.connect();

  // Resolve `materiosChainId`: prefer env (pinned in deployment config),
  // fall back to genesis block hash. Querying the chain at startup is
  // more reliable than a user-typed hex string surviving redeploys, but
  // either source ends up baked into every committee-signed digest.
  let materiosChainId = (process.env.MATERIOS_CHAIN_ID ?? "") as `0x${string}`;
  if (!materiosChainId || !materiosChainId.startsWith("0x")) {
    const api = rpc.getApi();
    const genesisHash = await api.rpc.chain.getBlockHash(0);
    materiosChainId = genesisHash.toHex() as `0x${string}`;
  }

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
      aegisPolicyV1ScriptHash,
      materiosChainId,
      networkMagic,
      settlementVersion,
      mainchainGenesisHash,
      minFinalityDepth,
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
