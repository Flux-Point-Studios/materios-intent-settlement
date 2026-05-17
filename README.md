# materios-intent-settlement

**Trustless DeFi primitives for Cardano.** Substrate FRAME pallets + TypeScript SDK + off-chain keeper + e2e harness, settling on a live Cardano-anchored preprod chain you can build against today.

Built by [Flux Point Studios](https://fluxpointstudios.com).

## What this repo gives you

Four production Substrate pallets that together form a permissionless-keeper, M-of-N-attested, Cardano-anchored settlement layer:

| Crate | LoC | Surface | What it does |
|---|---:|---|---|
| `pallets/intent-settlement` | 8.9k | 22 extrinsics | Intent → attest → voucher → settle → bond → slash pipeline. Both legacy single-shot (`settle_claim`) and split B+D (`request_settle` + `attest_settle` + bond/slash) paths live. |
| `pallets/perp-engine` | 3.5k | 10 extrinsics | Oracle-marked perpetual futures: deposit/withdraw margin, open/close positions, adjust leverage, permissionless `liquidate`, pull-based `settle_funding`, governance-gated market registration, bonded keeper slot. |
| `pallets/oracle` | 1.1k | 2 extrinsics | M-of-N attested median price oracle. `register_attestor` (governance) + `submit_price` (attestor). Monotonic slot gate, configurable quorum, freshness window. |
| `pallets/committee-governance` | 0.5k | 8 extrinsics | Cardano-mirrored committee + threshold + key rotation. Timelocked proposals, optional mirror-to-Cardano for SPO-based audit. |

Plus:
- **`sdk/`** (~5.3k LoC TS) — `IntentSettlementClient` with builders, canonical SCALE/CBOR payload hashing, CIP-0019 Cardano address helpers, fee helpers, network configs. Targets `polkadot-stable2409-4`.
- **`keeper/`** (~4.4k LoC TS) — committee-operated relayer: voucher signature verifier, Cardano-side mint via Lucid, M-of-N attestation aggregation, halt-mode + retry/slot-retry, daemon mode, CLI mode.
- **`e2e/`** — 8-step preprod demo (spec §7.4) that drives `submit_intent` → committee attest → voucher mint on Cardano → settlement → cexplorer tx-link capture. Run `pnpm demo` from `e2e/`.
- **`docs/`** — `spec-v1.md` (authoritative), 3 locked design memos in `docs/design/` (perp-engine v0, settle_claim L1 verification, MON Phase 1 oracle), decisions logs, test vectors.
- **`runtime-upgrades/`** — reference 2-of-3-multisig sudo ceremony scripts (env-var parameterized; adapt to your own chain).

## Status — live on preprod, spec_version 227

Genesis: `0x0e46e33f639a56cc8780fd871d9a15e16d99af248526f907cb560cb40849f7bf`. Substrate pinned to `polkadot-stable2409-4`.

**What's exercised on chain (not just merged):**

- ✅ Full intent pipeline: `submit_intent` → 2× `attest_intent` → `request_voucher` → committee mint on Cardano → `request_settle` → 2× `attest_settle` → settlement on Materios + Cardano.
- ✅ Split B+D settlement bond + slash: bait claim slashed autonomously at block #206180 on 2026-05-16. Watcher daemon detects bad evidence, M-of-N committee signs `slash_bad_settlement_evidence`, treasury share + watcher share paid on chain.
- ✅ Perp engine v0: ADA-PERP/USD market live, Alice opened+closed a 1.0 ADA long (PnL=0 since mark unchanged), then a separate 0.5 ADA long was opened, oracle crashed -40%, keeper fired `liquidate()` and settled bad_debt + keeper_fee on chain.
- ✅ Oracle: 5 ADA/BTC/ETH/USDT/USDC pairs publishing every ~60s with M=3 attestor quorum (3 attestors registered; threshold matches `submit_price` validation).
- ✅ Cardano L1 anchoring: every certified availability batch checkpoints to Cardano preprod under metadata label 8746 (anchor-worker live, ~30s cadence).

**Live perp demo:** <https://materios-perp.fluxpointstudios.com/?mode=live> — one-button cinematic end-to-end liquidation against real preprod. ~130s, real extrinsics, cexplorer tx-links on completion.

## Quickstart

### Build + test locally

```bash
git clone https://github.com/Flux-Point-Studios/materios-intent-settlement
cd materios-intent-settlement
cargo test --workspace          # 381 tests, ~10 min cold / ~30s warm
```

CI also runs `cargo check --workspace`, `cargo fmt --check`, and the e2e unit suite on every PR — see `.github/workflows/`.

### Talk to the live chain (TypeScript)

```ts
import { ApiPromise, WsProvider } from "@polkadot/api";

const api = await ApiPromise.create({
  provider: new WsProvider("wss://materios.fluxpointstudios.com/preprod-rpc"),
});
const head = await api.rpc.chain.getHeader();
console.log("Materios preprod head:", head.number.toNumber());
```

Or use the high-level SDK:

```ts
import { IntentSettlementClient, IntentStatus } from "@fluxpointstudios/materios-intent-settlement-sdk";

const client = new IntentSettlementClient({
  materiosRpcUrl: "wss://materios.fluxpointstudios.com/preprod-rpc",
  signerUri: process.env.MATERIOS_MNEMONIC,
});

const { intentId, txHash } = await client.submitIntent({
  tag: "BuyPolicy",
  productId: ("0x" + "00".repeat(32)) as `0x${string}`,
  strike: 500_000n,
  termSlots: 86400,
  premiumAda: 1_000_000n,
  beneficiaryCardanoAddr: new TextEncoder().encode("addr_test1..."),
});

const settled = await client.pollIntentStatus(intentId, [IntentStatus.Settled, IntentStatus.Expired]);
```

- **Preprod RPC:** `wss://materios.fluxpointstudios.com/preprod-rpc`
- **Genesis hash:** `0x0e46e33f639a56cc8780fd871d9a15e16d99af248526f907cb560cb40849f7bf`
- **Token:** MOTRA (gas, 18 decimals) / MATRA (app-layer balances)
- **Faucet:** ping [@fluxpointstudios](https://x.com/fluxpointstudios) on X or join the FPS Discord
- **Block explorer:** any polkadot.js-compatible explorer pointed at the RPC

### Run the e2e demo against preprod

```bash
cd e2e
pnpm install
./scripts/setup-preprod.sh       # probe RPCs, install deps
pnpm demo                         # the 8-step §7.4 narrative
./scripts/demo-reel.sh            # captures run.log + cexplorer tx-links to artifacts/
```

### Run a permissionless keeper

The `keeper/` crate ships both a CLI mode and a daemon mode. The keeper:

- Verifies M-of-N voucher signatures locally before paying Cardano fees.
- Submits Cardano txs via Lucid with explicit slot-retry + Ogmios+Kupo health checks.
- Sequences nonce-correct Materios extrinsics under a mutex (no nonce races on bursts).
- Halts on configurable error budgets; resumes after operator-issued resume.
- Posts a settlement bond and earns a share of any successful `slash_bad_settlement_evidence`.

Required env: `MATERIOS_RPC_URL`, `KEEPER_MNEMONIC`, plus Cardano-side `OGMIOS_URL` / `KUPO_URL` or `BLOCKFROST_PROJECT_ID`. See inline docs in `keeper/src/cli/keeper.ts` and `keeper/src/cli/daemon.ts`.

## What you can build on top

The primitive is intentionally generic — any oracle-marked, M-of-N-attested, bonded-keeper application maps onto it:

- **Parametric insurance** (the original target, [Aegis](https://github.com/Flux-Point-Studios) is the reference implementation): `BuyPolicy` intents, payouts triggered by oracle evidence, LP pool with utilization caps via `set_pool_utilization`.
- **Perpetual futures DEXes**: `pallet-perp-engine` is a complete v0. Add a CLOB or vAMM front-end, register markets via `governance_set_market`, run keepers.
- **Prediction markets**: a binary feed registered through `pallet-oracle.register_attestor` plus a `BuyPolicy`-shaped intent gives you cryptographically-settled binary markets with Cardano-anchored receipts.
- **Anything M-of-N + bond + slash**: the `post_settlement_bond` → `slash_bad_settlement_evidence` → `release_settlement_bond` pattern is reusable. Fork `pallet-perp-engine` for a starting template.

## Architecture in one diagram

```
  ┌────────────┐        ┌────────────────────┐        ┌───────────────────────┐
  │ Your dApp  │  →     │ Materios Substrate │  →     │ Cardano L1 (preprod) │
  │ (SDK)      │ submit │ (4 pallets, this   │ anchor │ - voucher mint        │
  │            │ intent │  repo)             │ +      │ - label-8746 batch    │
  │            │        │                    │ settle │   checkpoints         │
  └────────────┘        └────────────────────┘        └───────────────────────┘
                              ↑      ↓
                              │ M-of-N attestations + bonded keepers
                              │
                       ┌──────┴──────┐
                       │  Keeper(s)  │  (this repo, keeper/)
                       └─────────────┘
```

## Repository layout

```
pallets/
  intent-settlement/       — 22 extrinsics, ~8.9k LoC
  perp-engine/             — 10 extrinsics, ~3.5k LoC
  oracle/                  — 2 extrinsics, ~1.1k LoC
  committee-governance/    — 8 extrinsics, ~0.5k LoC
sdk/                       — TypeScript client + builders + hashing + fees (~5.3k LoC)
keeper/                    — TS keeper (CLI + daemon, ~4.4k LoC)
e2e/                       — preprod demo + integration tests
docs/
  spec-v1.md               — authoritative spec
  decisions-v1.md          — Wave 2 product decisions
  decisions-v2.md          — Wave 3 (Aegis) open questions
  demo-walkthrough.md      — narrative walkthrough
  committee-expansion-5-of-11.md  — committee growth playbook
  test-vectors.json        — canonical SCALE/CBOR payload fixtures
  design/                  — 3 locked design memos
runtime-upgrades/          — reference multisig-sudo ceremony scripts
.github/workflows/         — rust.yml (check+test) + e2e-preprod.yml
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) (pallets) and [MIT](LICENSE-MIT) (SDK / keeper / e2e). Contributions accepted under both licenses unless otherwise noted.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). TL;DR: open an issue first for non-trivial changes, branch off `main`, run `cargo test --workspace`, every PR runs through internal security review before merge.

## Security

Vulnerabilities → `security@fluxpointstudios.com`. Full disclosure policy in [SECURITY.md](SECURITY.md). **Do not** open public issues for security bugs. This codebase has not yet been independently audited; see SECURITY.md for the internal-review status and known limitations. The settle_claim L1-verification design and perp-engine v0 spec are in `docs/design/` and have each been through multiple sec-review rounds.
