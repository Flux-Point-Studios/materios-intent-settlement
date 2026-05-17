# materios-intent-settlement

**Trustless, oracle-marked DeFi primitives for Cardano.** Substrate FRAME pallets, off-chain keeper, TypeScript SDK, and a live preprod chain to build against.

Built by [Flux Point Studios](https://fluxpointstudios.com).

## What's in this repo

| Path | Purpose |
|---|---|
| `pallets/intent-settlement/` | Intent → claim → settle → bond → slash pipeline (the Cardano-DeFi intent primitive) |
| `pallets/perp-engine/` | Permissionless oracle-marked perpetual futures (open / close / liquidate / settle_funding / keeper bond) |
| `pallets/oracle/` | M-of-N attested median price oracle with monotonic slot gate (MON Phase 1) |
| `pallets/committee-governance/` | Cardano-mirrored committee + bonded membership |
| `keeper/` | Off-chain TypeScript keeper that drives `settle_claim` / `attest_settle` two-phase + L1 verification |
| `sdk/` | Client SDK for dApps consuming the primitive |
| `e2e/` | End-to-end integration tests + preprod demo |
| `docs/spec-v1.md` | Authoritative spec |
| `docs/design/` | Locked design memos (perp-engine v0, settle_claim L1 verification, MON Phase 1) |
| `runtime-upgrades/` | Reference runtime-upgrade ceremony scripts (adapt to your own chain) |

## Status (2026-05-16)

- **Live on Materios preprod** at spec_version 227 (chain ID `0x0e46e33f639a56cc8780fd871d9a15e16d99af248526f907cb560cb40849f7bf`).
- **`pallet-intent-settlement`** — `submit_intent` / `attest_intent` / `request_voucher` / `request_settle` / `attest_settle` / `post_settlement_bond` / `slash_bad_settlement_evidence` / `release_settlement_bond` all live. First autonomous on-chain slash fired 2026-05-16.
- **`pallet-perp-engine` v0** — full dispatch surface (`open_position` / `close_position` / `deposit_margin` / `withdraw_margin` / `adjust_leverage` / `liquidate` / `settle_funding` / `governance_set_market` / `reserve_keeper_bond` / `release_keeper_bond`). ADA-PERP/USD market registered, first end-to-end liquidation settled on chain 2026-05-16.
- **`pallet-oracle`** — 5 pairs (ADA / BTC / ETH / USDT / USDC) live with M=3 attestor quorum, ~60s update cadence.
- **Cardano L1 anchoring** — every certified availability batch checkpoints to Cardano under metadata label 8746 (~30s cadence).

Watch the live perp-engine demo at <https://materios-perp.fluxpointstudios.com/?mode=live>.

## Quickstart

### Build + test
```bash
git clone https://github.com/Flux-Point-Studios/materios-intent-settlement
cd materios-intent-settlement
cargo test --workspace
```

### Build against live preprod
```ts
import { ApiPromise, WsProvider } from "@polkadot/api";

const api = await ApiPromise.create({
  provider: new WsProvider("wss://materios.fluxpointstudios.com/preprod-rpc"),
});
```

- **Preprod RPC:** `wss://materios.fluxpointstudios.com/preprod-rpc`
- **Faucet:** ping [@fluxpointstudios](https://x.com/fluxpointstudios) for preprod MOTRA, or drop in the FPS Discord.
- **Block explorer:** any polkadot.js-compatible explorer pointed at the RPC above.

### Run the keeper
See `keeper/README.md`. The keeper expects `MATERIOS_RPC_URL` + `KEEPER_MNEMONIC` env vars. Bonded settlement keepers earn `settlement_keeper_share` of any successful slash.

## What you can build on top

- **Perp DEXes** — `pallet-perp-engine` gives you oracle-marked perps with permissionless liquidations and on-chain margin/funding accounting. Drop in a CLOB or AMM front-end and you have a working derivatives venue.
- **Prediction markets** — register a binary feed via `pallet-oracle.register_attestor` + `submit_price`, settle via `submit_intent` → `attest_intent` → `request_voucher`. Cardano-anchored receipts give you cryptographic settlement proofs.
- **Parametric insurance** — same pipeline, oracle-driven payouts. The Aegis project (cross-repo) is the reference implementation.
- **Anything oracle-marked + bonded** — the M-of-N quorum + bond + slash pattern is reusable. Fork `pallet-perp-engine` for a starting point.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) (pallets) and [MIT](LICENSE-MIT) (SDK / keeper / e2e). Contributions accepted under both licenses unless otherwise noted.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). TL;DR: open an issue first for non-trivial changes, branch off `main`, run `cargo test --workspace`, every PR runs through security review before merge.

## Security

Vulnerabilities → `security@fluxpointstudios.com`. Full disclosure policy in [SECURITY.md](SECURITY.md). **Do not** open public issues for security bugs. This codebase has not yet been independently audited; see SECURITY.md for the internal-review status and known limitations.
