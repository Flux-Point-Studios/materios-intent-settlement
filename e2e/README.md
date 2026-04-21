# Materios Intent-Settlement — E2E Preprod Demo

Wave 2 Team D deliverable. Proves that Teams A + B + C (pallets / Aiken validators / keeper)
are mutually interoperable against the locked interface spec at `docs/spec-v1.md` §7.4.

## TL;DR — 3 commands

```bash
cd e2e
./scripts/setup-preprod.sh       # install deps, probe RPCs, warn on gaps
pnpm demo                         # run the 8-step narrative
./scripts/demo-reel.sh            # same thing, but captures run.log + tx-links for sharing
```

## What the demo does

Maps 1:1 to the 8 bullets in spec §7.4 "Glue (cross-team E2E)":

| Step | Action | On-chain artifact |
|------|--------|------------------|
| 1 | Use Team B's deployed Aiken validator addresses (from `config/preprod.json`) | — |
| 2 | Sign + submit `submit_intent(BuyPolicy)` extrinsic on Materios preprod | `IntentSubmitted` event |
| 3 | Wait for Team C cert-daemon to attest the intent | `IntentAttested` event (≤ 6 blocks) |
| 4 | Request voucher + collect ≥ threshold committee sigs | `VoucherIssued` event |
| 5 | Wait for Team C keeper to batch + submit to Cardano preprod | `ClaimSettled` event on Materios; tx on Cardano |
| 6 | Query Cardano preprod UTxO set; confirm Aiken validator accepted the voucher | Pool-custody UTxO consumed, payout UTxO at beneficiary |
| 7 | Produce `https://preprod.cexplorer.io/tx/<hash>` link for reviewers | `artifacts/demo-*/tx-links.md` |
| 8 | Recompute BFPR math locally; assert byte-match with committee's anchored proof | Audit passes if assertion holds |

Pass criteria (spec §7.4 bullet 9): user's Cardano wallet increases by `payout_ada - keeper_fee`.

## Repo layout

```
e2e/
├── config/
│   ├── preprod.json      # committed; edit once Team B deploys validators
│   └── mainnet.json      # committed placeholder; gated on committee expansion + audit
├── scripts/
│   ├── full-demo.ts      # the TypeScript E2E (pnpm demo)
│   ├── setup-preprod.sh  # one-shot idempotent setup
│   ├── tear-down.sh      # clean local artifacts
│   └── demo-reel.sh      # verbose capture for showcase
├── src/
│   ├── types.ts          # TS mirror of spec §1 types
│   ├── hashing.ts        # Blake2b-256 domain-tagged hashing (spec §1.1)
│   ├── fairness.ts       # BFPR recomputation (spec §1.6)
│   ├── materios.ts       # @polkadot/api helpers (waitForIntentStatus, etc.)
│   ├── cardano.ts        # Kupo/Ogmios helpers (pollCardanoUtxo, etc.)
│   ├── config.ts         # typed loader with mainnet-lockout
│   └── index.ts          # barrel
├── tests/
│   ├── hashing.test.ts   # unit tests (≥80% coverage gate)
│   ├── fairness.test.ts
│   ├── materios.test.ts
│   ├── cardano.test.ts
│   ├── config.test.ts
│   └── e2e.test.ts       # describe.todo narrative; full flow runs when MATERIOS_E2E_LIVE=1
└── vitest.config.ts
```

## Tech stack

- `@polkadot/api` — Materios preprod RPC client
- `@meshsdk/core` — (future) Cardano tx-building if the demo ever builds txs itself; currently the keeper (Team C) builds them and this demo only reads Kupo
- `blake2b` — pure-JS Blake2b-256 for domain-tagged hashing
- `vitest` — unit tests + E2E describe.todo gate
- `tsx` — run the TS demo without a pre-build step

## Prerequisites

- Node ≥ 20
- pnpm (preferred) or npm
- Network access to:
  - `wss://materios.fluxpointstudios.com/preprod-rpc`
  - `https://preprod.saturnswap.io/kupo`
  - `https://preprod.saturnswap.io/ogmios`

## Status (2026-04-20, at Team D handoff)

- Helpers + unit tests: **green**, ≥80% coverage on all orchestration modules.
- `scripts/full-demo.ts`: **scaffold-complete**, will run end-to-end once:
  - Team A PR lands `api.tx.intentSettlement.*` on Materios preprod runtime, AND
  - Team B PR populates `config/preprod.json` with real aegis-validator addresses, AND
  - Team C's keeper service is running on Node-3 for preprod.
- `scripts/setup-preprod.sh` gracefully reports which dependency is still missing.
- `tests/e2e.test.ts` uses `describe.todo(...)` for each of the 8 steps with explicit
  "depends on Team X PR" notes so reviewers see the remaining work at a glance.

Until all three teams land, `pnpm demo` exits 0 with a clear SCAFFOLD MODE banner.
Once config is populated and Materios runtime registers the pallet, re-running the
same command executes the full flow.

## Safety

- Mainnet config (`config/mainnet.json`) is a placeholder. `loadConfig('mainnet')` throws
  unless `MATERIOS_E2E_ALLOW_MAINNET=1` is exported, AND mainnet itself is gated on
  committee expansion to 5-of-11 + formal audit (spec §6.6).
- `tear-down.sh` only touches local artifacts; it never submits txs.
- No ADA is spent by the demo itself — the keeper pays Cardano fees; the Materios
  submitter pays MOTRA gas from pre-funded accounts.
