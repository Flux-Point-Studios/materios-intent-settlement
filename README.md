# materios-intent-settlement

Platform primitive for Cardano DeFi intent settlement. Built by Flux Point Studios.

**Status:** Wave 2 build in progress (2026-04-20). See `docs/` for spec + decisions.

## Layout

| Path | Team | Purpose |
|---|---|---|
| `pallets/intent-settlement/` | Team A | `pallet_intent_settlement` (Rust, Substrate FRAME) |
| `pallets/committee-governance/` | Team A | `pallet_committee_governance` (Rust, Substrate FRAME) |
| `keeper/` | Team C | Permissionless off-chain relayer (TypeScript, mesh-js) |
| `sdk/` | Team C | Client SDK for dApps consuming the primitive |
| `e2e/` | Team D | End-to-end integration + preprod demo |
| `docs/` | all | Spec, decisions, interface contracts |

## Cross-repo deliverables

- Aiken validator library (`aegis-policy-v1`): lives in `Flux-Point-Studios/aegis-parametric-insurance-dev` (Team B)

## Authoritative spec

See `docs/spec-v1.md`.

## License

Dual-licensed under Apache-2.0 (pallets) and MIT (SDK / keeper / e2e). See
`LICENSE-APACHE` and `LICENSE-MIT`. Contributions are accepted under both
licenses unless otherwise noted.

## Security

See [`SECURITY.md`](SECURITY.md) for vulnerability disclosure. This codebase
has not yet been independently audited; see SECURITY.md "Status" for the
internal-review status and known limitations.
