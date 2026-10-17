# Runtime Currency weight integration

The bond dispatches use the host runtime's configured `WeightInfo`. A runtime
whose `Currency` implementation performs extra work on balance changes must
include that work in these weights. This pallet has no MOTRA dependency.

| Dispatch | Currency work to budget |
| --- | --- |
| `post_settlement_bond` | One reserve |
| `release_settlement_bond` | One unreserve |
| `slash_bad_settlement_evidence` | Two reserved-balance repatriations |
| `request_settle` | One reserve, plus one unreserve when it replaces an expired bonded request |
| `request_batch_settle(n)` | Per entry, as `request_settle` |
| `supersede_settlement_request` | One unreserve for the displaced bond |

The default `SubstrateWeight` for these six dispatches is measured against the
Materios runtime, whose Balances account store runs MOTRA accrual checkpoints,
so its reads, writes and time already include that checkpoint work. A host
that wraps these weights with an extra per-account checkpoint charge, as
Materios' `WithMotra` does, over-charges by that amount; mapping these six
methods to zero extra accounts removes the double count. A host with a
different Currency must rebenchmark. The pallet tests use deliberately
synthetic weights to verify runtime wiring; these values are not performance
estimates or Materios configuration.

`Operational` and `Pays::No` are dispatch metadata. They do not establish the
actual fee policy of a host runtime: Materios' `ChargeMotra` does not implement
fee exemption from `Pays::No`. Fee behavior must be tested in the host runtime.
