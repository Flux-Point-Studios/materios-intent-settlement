# Runtime Currency weight integration

The bond dispatches use the host runtime's configured `WeightInfo`. A runtime
whose `Currency` implementation performs extra work on balance changes must
include that work in these weights. This pallet has no MOTRA dependency.

| Dispatch | Currency work to budget |
| --- | --- |
| `post_settlement_bond` | One reserve |
| `release_settlement_bond` | One unreserve |
| `slash_bad_settlement_evidence` | Two reserved-balance repatriations |

Materios wraps these base weights with its current MOTRA checkpoint costs.
Its benchmark, generated weights, proof bounds and raw samples are maintained
in [Materios PR #68](https://github.com/Flux-Point-Studios/materios/pull/68).
The pallet tests use deliberately synthetic weights to verify runtime wiring;
these values are not performance estimates or Materios configuration.

`Operational` and `Pays::No` are dispatch metadata. They do not establish the
actual fee policy of a host runtime: Materios' `ChargeMotra` does not implement
fee exemption from `Pays::No`. Fee behavior must be tested in the host runtime.
