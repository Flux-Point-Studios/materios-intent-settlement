# Materios MOTRA checkpoint integration

The bond dispatches use the runtime's configured `WeightInfo`, preserving their
operational class and fee policy. Materios PR #68 benchmarks the checkpoint
path on Gemtek (AMD Ryzen 7 7730U): 23,885,000 execution ref_time, one database
read and one write. The RocksDB floor makes the per-account surcharge
148,885,000 ref_time with a 3,533-byte `MaxEncodedLen` proof bound.

| Dispatch | Checkpoint budget | Before ref_time / proof | After ref_time / proof |
| --- | ---: | ---: | ---: |
| `post_settlement_bond` | 1 | 1,100,000,000 / 42,000 | 648,885,000 / 3,533 |
| `release_settlement_bond` | 1 | 1,100,000,000 / 42,000 | 648,885,000 / 3,533 |
| `slash_bad_settlement_evidence` | 4 | 2,900,000,000 / 168,000 | 1,095,540,000 / 14,132 |

The existing 500,000,000 base is unchanged. Reserve/unreserve affect one free
balance. Slash retains its bound for two repatriations. The test runtime's
`BondWeights` matches these integration examples; tests also assert the actual
dispatch information preserves the configured weight, class and fee policy.
The host runtime owns its checkpoint implementation; this pallet has no MOTRA
dependency.

The benchmark, generated weight, raw samples and reproduction command are in
[Materios PR #68](https://github.com/Flux-Point-Studios/materios/pull/68).
