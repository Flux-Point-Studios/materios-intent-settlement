# Settlement request and genesis safety

## Request lifetime

A request is fresh while `now - submitted_block <= SettlementRequestTtl`.
Attestation and slashing use that inclusive boundary. On the next block, an
unattested request can be replaced by either request extrinsic. Replacement
returns any reserve to the original requester before storing the new request.
Batch replacement is atomic, including balance changes and release events.

Anyone can release an expired, unattested, unslashed bond. The funds always go
to its recorded requester. The expired request is removed so release cannot
pay twice. Attested bonds retain the separate `BondReleaseDelayBlocks` rule.
Slashed claims retain their tombstone and cannot be released or replaced.
Slashing operates only on pending requests; successful attestation consumes
that request. Policy-expiry requests use the same replacement boundary so a
stale request cannot wedge the EXPP path after the legacy cutover.

There is no automatic expiry sweep. A failed attestation does not remove a
request. Unused expired requests remain stored until replacement or bonded
release; TTL alone does not bound historical storage growth.

## Fraud-signature binding

Replacement requires request-specific fraud signatures. The old `FRAU` digest
identified a claim but not its request, allowing a previously signed allegation
to be applied to a replacement request's bond. The new digest is:

```text
request_id = blake2_256(SCALE(
    account_to_bytes(requester): [u8; 32],
    submitted_block: u64,
    evidence: SettlementEvidence,
    settled_direct: bool
))
fraud_digest = blake2_256(
    "FRV2" || materios_chain_id || claim_id || request_id || SCALE(fraud_proof)
)
```

The block number is normalized to `u64` independently of the host runtime's
block-number type. The bond amount is excluded so posting the bond does not
change request identity. Signers must read the current on-chain request and
use this digest; old `FRAU` signatures are rejected. Deployment requires a
coordinated update to external slash-watchers and their aggregators before
enactment. No such deployment is performed by this change.

Cross-language vector (byte fills are repeated to the field width): chain
`73`, claim `e7`, requester `77`, submitted block `102`, transaction hash `33`,
depth `15`, slot `123`, beneficiary `22`, amount `1000`, mainchain genesis `65`,
settled-direct `false`, proof `TxNotFound` (SCALE discriminant `01`).

- Request ID: `0f3f88da7a6b6fe85f3e57ad2dcdad53516b8d2490dfd2cc7980c891db39d12e`
- Fraud digest: `a99ffae513bd71d6be7825c6bd7853f816fbf6ec22d1f24b7e312a7926e92437`

## Genesis and upgrades

Fresh genesis writes settlement storage version 3 and both cutovers at block
zero. A zero cutover is immediately closed when its migration version is
already present. On an older chain, a zero cutover keeps its existing meaning
of an unscheduled migration. Nonzero cutovers preserve the upgrade grace
window.

An upgrade over fresh genesis does not relabel STCA settlements or subsequent
expiries as legacy. Storage encodings and call indices remain unchanged.
Existing version-3 preprod state needs no data migration for these fixes;
older versions retain the existing migration sequence.

## Signature work and runtime integration

Every threshold-signature dispatch charges a bounded bundle-length component
in addition to its existing base. Post-dispatch weight retains the base and
the signatures checked, including on failure. Cheap rejection paths return
the unused verification budget. Deposit replay checks precede verification.

The verification benchmark must use real sr25519 verification, not the
benchmark runtime's permissive verifier. Runtime-specific Currency costs
remain in the host's `WeightInfo`; see [Currency integration](motra-checkpoint-weights.md).

Materios PR #68 must re-pin both settlement-repository dependencies to this
PR's merge commit and repeat its runtime integration checks before merging.

### Recorded signature weights

`benchmarking/signature-samples.json` contains 1,200 timing samples: 20 bundle
sizes from 1 through 96, 20 repeats and three external repeats. The benchmark
fills the actual Materios committee to 96, chooses the caller last in the
bundle, and explicitly invokes `Sr25519Verifier`. Membership decoding and
duplicate checks are inside the timed block. Storage tracing records two
unique reads; repeated committee decoding is charged in execution time.

FRAME's maximum regression gives a base of 63,481,676 ps and a slope of
56,931,750 ps/signature. A regression is not an upper bound: the maximum
`ceil((sample_ns * 1000 - base) / signatures)` is 88,324,551 ps/signature.
The checked-in slope rounds that up to **89,000,000 ps/signature**, covering
every recorded sample. Two RocksDB reads are charged separately.

The proof bound sums independent StorageValues, rather than taking only the
largest prefix: `(4 + 3*495) + (3074 + 3*495) = 6,048` bytes. Their maximum
encoded values are the threshold's `u32` and a 96-member committee. The
recorded proof is 3,510 bytes. The regression test checks the time and proof
bounds against the raw samples, and verifies that sampling reaches 96.
Zero checked signatures add no verification component.

These defaults are measured for Materios' committee adapter with at most 96
members. A host with another adapter, a larger committee or a more expensive
DB schedule must override `WeightInfo::threshold_signatures` and rebenchmark.
Currency-specific weights remain the runtime's responsibility.

Reproduce from a scratch Materios checkout with both settlement/oracle Cargo
dependencies pointed at this repository. Serialize these commands under the
shared build lock, use `nice -n 10`, `CARGO_BUILD_JOBS=4`, and a task-specific
`CARGO_TARGET_DIR`:

```bash
cargo build -p materios-runtime --features runtime-benchmarks
frame-omni-bencher v1 benchmark pallet \
  --runtime "$CARGO_TARGET_DIR/debug/wbuild/materios-runtime/materios_runtime.wasm" \
  --pallet pallet_intent_settlement --extrinsic threshold_signatures \
  --steps 20 --repeat 20 --external-repeat 3 --output-analysis max \
  --map-size 1000000 --additional-trie-layers 2 \
  --genesis-builder runtime --genesis-builder-preset development \
  --json-file "$SETTLEMENT_ROOT/pallets/intent-settlement/benchmarking/signature-samples.json" \
  --template "$SETTLEMENT_ROOT/pallets/intent-settlement/benchmarking/signature-weight.hbs" \
  --output /tmp/settlement-signature-fit.rs
```

The template emits the raw fit. Apply the sample-envelope formula above and
sum the independent proof bounds before updating `signature_weights.rs`;
then run `cargo test -p pallet-intent-settlement genesis_safety`. The raw
benchmark used frame-omni-bencher 43.0.0 and Materios source
`ce897154df80816a0929e9917d693c1dd77fc84b` with the scratch path overrides.
