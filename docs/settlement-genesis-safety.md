# Settlement request and genesis safety

## Request lifetime

`request_settle` takes a trailing `bond_amount: u128`;
`request_batch_settle` takes the same trailing amount **per claim**. Both
reserve the bond atomically with request creation. The amount must be positive
and at least `Config::MinSettlementBond`, including when that constant is zero.
The runtime owns the economic minimum; this pallet does not choose a MATRA
value. Insufficient funds roll back the entire request or batch, including
refunds of replaced requests. Keepers read the exposed runtime constant and
submit `max(MinSettlementBond, 1)`.

A request is fresh while `now - submitted_block <= SettlementRequestTtl`.
Attestation and slashing use that inclusive boundary. On the next block, an
unattested request can be replaced by either request extrinsic. Replacement
returns any reserve to the original requester before storing the new request.
Batch replacement is atomic, including balance changes and release events.

Anyone can release an expired, unattested, unslashed bond. The funds always go
to its recorded requester. The expired request is removed so release cannot
pay twice. Attested bonds retain the separate `BondReleaseDelayBlocks` rule.

A slash records `(claim_id, request_id)` in `SlashedSettlementRequests` and
removes the pending request. Any other request for the claim, from any
requester, can be filed and attested immediately, so a junk bond cannot wedge
a claim. FRV2 binds each allegation to one `request_id`; only an identical
repost in the slashing block recreates it, and that repost is refused with
`BondSlashedNoRelease`, so each signed allegation slashes at most once. The
claim-wide `BondSlashedRequests` map from earlier runtimes is no longer read or
written; its existing entries no longer block requests.

Slashing operates only on pending requests; successful attestation consumes
that request. The post-attestation release delay is a liquidity hold, **not a
fraud-challenge period**: there is no slash path after attestation.
`post_settlement_bond` exists for unbonded requests stored before request-time
bonding and refuses a request past its TTL, so no bond is reserved after its
slash window has closed. Policy-expiry requests use the same replacement
boundary so a stale request cannot wedge the EXPP path after the legacy
cutover.

If another Currency consumer depleted the shared reserve, release and
replacement return only the funds still reserved, emit the actual released
amount, and report the missing amount in `SettlementBondReserveDeficit`.
The missing funds do not permanently lock the claim.

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
enactment. Signers that select FRAU or FRV2 by fingerprinting the
`slash_bad_settlement_evidence` metadata docs must pin the docs of the
runtime being enacted. No deployment is performed here.

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
expiries as legacy. Call indices and existing storage encodings are preserved.
The two request calls take the bond argument, so hosts must bump the
transaction version and upgrade request submitters together. The signed FRV2,
STCA and EXPP payloads are as specified above. The request-scoped tombstone
map and the `SettlementBondReserveDeficit` event are appended, so existing
metadata indices hold. Existing version-3 preprod state needs no data
migration; older versions retain the existing migration sequence.

Try-runtime pre/post hooks check version progression, cutover preservation and
legacy audit flags. An upgrade over a chain already at the current version must
leave every key and value under the pallet's storage prefix unchanged; other
pallets' storage is out of scope. `try_state` rejects unknown versions,
inconsistent cutovers and migration progress outside version 2.

## Signature work and runtime integration

Every threshold-signature dispatch charges a bounded bundle-length component
in addition to its existing base. Post-dispatch weight retains the base and
the signatures checked, including on failure. Cheap rejection paths return
the unused verification budget. Deposit replay checks precede verification.
Single-intent duplicates, fully replayed intent batches and nonmember slash
callers also exit before signature verification. Single-intent attestation
declares the one-signature component plus its storage work.

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

CI executes the signature benchmark with real sr25519 keys and a 96-member
committee in the integration runtime, in addition to checking the recorded
timing envelope. It also executes the request, bond, release and slash
benchmarks there; the slash benchmark reserves a real bond and signs its FRV2
digest. These native runs prove the benchmarks execute; refreshing timing
coefficients still requires the Wasm measurement below.

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
