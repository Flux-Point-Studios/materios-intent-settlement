// SPDX-License-Identifier: Apache-2.0
//
//! Weight functions for `pallet_intent_settlement`.
//!
//! The `settle_batch_atomic` slot was auto-generated via frame-omni-bencher
//! (task #43); see `cargo run --release --features runtime-benchmarks ...`
//! in the materios-node workspace for the reproducible command. The other
//! slots remain hand-tuned upper bounds — they will be replaced as their
//! benchmarks land (tracked under tasks #209-#212).
//!
//! AUTO-GENERATED BLOCK BELOW (settle_batch_atomic only)
//! ----------------------------------------------------------------------
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 43.0.0
//! DATE: 2026-05-14, STEPS: `10`, REPEAT: `5`
//! HOSTNAME: `deci-desktop`, CPU: `AMD Ryzen 7 7730U with Radeon Graphics`
//! WASM-EXECUTION: `Compiled`, CHAIN: `None`, DB CACHE: 1024
//!
//! Executed Command:
//!   frame-omni-bencher v1 benchmark pallet
//!     --runtime <materios_runtime.compact.compressed.wasm>
//!     --pallet pallet_intent_settlement
//!     --extrinsic settle_batch_atomic
//!     --steps 10 --repeat 5
//!     --genesis-builder runtime
//!     --output pallets/intent-settlement/src/weights.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight surface used by `pallet_intent_settlement`. Production runtimes
/// wire `T::WeightInfo = SubstrateWeight<Runtime>` (auto-generated below).
pub trait WeightInfo {
    fn settle_batch_atomic(n: u32) -> Weight;
}

/// Auto-generated `SubstrateWeight` impl. Mirrors the cost slope measured by
/// `frame-omni-bencher` on the materios-runtime WASM with
/// `BenchAllowAnyVerifier` (i.e. sig-verify cost is excluded). The
/// production runtime budgets in a single sr25519 sig-verify (~50M ref_time)
/// on top via the `weight!` annotation on the extrinsic call.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// Storage: `OrinqReceipts::CommitteeMembers` (r:1 w:0)
    /// Proof: `OrinqReceipts::CommitteeMembers` (`max_values`: Some(1), `max_size`: Some(3074), added: 3569, mode: `MaxEncodedLen`)
    /// Storage: `IntentSettlement::MinSignerThreshold` (r:1 w:0)
    /// Proof: `IntentSettlement::MinSignerThreshold` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
    /// Storage: `IntentSettlement::Claims` (r:256 w:256)
    /// Proof: `IntentSettlement::Claims` (`max_values`: None, `max_size`: Some(166), added: 2641, mode: `MaxEncodedLen`)
    /// Storage: `IntentSettlement::Intents` (r:256 w:256)
    /// Proof: `IntentSettlement::Intents` (`max_values`: None, `max_size`: Some(644), added: 3119, mode: `MaxEncodedLen`)
    /// Storage: `IntentSettlement::PendingBatches` (r:1 w:1)
    /// Proof: `IntentSettlement::PendingBatches` (`max_values`: Some(1), `max_size`: Some(320002), added: 320497, mode: `MaxEncodedLen`)
    /// Storage: `IntentSettlement::PoolUtilization` (r:1 w:1)
    /// Proof: `IntentSettlement::PoolUtilization` (`max_values`: Some(1), `max_size`: Some(24), added: 519, mode: `MaxEncodedLen`)
    /// The range of component `n` is `[1, 256]`.
    fn settle_batch_atomic(n: u32) -> Weight {
        // Proof Size summary in bytes:
        //  Measured:  `534 + n * (314 ±0)`
        //  Estimated: `321487 + n * (3119 ±0)`
        // Minimum execution time: 46_628_000 picoseconds.
        Weight::from_parts(46_989_000, 0)
            .saturating_add(Weight::from_parts(0, 321487))
            // Standard Error: 159_726
            .saturating_add(Weight::from_parts(16_464_755, 0).saturating_mul(n.into()))
            .saturating_add(T::DbWeight::get().reads(4))
            .saturating_add(T::DbWeight::get().reads((2_u64).saturating_mul(n.into())))
            .saturating_add(T::DbWeight::get().writes(2))
            .saturating_add(T::DbWeight::get().writes((2_u64).saturating_mul(n.into())))
            .saturating_add(Weight::from_parts(0, 3119).saturating_mul(n.into()))
    }
}

/// Unit-test default. Mirrors the auto-generated curve at a slightly higher
/// constant offset so tests can assert "weight grows with n" without
/// depending on hardware-specific picosecond values.
impl WeightInfo for () {
    fn settle_batch_atomic(n: u32) -> Weight {
        Weight::from_parts(
            50_000_000u64.saturating_add((n as u64).saturating_mul(17_000_000)),
            321_487u64.saturating_add((n as u64).saturating_mul(3_119)),
        )
    }
}
