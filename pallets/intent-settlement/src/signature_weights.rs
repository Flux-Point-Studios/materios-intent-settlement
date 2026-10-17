//! Measured by frame-omni-bencher 43.0.0 on 2026-10-17.
//! Host: deci-desktop; CPU: AMD Ryzen 7 7730U with Radeon Graphics.
//! Steps: 20; repeats: 20; execution: Compiled.
//! Full committee, real sr25519, recorded proofs.
//! Slope covers every recorded sample; proof sums both independent values.
//! Reproduction and fitted coefficients: docs/settlement-genesis-safety.md.

use frame_support::weights::{constants::RocksDbWeight, Weight};

/// Storage: `IntentSettlement::MinSignerThreshold` (r:1 w:0)
/// Proof: `IntentSettlement::MinSignerThreshold` (`max_values`: Some(1), `max_size`: Some(4), added: 499, mode: `MaxEncodedLen`)
/// Storage: `OrinqReceipts::CommitteeMembers` (r:1 w:0)
/// Proof: `OrinqReceipts::CommitteeMembers` (`max_values`: Some(1), `max_size`: Some(3074), added: 3569, mode: `MaxEncodedLen`)
pub fn threshold_signatures(s: u32) -> Weight {
    if s == 0 {
        return Weight::zero();
    }
    Weight::from_parts(63_481_676, 6_048)
        .saturating_add(Weight::from_parts(89_000_000, 0).saturating_mul(s.into()))
        .saturating_add(RocksDbWeight::get().reads(2))
}
