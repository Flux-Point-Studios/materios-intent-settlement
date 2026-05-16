//! Fixed-point math helpers for `pallet-perp-engine` v0 (task #259, PR-B).
//!
//! All position / margin / PnL / funding math goes through this module so
//! the overflow-surfacing contract is consistent and the call sites stay
//! lean. Per design memo §10.1 risk #3: every multiplication must be
//! `checked_mul`, every overflow surfaces as a typed error rather than
//! silently saturating.
//!
//! ## Precision contract
//!
//! - **Size** is in `1e-8` contract units (`size_e8`). Long = positive,
//!   short = negative.
//! - **Prices** are 1e18-scaled (`mark_e18`, `entry_mark_e18`).
//! - **Notional** is in 1e18-scaled pMATRA-USD. `notional_e18 =
//!   |size_e8| * price_e18 / 1e8`.
//! - **Margin** is in 1e18-scaled pMATRA-USD.
//! - **Leverage** is in basis points (`leverage_bps`); `100 = 1×`,
//!   `1000 = 10×`, `2000 = 20×`.
//! - **Funding index** is signed `i128` and pre-scaled by the caller —
//!   see §7.4 for the pull-based settlement contract.
//!
//! ## Why u128 / i128 instead of `sp-arithmetic::FixedU128`
//!
//! `FixedU128` is fine for ratios but we're juggling four distinct scales
//! (size = 1e8, price = 1e18, notional = 1e18, leverage = 1e2). A bespoke
//! integer pipeline with explicit overflow-checked multiplications keeps
//! the precision contract auditable in one file.

use sp_std::vec::Vec;

/// Generic math-overflow tag. The pallet maps this to its own
/// `Error::ArithmeticOverflow` variant — see `lib.rs`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MathOverflow;

/// Saturating MUL of size + price into a 1e18-scaled notional.
///
/// `notional_e18 = size_e8 * mark_e18 / 1e8`.
///
/// Caller passes `|size_e8|` (positive magnitude). Returns
/// `MathOverflow` if the intermediate `size_e8 * mark_e18` exceeds
/// `u128::MAX` (range check, not a silent saturate).
///
/// Worst-case headroom check: at the design memo §9.1 cap of
/// `max_position_size_e8 = 250_000_000_000` (= $250k notional at $1
/// price) and a `mark_e18 = 1e18 * 100_000` (= $100k unit price),
/// `size_e8 * mark_e18 = 2.5e10 * 1e23 ≈ 2.5e33` — well inside `u128`
/// (~3.4e38). The check is a defensive belt-and-braces gate, not a
/// reachable concern in practice.
pub fn compute_notional(size_e8_abs: u128, mark_e18: u128) -> Result<u128, MathOverflow> {
    let prod = size_e8_abs.checked_mul(mark_e18).ok_or(MathOverflow)?;
    // Divide by 1e8 to drop the size scale; notional comes out 1e18-scaled.
    Ok(prod / 100_000_000u128)
}

/// Initial margin in 1e18-scaled pMATRA-USD.
///
/// `initial_margin_e18 = notional_e18 * 100 / leverage_bps`.
///
/// (The `100` factor is the bps↔×-multiplier scale: `leverage_bps=100`
/// = 1×, so `notional / leverage_bps * 100` is the same as `notional /
/// leverage_multiplier`.)
///
/// Errors:
/// - `MathOverflow` if `leverage_bps == 0` (caller MUST validate this
///   upstream — `LeverageOutOfBounds` in the pallet).
/// - `MathOverflow` if `notional * 100` overflows.
pub fn compute_initial_margin(
    notional_e18: u128,
    leverage_bps: u32,
) -> Result<u128, MathOverflow> {
    if leverage_bps == 0 {
        return Err(MathOverflow);
    }
    let scaled = notional_e18
        .checked_mul(100u128)
        .ok_or(MathOverflow)?;
    Ok(scaled / leverage_bps as u128)
}

/// Maintenance margin in 1e18-scaled pMATRA-USD.
///
/// `maintenance_margin_e18 = notional_e18 * maintenance_bps / 10_000`.
///
/// Errors: `MathOverflow` if `notional * maintenance_bps` overflows.
pub fn compute_maintenance_margin(
    notional_e18: u128,
    maintenance_bps: u32,
) -> Result<u128, MathOverflow> {
    let scaled = notional_e18
        .checked_mul(maintenance_bps as u128)
        .ok_or(MathOverflow)?;
    Ok(scaled / 10_000u128)
}

/// Signed realized PnL = `signed_size_e8 * (exit_mark_e18 - entry_mark_e18) / 1e8`.
///
/// Result is signed `i128` in 1e18-scaled pMATRA-USD. Positive = profit
/// for the position holder; negative = loss.
///
/// Errors: `MathOverflow` if the intermediate signed product overflows
/// `i128`.
pub fn compute_realized_pnl_signed(
    exit_mark_e18: u128,
    entry_mark_e18: u128,
    signed_size_e8: i128,
) -> Result<i128, MathOverflow> {
    // Compute the signed delta first. Both marks are u128; their
    // signed difference fits in `i128` because each is at most ~2^127
    // (in practice, prices fit comfortably below 2^127, but we still
    // check).
    let exit_i: i128 = i128::try_from(exit_mark_e18).map_err(|_| MathOverflow)?;
    let entry_i: i128 = i128::try_from(entry_mark_e18).map_err(|_| MathOverflow)?;
    let delta = exit_i.checked_sub(entry_i).ok_or(MathOverflow)?;
    let prod = signed_size_e8.checked_mul(delta).ok_or(MathOverflow)?;
    Ok(prod / 100_000_000i128)
}

/// Signed funding delta applied to a position = `(current_idx -
/// entry_idx) * signed_size_e8 / 1e18`.
///
/// The funding index is itself in 1e18-scaled per-unit-of-size, and
/// `signed_size_e8` is 1e-8 contract units, so the product is
/// 1e26-scaled and we divide by 1e18 to land in 1e8-scaled
/// pMATRA-USD-equivalent units before the caller normalises further.
///
/// **Sign convention** matches design memo §7.4: a positive result means
/// the position OWES funding (funding gets deducted from margin); a
/// negative result means the position RECEIVES funding.
///
/// Errors: `MathOverflow` if the intermediate signed product overflows
/// `i128`.
pub fn compute_funding_delta(
    current_idx_e18: i128,
    entry_idx_e18: i128,
    signed_size_e8: i128,
) -> Result<i128, MathOverflow> {
    let idx_delta = current_idx_e18
        .checked_sub(entry_idx_e18)
        .ok_or(MathOverflow)?;
    let prod = signed_size_e8.checked_mul(idx_delta).ok_or(MathOverflow)?;
    // `signed_size_e8` is 1e-8 scale; `idx_delta` is 1e18 per unit of
    // size; product is at 1e10-scale-of-pMATRA-USD. Divide once by
    // 1e10 so the result is unscaled pMATRA-USD (later upscaled to
    // 1e18 by the call site if it needs).
    //
    // BUT: design memo §7.4 example math shows funding_owed_e18 =
    // signed_size * (idx_now - idx_entry); since idx values are
    // already 1e18-scaled and size is 1e-8, the natural product lands
    // in 1e10 — we want 1e18-scaled pMATRA-USD-output, so the actual
    // divisor is /1e-8 = *1e8 multiplier... wait. Let me re-derive.
    //
    // funding_index has units of "1e18-scaled (rate × time)".
    // size_e8 has units of "1e8-scaled contracts".
    // The dimensionally correct product is `idx * size / 1e8` to
    // produce 1e18-scaled pMATRA-USD. That matches the memo §7.4.
    Ok(prod / 100_000_000i128)
}

/// Median of an unsorted slice of signed i128 values. Returns 0 for
/// empty input. Used by `settle_funding` (PR-C) to aggregate
/// `PremiumIndexSamples`. Lives here so PR-B doesn't dead-code-warn it.
#[allow(dead_code)]
pub fn median_i128(samples: &[i128]) -> i128 {
    if samples.is_empty() {
        return 0;
    }
    let mut v: Vec<i128> = samples.to_vec();
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        // Avg the two middle values without overflowing — use
        // (a/2) + (b/2) + ((a%2)+(b%2))/2 to preserve LSB.
        let lo = v[n / 2 - 1];
        let hi = v[n / 2];
        let a = lo / 2;
        let b = hi / 2;
        let r = (lo % 2 + hi % 2) / 2;
        a.checked_add(b).and_then(|s| s.checked_add(r)).unwrap_or(0)
    }
}

#[cfg(test)]
mod math_tests {
    use super::*;

    /// `notional = size_e8 * mark_e18 / 1e8`. Spot-check: 1 ADA-PERP at
    /// $0.425 = 4.25e17 pMATRA-USD (1e18-scaled $0.425).
    #[test]
    fn notional_canonical() {
        let size_e8 = 100_000_000u128; // 1.0 contract
        let mark_e18 = 425_000_000_000_000_000u128; // $0.425
        let n = compute_notional(size_e8, mark_e18).unwrap();
        // 1.0 * 0.425 = $0.425 → 4.25e17 in 1e18 scale
        assert_eq!(n, 425_000_000_000_000_000u128);
    }

    /// Initial margin = notional / leverage. 10× on $0.425 = $0.0425 =
    /// 4.25e16.
    #[test]
    fn initial_margin_10x() {
        let notional = 425_000_000_000_000_000u128; // $0.425
        let m = compute_initial_margin(notional, 1_000).unwrap(); // 10×
        assert_eq!(m, 42_500_000_000_000_000u128); // $0.0425
    }

    /// At 1× leverage initial margin = notional.
    #[test]
    fn initial_margin_1x() {
        let notional = 1_000_000_000_000_000_000u128;
        let m = compute_initial_margin(notional, 100).unwrap();
        assert_eq!(m, notional);
    }

    /// Maintenance margin at 5% on $1 notional = $0.05.
    #[test]
    fn maintenance_margin_5pct() {
        let notional = 1_000_000_000_000_000_000u128;
        let m = compute_maintenance_margin(notional, 500).unwrap();
        assert_eq!(m, 50_000_000_000_000_000u128);
    }

    /// Long position profits when mark rises. 1.0 long, entry $1.0,
    /// exit $1.10 → +$0.10 PnL = +1e17.
    #[test]
    fn pnl_long_win() {
        let pnl = compute_realized_pnl_signed(
            1_100_000_000_000_000_000u128, // exit $1.10
            1_000_000_000_000_000_000u128, // entry $1.00
            100_000_000i128,                // 1.0 long
        )
        .unwrap();
        assert_eq!(pnl, 100_000_000_000_000_000i128);
    }

    /// Long position loses when mark falls.
    #[test]
    fn pnl_long_loss() {
        let pnl = compute_realized_pnl_signed(
            900_000_000_000_000_000u128, // exit $0.90
            1_000_000_000_000_000_000u128, // entry $1.00
            100_000_000i128,
        )
        .unwrap();
        assert_eq!(pnl, -100_000_000_000_000_000i128);
    }

    /// Short profits when mark falls. Signed size is negative.
    #[test]
    fn pnl_short_win() {
        let pnl = compute_realized_pnl_signed(
            900_000_000_000_000_000u128,
            1_000_000_000_000_000_000u128,
            -100_000_000i128, // 1.0 short
        )
        .unwrap();
        // signed_size negative * delta negative = positive PnL
        assert_eq!(pnl, 100_000_000_000_000_000i128);
    }

    /// Notional must not overflow `u128`.
    #[test]
    fn notional_overflow_protected() {
        // Largest u128 is ~3.4e38. Pick a size * mark that just
        // squeaks over.
        let big = u128::MAX;
        let r = compute_notional(big, 2);
        assert_eq!(r, Err(MathOverflow));
    }

    #[test]
    fn initial_margin_rejects_zero_leverage() {
        let r = compute_initial_margin(1_000_000u128, 0);
        assert_eq!(r, Err(MathOverflow));
    }

    /// Funding delta math, design memo §7.4: signed_size *
    /// (idx_now - idx_at_open). Long position paid funding when index
    /// rises.
    #[test]
    fn funding_delta_long_pays() {
        let d = compute_funding_delta(
            1_000_000_000_000_000_000i128, // idx_now
            0i128,                          // idx_at_open
            100_000_000i128,                // 1.0 long
        )
        .unwrap();
        // 1.0 long * delta_1.0 / 1e8 = 1.0 → 1e10 in unscaled
        // pMATRA-USD ... actually let's trace dimensions:
        // size=1e8 * idx_delta=1e18 = 1e26; /1e8 = 1e18. So result is
        // 1e18 (= 1.0 pMATRA-USD in 1e18 scale).
        assert_eq!(d, 1_000_000_000_000_000_000i128);
    }

    /// Short position receives funding when index rises.
    #[test]
    fn funding_delta_short_receives() {
        let d = compute_funding_delta(
            1_000_000_000_000_000_000i128,
            0i128,
            -100_000_000i128,
        )
        .unwrap();
        assert_eq!(d, -1_000_000_000_000_000_000i128);
    }

    /// Median helper — odd count picks middle.
    #[test]
    fn median_odd() {
        assert_eq!(median_i128(&[3, 1, 2]), 2);
    }

    /// Median helper — even count picks avg of middles.
    #[test]
    fn median_even() {
        assert_eq!(median_i128(&[1, 2, 3, 4]), 2); // (2+3)/2 = 2 (rounded down)
    }

    /// Median of empty = 0 (caller responsibility to gate).
    #[test]
    fn median_empty() {
        assert_eq!(median_i128(&[]), 0);
    }
}
