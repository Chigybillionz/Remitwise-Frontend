//! Type-safe Stellar-compatible monetary amounts with exact precision.
//!
//! # Stellar amount model
//!
//! Stellar uses signed 64-bit integers with **7 decimal places** of
//! sub-unit precision.  The smallest transferable unit is therefore
//! `10^-7 XLM` (often called a *stroop*).  The absolute range is
//! `[1, 9_223_372_036_854_775_807]` stroops.
//!
//! # Invariants enforced here
//!
//! 1. An `Amount` is **strictly positive** — zero and negative values are
//!    rejected at construction time.
//! 2. The raw stroop value fits in a **non-negative `i64`** (the Stellar
//!    convention), but the type is stored as `u64` to prevent accidental
//!    negative arithmetic.
//! 3. All arithmetic operations (`checked_add`, `checked_sub`,
//!    `checked_mul`, `checked_div`) propagate an [`AmountError`] on
//!    overflow / underflow / divide-by-zero **before** any state change.
//! 4. Conversion helpers for common denominations (`stroops_to_xlm` and
//!    `xlm_to_stroops`) reject values that cannot be represented exactly.

use std::fmt;
use std::ops::{Add, Sub};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum value Stellar accepts for an amount (stroops).
pub const MAX_STROOPS: u64 = 9_223_372_036_854_775_807; // i64::MAX as u64

/// Number of decimal places in Stellar's sub-unit.
pub const STROOP_DECIMALS: u32 = 7;

/// 10^STROOP_DECIMALS — the number of stroops in one whole XLM.
pub const STROOPS_PER_XLM: u64 = 10_u64.pow(STROOP_DECIMALS);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors arising from amount construction or arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmountError {
    /// The value is zero — amounts must be strictly positive.
    Zero,
    /// The value exceeds the Stellar maximum (`i64::MAX` stroops).
    Overflow,
    /// Arithmetic produced a negative result or overflow.
    ArithmeticOverflow,
    /// Attempted to subtract a larger value from a smaller one.
    NegativeResult,
    /// Division by zero.
    DivisionByZero,
    /// The XLM conversion has a non-zero fractional stroop remainder.
    LossOfPrecision,
    /// The value cannot be represented as a non-negative `i64`.
    NotRepresentable,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmountError::Zero => write!(f, "amount must be strictly positive"),
            AmountError::Overflow => write!(f, "amount exceeds maximum stellar value"),
            AmountError::ArithmeticOverflow => write!(f, "arithmetic overflow"),
            AmountError::NegativeResult => write!(f, "subtraction would produce a negative result"),
            AmountError::DivisionByZero => write!(f, "division by zero"),
            AmountError::LossOfPrecision => {
                write!(f, "conversion would lose fractional precision")
            }
            AmountError::NotRepresentable => write!(f, "value cannot be represented"),
        }
    }
}

impl std::error::Error for AmountError {}

// ---------------------------------------------------------------------------
// Amount type
// ---------------------------------------------------------------------------

/// A Stellar-compatible monetary amount held in **stroops** (10^-7 XLM).
///
/// Constructed via [`Amount::new`] which rejects zero, negative, and
/// out-of-range values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount {
    /// Stroops — strictly positive, at most `MAX_STROOPS`.
    stroops: u64,
}

impl Amount {
    /// The zero sentinel used internally; never returned to callers.
    const ZERO_SENTINEL: u64 = 0;

    // -- Constructors -------------------------------------------------------

    /// Create a new amount from raw stroops.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Zero`] if `stroops == 0` and
    /// [`AmountError::Overflow`] if `stroops > MAX_STROOPS`.
    pub fn new(stroops: u64) -> Result<Self, AmountError> {
        if stroops == Self::ZERO_SENTINEL {
            return Err(AmountError::Zero);
        }
        if stroops > MAX_STROOPS {
            return Err(AmountError::Overflow);
        }
        Ok(Self { stroops })
    }

    /// Create an amount from a whole XLM value (e.g. `5` → 5 XLM).
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Overflow`] if the multiplication would
    /// overflow, or [`AmountError::Zero`] if `xlm == 0`.
    pub fn from_xlm(xlm: u64) -> Result<Self, AmountError> {
        let stroops = xlm
            .checked_mul(STROOPS_PER_XLM)
            .ok_or(AmountError::Overflow)?;
        Self::new(stroops)
    }

    /// Parse a decimal XLM string like `"1.2345678"` and convert to stroops.
    ///
    /// Rejects strings that would overflow, be zero, or have more than
    /// [`STROOP_DECIMALS`] fractional digits (loss-of-precision guard).
    pub fn from_xlm_decimal(s: &str) -> Result<Self, AmountError> {
        let parts: Vec<&str> = s.split('.').collect();

        match parts.len() {
            1 => {
                // No decimal point — treat as whole XLM.
                let whole: u64 = parts[0]
                    .parse()
                    .map_err(|_| AmountError::NotRepresentable)?;
                Self::from_xlm(whole)
            }
            2 => {
                let whole_str = if parts[0].is_empty() { "0" } else { parts[0] };
                let frac_str = parts[1];

                if frac_str.len() > STROOP_DECIMALS as usize {
                    return Err(AmountError::LossOfPrecision);
                }

                let whole: u64 = whole_str
                    .parse()
                    .map_err(|_| AmountError::NotRepresentable)?;

                // Pad fractional part to exactly STROOP_DECIMALS digits.
                let padded = format!("{:0<width$}", frac_str, width = STROOP_DECIMALS as usize);
                let frac: u64 = padded.parse().map_err(|_| AmountError::NotRepresentable)?;

                let stroops = whole
                    .checked_mul(STROOPS_PER_XLM)
                    .ok_or(AmountError::Overflow)?
                    .checked_add(frac)
                    .ok_or(AmountError::Overflow)?;

                Self::new(stroops)
            }
            _ => Err(AmountError::NotRepresentable),
        }
    }

    /// Try to convert from a signed `i64` (Stellar SDK convention).
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::Zero`] for zero and [`AmountError::NotRepresentable`]
    /// for negative values.
    pub fn from_i64(value: i64) -> Result<Self, AmountError> {
        if value <= 0 {
            if value == 0 {
                return Err(AmountError::Zero);
            }
            return Err(AmountError::NotRepresentable);
        }
        Self::new(value as u64)
    }

    // -- Accessors ----------------------------------------------------------

    /// The raw stroop value.
    pub fn stroops(&self) -> u64 {
        self.stroops
    }

    /// The value as a signed `i64` (Stellar SDK convention).
    ///
    /// Always safe because `Amount` guarantees `stroops <= i64::MAX`.
    pub fn as_i64(&self) -> i64 {
        self.stroops as i64
    }

    /// The whole-XLM component.
    pub fn whole_xlm(&self) -> u64 {
        self.stroops / STROOPS_PER_XLM
    }

    /// The fractional stroop remainder (0..9999999).
    pub fn fractional_stroops(&self) -> u64 {
        self.stroops % STROOPS_PER_XLM
    }

    /// Format as a decimal XLM string (e.g. `"1.2345678"`).
    pub fn to_xlm_string(&self) -> String {
        format!("{}.{:07}", self.whole_xlm(), self.fractional_stroops())
    }

    // -- Checked arithmetic -------------------------------------------------

    /// Checked addition. Returns [`AmountError::Overflow`] on overflow.
    pub fn checked_add(self, other: Amount) -> Result<Amount, AmountError> {
        let result = self
            .stroops
            .checked_add(other.stroops)
            .ok_or(AmountError::ArithmeticOverflow)?;
        Amount::new(result)
    }

    /// Checked subtraction. Returns [`AmountError::NegativeResult`] when
    /// `other > self`.
    pub fn checked_sub(self, other: Amount) -> Result<Amount, AmountError> {
        let result = self
            .stroops
            .checked_sub(other.stroops)
            .ok_or(AmountError::NegativeResult)?;
        Amount::new(result)
    }

    /// Checked multiplication by a `u64` scalar.
    pub fn checked_mul_u64(self, scalar: u64) -> Result<Amount, AmountError> {
        let result = self
            .stroops
            .checked_mul(scalar)
            .ok_or(AmountError::ArithmeticOverflow)?;
        Amount::new(result)
    }

    /// Checked multiplication by another `Amount` (cross-multiply).
    ///
    /// This is useful for basis-point fee calculations where you need
    /// `amount * bps / 10_000`.
    pub fn checked_mul_amount(self, other: Amount) -> Result<u128, AmountError> {
        Ok((self.stroops as u128) * (other.stroops as u128))
    }

    /// Checked division by a `u64` divisor.
    pub fn checked_div_u64(self, divisor: u64) -> Result<u64, AmountError> {
        if divisor == 0 {
            return Err(AmountError::DivisionByZero);
        }
        Ok(self.stroops / divisor)
    }

    /// Basis-point fee: `self * bps / 10_000` using 128-bit intermediate.
    ///
    /// Returns the fee amount. Errors on zero basis points or overflow.
    pub fn basis_point_fee(self, bps: u64) -> Result<Amount, AmountError> {
        if bps == 0 {
            return Err(AmountError::Zero);
        }
        if bps > 10_000 {
            return Err(AmountError::Overflow);
        }
        let product = (self.stroops as u128) * (bps as u128);
        let fee = product / 10_000;
        if fee > MAX_STROOPS as u128 {
            return Err(AmountError::Overflow);
        }
        Amount::new(fee as u64)
    }

    /// Percentage fee: `self * percent / 100` using 128-bit intermediate.
    pub fn percentage_fee(self, percent: u64) -> Result<Amount, AmountError> {
        if percent == 0 {
            return Err(AmountError::Zero);
        }
        if percent > 100 {
            return Err(AmountError::Overflow);
        }
        let product = (self.stroops as u128) * (percent as u128);
        let fee = product / 100;
        if fee > MAX_STROOPS as u128 {
            return Err(AmountError::Overflow);
        }
        Amount::new(fee as u64)
    }

    // -- Balance accumulator (overflow-safe) --------------------------------

    /// Add to an external accumulator. Returns the new balance.
    ///
    /// This is the canonical way to update a balance: the checked
    /// arithmetic happens *before* the caller writes the result to
    /// storage.
    pub fn accumulate_balance(current: Amount, delta: Amount) -> Result<Amount, AmountError> {
        current.checked_add(delta)
    }

    /// Deduct from an external accumulator. Returns the new balance.
    pub fn deduct_balance(current: Amount, delta: Amount) -> Result<Amount, AmountError> {
        current.checked_sub(delta)
    }
}

// -- Display --------------------------------------------------------------

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} XLM", self.to_xlm_string())
    }
}

// ---------------------------------------------------------------------------
// Trait implementations — ergonomic operators that propagate errors
// ---------------------------------------------------------------------------

impl Add for Amount {
    type Output = Result<Amount, AmountError>;

    fn add(self, rhs: Amount) -> Self::Output {
        self.checked_add(rhs)
    }
}

impl Sub for Amount {
    type Output = Result<Amount, AmountError>;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Construction -------------------------------------------------------

    #[test]
    fn new_rejects_zero() {
        assert_eq!(Amount::new(0), Err(AmountError::Zero));
    }

    #[test]
    fn new_rejects_overflow() {
        assert_eq!(Amount::new(MAX_STROOPS + 1), Err(AmountError::Overflow));
    }

    #[test]
    fn new_accepts_minimum() {
        let a = Amount::new(1).unwrap();
        assert_eq!(a.stroops(), 1);
    }

    #[test]
    fn new_accepts_maximum() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        assert_eq!(a.stroops(), MAX_STROOPS);
    }

    #[test]
    fn new_accepts_typical_value() {
        let a = Amount::new(1_000_000).unwrap();
        assert_eq!(a.stroops(), 1_000_000);
    }

    // -- from_xlm ----------------------------------------------------------

    #[test]
    fn from_xlm_zero_is_rejected() {
        assert_eq!(Amount::from_xlm(0), Err(AmountError::Zero));
    }

    #[test]
    fn from_xlm_overflow_is_rejected() {
        // u64::MAX / STROOPS_PER_XLM + 1 should overflow
        let too_many = u64::MAX / STROOPS_PER_XLM + 1;
        assert_eq!(Amount::from_xlm(too_many), Err(AmountError::Overflow));
    }

    #[test]
    fn from_xlm_one() {
        let a = Amount::from_xlm(1).unwrap();
        assert_eq!(a.stroops(), STROOPS_PER_XLM);
    }

    // -- from_xlm_decimal --------------------------------------------------

    #[test]
    fn decimal_whole() {
        let a = Amount::from_xlm_decimal("5").unwrap();
        assert_eq!(a.stroops(), 5 * STROOPS_PER_XLM);
    }

    #[test]
    fn decimal_fractional() {
        let a = Amount::from_xlm_decimal("1.2345678").unwrap();
        assert_eq!(a.stroops(), 1 * STROOPS_PER_XLM + 2_345_678);
    }

    #[test]
    fn decimal_too_many_digits_rejected() {
        assert_eq!(
            Amount::from_xlm_decimal("1.12345678"),
            Err(AmountError::LossOfPrecision)
        );
    }

    #[test]
    fn decimal_zero_rejected() {
        assert_eq!(Amount::from_xlm_decimal("0"), Err(AmountError::Zero));
        assert_eq!(
            Amount::from_xlm_decimal("0.0000000"),
            Err(AmountError::Zero)
        );
    }

    #[test]
    fn decimal_negative_rejected() {
        assert_eq!(
            Amount::from_xlm_decimal("-1.0"),
            Err(AmountError::NotRepresentable)
        );
    }

    #[test]
    fn decimal_partial_stroops() {
        let a = Amount::from_xlm_decimal("0.0000001").unwrap();
        assert_eq!(a.stroops(), 1);
    }

    #[test]
    fn decimal_large_value() {
        // MAX_STROOPS = 9_223_372_036_854_775_807
        // In XLM: 922_337_203_685.4775807
        let a = Amount::from_xlm_decimal("922337203685.4775807").unwrap();
        assert_eq!(a.stroops(), MAX_STROOPS);
    }

    // -- from_i64 ----------------------------------------------------------

    #[test]
    fn from_i64_positive() {
        let a = Amount::from_i64(100).unwrap();
        assert_eq!(a.stroops(), 100);
    }

    #[test]
    fn from_i64_zero_rejected() {
        assert_eq!(Amount::from_i64(0), Err(AmountError::Zero));
    }

    #[test]
    fn from_i64_negative_rejected() {
        assert_eq!(Amount::from_i64(-1), Err(AmountError::NotRepresentable));
    }

    // -- Display / formatting -----------------------------------------------

    #[test]
    fn display_whole() {
        let a = Amount::from_xlm(5).unwrap();
        assert_eq!(a.to_xlm_string(), "5.0000000");
    }

    #[test]
    fn display_fractional() {
        let a = Amount::new(1_234_567).unwrap();
        assert_eq!(a.to_xlm_string(), "0.1234567");
    }

    // -- Arithmetic --------------------------------------------------------

    #[test]
    fn add_basic() {
        let a = Amount::new(100).unwrap();
        let b = Amount::new(200).unwrap();
        assert_eq!((a + b).unwrap().stroops(), 300);
    }

    #[test]
    fn add_overflow_rejected() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        let b = Amount::new(1).unwrap();
        // u64 addition succeeds (both < u64::MAX), but result > MAX_STROOPS
        // so Amount::new() returns Overflow.
        assert_eq!(a + b, Err(AmountError::Overflow));
    }

    #[test]
    fn sub_basic() {
        let a = Amount::new(300).unwrap();
        let b = Amount::new(100).unwrap();
        assert_eq!((a - b).unwrap().stroops(), 200);
    }

    #[test]
    fn sub_negative_rejected() {
        let a = Amount::new(100).unwrap();
        let b = Amount::new(200).unwrap();
        assert_eq!(a - b, Err(AmountError::NegativeResult));
    }

    #[test]
    fn sub_exact_zero_rejected() {
        let a = Amount::new(100).unwrap();
        let b = Amount::new(100).unwrap();
        assert_eq!(a - b, Err(AmountError::Zero));
    }

    #[test]
    fn mul_u64_basic() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.checked_mul_u64(5).unwrap().stroops(), 500);
    }

    #[test]
    fn mul_u64_overflow() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        // u64 mul succeeds but result > MAX_STROOPS → Overflow.
        assert_eq!(a.checked_mul_u64(2), Err(AmountError::Overflow));
    }

    #[test]
    fn div_u64_basic() {
        let a = Amount::new(1000).unwrap();
        assert_eq!(a.checked_div_u64(10).unwrap(), 100);
    }

    #[test]
    fn div_u64_by_zero() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.checked_div_u64(0), Err(AmountError::DivisionByZero));
    }

    // -- Basis-point fee ---------------------------------------------------

    #[test]
    fn bps_fee_basic() {
        let a = Amount::from_xlm(100).unwrap();
        let fee = a.basis_point_fee(250).unwrap(); // 2.5%
        assert_eq!(
            fee,
            (Amount::from_xlm(2).unwrap() + Amount::from_xlm_decimal("0.5").unwrap()).unwrap()
        );
    }

    #[test]
    fn bps_fee_zero_rejected() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.basis_point_fee(0), Err(AmountError::Zero));
    }

    #[test]
    fn bps_fee_over_10000_rejected() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.basis_point_fee(10_001), Err(AmountError::Overflow));
    }

    #[test]
    fn bps_fee_max_amount() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        let fee = a.basis_point_fee(1).unwrap();
        assert_eq!(fee.stroops(), MAX_STROOPS / 10_000);
    }

    #[test]
    fn bps_fee_exact_10000_is_full_amount() {
        let a = Amount::from_xlm(10).unwrap();
        let fee = a.basis_point_fee(10_000).unwrap();
        assert_eq!(fee, a);
    }

    // -- Percentage fee ----------------------------------------------------

    #[test]
    fn pct_fee_basic() {
        let a = Amount::from_xlm(200).unwrap();
        let fee = a.percentage_fee(10).unwrap(); // 10%
        assert_eq!(fee.stroops(), 20 * STROOPS_PER_XLM);
    }

    #[test]
    fn pct_fee_zero_rejected() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.percentage_fee(0), Err(AmountError::Zero));
    }

    #[test]
    fn pct_fee_over_100_rejected() {
        let a = Amount::new(100).unwrap();
        assert_eq!(a.percentage_fee(101), Err(AmountError::Overflow));
    }

    // -- Balance accumulator ------------------------------------------------

    #[test]
    fn accumulate_balance_basic() {
        let bal = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(50).unwrap();
        let new = Amount::accumulate_balance(bal, delta).unwrap();
        assert_eq!(new, Amount::from_xlm(150).unwrap());
    }

    #[test]
    fn accumulate_balance_overflow() {
        let bal = Amount::new(MAX_STROOPS).unwrap();
        let delta = Amount::new(1).unwrap();
        assert_eq!(
            Amount::accumulate_balance(bal, delta),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn deduct_balance_basic() {
        let bal = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(30).unwrap();
        let new = Amount::deduct_balance(bal, delta).unwrap();
        assert_eq!(new, Amount::from_xlm(70).unwrap());
    }

    #[test]
    fn deduct_balance_insufficient() {
        let bal = Amount::from_xlm(10).unwrap();
        let delta = Amount::from_xlm(20).unwrap();
        assert_eq!(
            Amount::deduct_balance(bal, delta),
            Err(AmountError::NegativeResult)
        );
    }

    // -- Cross-multiply (128-bit) ------------------------------------------

    #[test]
    fn mul_amount_basic() {
        let a = Amount::new(1_000).unwrap();
        let b = Amount::new(2_000).unwrap();
        assert_eq!(a.checked_mul_amount(b).unwrap(), 2_000_000);
    }

    #[test]
    fn mul_amount_large_values() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        let b = Amount::new(MAX_STROOPS).unwrap();
        let result = a.checked_mul_amount(b).unwrap();
        assert_eq!(result, (MAX_STROOPS as u128) * (MAX_STROOPS as u128));
    }

    // -- Edge cases: near-boundary values -----------------------------------

    #[test]
    fn stroops_one_below_max() {
        let a = Amount::new(MAX_STROOPS - 1).unwrap();
        let one = Amount::new(1).unwrap();
        assert_eq!(a.checked_add(one).unwrap().stroops(), MAX_STROOPS);
    }

    #[test]
    fn stroops_max_minus_stroops_max_is_zero_rejected() {
        let a = Amount::new(MAX_STROOPS).unwrap();
        let b = Amount::new(MAX_STROOPS).unwrap();
        assert_eq!(a - b, Err(AmountError::Zero));
    }

    #[test]
    fn conversion_roundtrip_xlm() {
        let original = Amount::from_xlm(42).unwrap();
        let as_i64 = original.as_i64();
        let reconstructed = Amount::from_i64(as_i64).unwrap();
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn conversion_roundtrip_decimal() {
        let original = Amount::from_xlm_decimal("3.1415926").unwrap();
        let reconstructed = Amount::from_xlm_decimal(&original.to_xlm_string()).unwrap();
        assert_eq!(original, reconstructed);
    }

    // -- Deterministic oracle comparison ------------------------------------

    /// Verify against an independent oracle: 1 XLM = 10^7 stroops.
    #[test]
    fn oracle_one_xlm_equals_10e7_stroops() {
        let a = Amount::from_xlm(1).unwrap();
        assert_eq!(a.stroops(), 10_000_000);
    }

    /// Verify fee oracle: 250 bps on 1000 XLM = 25 XLM.
    #[test]
    fn oracle_bps_fee_250_on_1000_xlm() {
        let amount = Amount::from_xlm(1000).unwrap();
        let fee = amount.basis_point_fee(250).unwrap();
        assert_eq!(fee, Amount::from_xlm(25).unwrap());
    }

    /// Verify fee oracle: 10% on 500 XLM = 50 XLM.
    #[test]
    fn oracle_pct_fee_10_on_500_xlm() {
        let amount = Amount::from_xlm(500).unwrap();
        let fee = amount.percentage_fee(10).unwrap();
        assert_eq!(fee, Amount::from_xlm(50).unwrap());
    }

    /// Verify that near-max addition does not silently wrap.
    #[test]
    fn oracle_near_max_no_wrap() {
        let a = Amount::new(MAX_STROOPS - 1).unwrap();
        let b = Amount::new(2).unwrap();
        assert_eq!(a + b, Err(AmountError::Overflow));
    }
}
