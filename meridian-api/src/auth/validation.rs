//! Auth-specific validation helpers.
//!
//! This module provides validation functions that combine the precision
//! guarantees of [`crate::amount`] with auth-specific constraints.
//!
//! # Design
//!
//! Every validator returns `Result<T, AuthError>` and performs *no*
//! side effects.  All validation happens before any state change,
//! following the project's validation protocol.

use crate::amount::{Amount, MAX_STROOPS};

use super::errors::AuthError;

// ---------------------------------------------------------------------------
// Amount validators (auth-context)
// ---------------------------------------------------------------------------

/// Validate that a stroop value is a valid, non-zero Stellar amount
/// and return it as an [`Amount`].
///
/// This is the canonical entry point for validating amounts that appear
/// in auth payloads (login balance snapshots, recovery balance checks,
/// etc.).
pub fn validate_auth_amount(stroops: u64) -> Result<Amount, AuthError> {
    Amount::new(stroops).map_err(|e| AuthError::AmountValidationFailed(e.to_string()))
}

/// Validate a balance delta (e.g. for a deposit or withdrawal in a
/// recovery snapshot).  Rejects zero, negative, and overflow.
pub fn validate_balance_delta(
    current: Amount,
    delta: Amount,
    operation: &str,
) -> Result<Amount, AuthError> {
    match operation {
        "credit" => Amount::accumulate_balance(current, delta)
            .map_err(|e| AuthError::AmountValidationFailed(format!("credit: {e}"))),
        "debit" => Amount::deduct_balance(current, delta)
            .map_err(|e| AuthError::AmountValidationFailed(format!("debit: {e}"))),
        _ => Err(AuthError::ValidationError(format!(
            "unknown operation: {operation}"
        ))),
    }
}

/// Validate that a fee amount is within acceptable bounds for an auth
/// context (e.g. platform fee on a recovery-initiated transfer).
///
/// Uses basis-point calculation through [`Amount::basis_point_fee`] to
/// ensure no precision loss.
pub fn validate_fee_amount(
    principal: Amount,
    bps: u64,
    max_fee_ratio: u64,
) -> Result<Amount, AuthError> {
    let fee = principal
        .basis_point_fee(bps)
        .map_err(|e| AuthError::AmountValidationFailed(format!("fee calc: {e}")))?;

    // Ensure fee doesn't exceed max ratio (in basis points).
    let max_fee = principal
        .basis_point_fee(max_fee_ratio)
        .map_err(|e| AuthError::AmountValidationFailed(format!("fee calc: {e}")))?;

    if fee > max_fee {
        return Err(AuthError::AmountValidationFailed(format!(
            "fee {} exceeds max ratio {} bps",
            fee.stroops(),
            max_fee_ratio
        )));
    }

    Ok(fee)
}

// ---------------------------------------------------------------------------
// Session validators
// ---------------------------------------------------------------------------

/// Validate that a session id is a non-zero positive integer.
pub fn validate_session_id(id: u64) -> Result<u64, AuthError> {
    if id == 0 {
        return Err(AuthError::ValidationError(
            "session id must be positive".into(),
        ));
    }
    Ok(id)
}

/// Validate that a subject string is non-empty and within length bounds.
pub fn validate_subject(subject: &str) -> Result<(), AuthError> {
    if subject.is_empty() {
        return Err(AuthError::ValidationError(
            "subject must not be empty".into(),
        ));
    }
    if subject.len() > 256 {
        return Err(AuthError::ValidationError(
            "subject exceeds maximum length of 256".into(),
        ));
    }
    Ok(())
}

/// Validate that a password meets minimum complexity requirements.
pub fn validate_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::ValidationError(
            "password must be at least 8 characters".into(),
        ));
    }
    if password.len() > 72 {
        return Err(AuthError::ValidationError(
            "password must not exceed 72 characters".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Recovery state validators
// ---------------------------------------------------------------------------

/// Validate that a recovery token has not expired.
pub fn validate_recovery_token_expiry(expires_at: u64, now: u64) -> Result<(), AuthError> {
    if expires_at <= now {
        return Err(AuthError::TokenExpired);
    }
    Ok(())
}

/// Validate that a balance snapshot in a recovery context is consistent:
/// no overflow when added, no underflow when subtracted.
pub fn validate_recovery_balance_consistency(
    previous: Amount,
    claimed: Amount,
    expected_delta: Option<Amount>,
) -> Result<(), AuthError> {
    if let Some(delta) = expected_delta {
        // The claimed balance should equal previous + delta.
        let recomputed = Amount::accumulate_balance(previous, delta)
            .map_err(|e| AuthError::AmountValidationFailed(format!("recovery balance: {e}")))?;
        if recomputed != claimed {
            return Err(AuthError::AmountValidationFailed(
                "recovery balance does not match expected value".into(),
            ));
        }
    }
    // Always validate that claimed balance is within range.
    if claimed.stroops() > MAX_STROOPS {
        return Err(AuthError::AmountValidationFailed(
            "recovery balance exceeds maximum".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::{Amount, MAX_STROOPS};

    // -- Amount validators -------------------------------------------------

    #[test]
    fn validate_auth_amount_valid() {
        let a = validate_auth_amount(1_000_000).unwrap();
        assert_eq!(a.stroops(), 1_000_000);
    }

    #[test]
    fn validate_auth_amount_zero_rejected() {
        assert!(validate_auth_amount(0).is_err());
    }

    #[test]
    fn validate_auth_amount_overflow_rejected() {
        assert!(validate_auth_amount(MAX_STROOPS + 1).is_err());
    }

    #[test]
    fn validate_balance_delta_credit() {
        let current = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(50).unwrap();
        let result = validate_balance_delta(current, delta, "credit").unwrap();
        assert_eq!(result, Amount::from_xlm(150).unwrap());
    }

    #[test]
    fn validate_balance_delta_debit() {
        let current = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(30).unwrap();
        let result = validate_balance_delta(current, delta, "debit").unwrap();
        assert_eq!(result, Amount::from_xlm(70).unwrap());
    }

    #[test]
    fn validate_balance_delta_insufficient_debit() {
        let current = Amount::from_xlm(10).unwrap();
        let delta = Amount::from_xlm(20).unwrap();
        assert!(validate_balance_delta(current, delta, "debit").is_err());
    }

    #[test]
    fn validate_balance_delta_unknown_operation() {
        let current = Amount::from_xlm(10).unwrap();
        let delta = Amount::from_xlm(5).unwrap();
        assert!(validate_balance_delta(current, delta, "multiply").is_err());
    }

    #[test]
    fn validate_balance_delta_overflow_credit() {
        let current = Amount::new(MAX_STROOPS).unwrap();
        let delta = Amount::new(1).unwrap();
        assert!(validate_balance_delta(current, delta, "credit").is_err());
    }

    // -- Fee validator -----------------------------------------------------

    #[test]
    fn validate_fee_within_bounds() {
        let principal = Amount::from_xlm(1000).unwrap();
        let fee = validate_fee_amount(principal, 250, 500).unwrap(); // 2.5% fee, max 5%
        assert_eq!(fee, Amount::from_xlm(25).unwrap());
    }

    #[test]
    fn validate_fee_exceeds_max() {
        let principal = Amount::from_xlm(1000).unwrap();
        let result = validate_fee_amount(principal, 500, 250); // 5% fee, max 2.5%
        assert!(result.is_err());
    }

    // -- Session validators ------------------------------------------------

    #[test]
    fn validate_session_id_valid() {
        assert_eq!(validate_session_id(1).unwrap(), 1);
    }

    #[test]
    fn validate_session_id_zero_rejected() {
        assert!(validate_session_id(0).is_err());
    }

    #[test]
    fn validate_subject_valid() {
        assert!(validate_subject("alice").is_ok());
    }

    #[test]
    fn validate_subject_empty_rejected() {
        assert!(validate_subject("").is_err());
    }

    #[test]
    fn validate_subject_too_long_rejected() {
        let long = "x".repeat(257);
        assert!(validate_subject(&long).is_err());
    }

    #[test]
    fn validate_password_valid() {
        assert!(validate_password("securepassword").is_ok());
    }

    #[test]
    fn validate_password_too_short() {
        assert!(validate_password("short").is_err());
    }

    #[test]
    fn validate_password_too_long() {
        let long = "x".repeat(73);
        assert!(validate_password(&long).is_err());
    }

    // -- Recovery validators -----------------------------------------------

    #[test]
    fn validate_recovery_token_expiry_valid() {
        assert!(validate_recovery_token_expiry(200, 100).is_ok());
    }

    #[test]
    fn validate_recovery_token_expiry_expired() {
        assert_eq!(
            validate_recovery_token_expiry(100, 100),
            Err(AuthError::TokenExpired)
        );
    }

    #[test]
    fn validate_recovery_token_expiry_already_past() {
        assert_eq!(
            validate_recovery_token_expiry(50, 100),
            Err(AuthError::TokenExpired)
        );
    }

    #[test]
    fn validate_recovery_balance_consistent() {
        let prev = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(50).unwrap();
        let claimed = Amount::from_xlm(150).unwrap();
        assert!(validate_recovery_balance_consistency(prev, claimed, Some(delta)).is_ok());
    }

    #[test]
    fn validate_recovery_balance_inconsistent() {
        let prev = Amount::from_xlm(100).unwrap();
        let delta = Amount::from_xlm(50).unwrap();
        let claimed = Amount::from_xlm(200).unwrap(); // wrong!
        assert!(validate_recovery_balance_consistency(prev, claimed, Some(delta)).is_err());
    }

    #[test]
    fn validate_recovery_balance_within_range() {
        let prev = Amount::from_xlm(100).unwrap();
        let claimed = Amount::new(MAX_STROOPS).unwrap();
        assert!(validate_recovery_balance_consistency(prev, claimed, None).is_ok());
    }

    // -- Deterministic oracle tests ----------------------------------------

    /// Verify that fee validation is consistent with the amount module's
    /// oracle tests.
    #[test]
    fn oracle_fee_consistency() {
        let principal = Amount::from_xlm(1000).unwrap();
        let fee_250bps = validate_fee_amount(principal, 250, 10_000).unwrap();
        let manual_fee = Amount::from_xlm(25).unwrap();
        assert_eq!(fee_250bps, manual_fee);
    }

    /// Verify that balance delta validation is lossless.
    #[test]
    fn oracle_delta_lossless() {
        let a = Amount::from_xlm_decimal("1.2345678").unwrap();
        let b = Amount::from_xlm_decimal("0.0000001").unwrap();
        let sum = validate_balance_delta(a, b, "credit").unwrap();
        let expected = Amount::from_xlm_decimal("1.2345679").unwrap();
        assert_eq!(sum, expected);
    }
}
