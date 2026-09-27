# meridian-api: Amount Precision & Auth Design

**Issue:** #1642 — Quality/High: authentication and account recovery: amount precision and overflow
**Date:** 2026-08-28

---

## Overview

This module implements production-grade amount precision and overflow-safe authentication/account-recovery flows for the Meridian API layer.  It addresses the security and UX-correctness concerns raised in #1642.

---

## Architecture

```
meridian-api/src/
├── lib.rs                  # Crate root — re-exports amount and auth
├── amount.rs               # Type-safe Stellar amounts with checked arithmetic
└── auth/
    ├── mod.rs              # Auth module root — re-exports public types
    ├── errors.rs           # AuthError enum with structured context
    ├── tokens.rs           # Token lifecycle (issue, verify, refresh, revoke)
    ├── flows.rs            # Sign-in, logout, verification flows
    ├── recovery.rs         # Account recovery (two-phase, idempotent)
    └── validation.rs       # Auth-context validation helpers
```

---

## Design Invariants

### Amount Precision (`amount.rs`)

1. **Strictly positive**: An `Amount` is always `> 0`.  Zero and negative values are rejected at construction time via `Amount::new()`.
2. **Stellar range**: The raw stroop value is `<= i64::MAX` (9,223,372,036,854,775,807).  Stored as `u64` to prevent accidental negative arithmetic.
3. **Exact decimal conversion**: `from_xlm_decimal()` rejects strings with more than 7 fractional digits (loss-of-precision guard).
4. **Checked arithmetic**: All operations (`checked_add`, `checked_sub`, `checked_mul_u64`, `checked_div_u64`) use checked primitives.  Overflow/underflow/divide-by-zero returns `AmountError` *before* any state change.
5. **128-bit intermediates**: Basis-point and percentage fee calculations use `u128` intermediates to prevent overflow during multiplication, then validate the result fits in the Stellar range.
6. **Balance accumulation**: `accumulate_balance()` and `deduct_balance()` are the canonical ways to update balances — checked arithmetic happens before the caller writes to storage.

### Auth Flows (`auth/`)

7. **Stale token rejection**: Expired, revoked, or unknown tokens are rejected without advancing to any authoritative state.
8. **Token rotation**: Refresh tokens are rotated on every use.  The old refresh token is immediately revoked.  Replay of a rotated token revokes the entire session.
9. **Multi-device safety**: Concurrent logins create independent sessions.  Logout revokes all tokens for a user.
10. **Recovery idempotency**: Repeated recovery requests for the same session produce the same outcome.  Only the first recovery completes; subsequent attempts are rejected.
11. **Amount validation before state change**: Balance snapshots in login responses are validated through `Amount` before any tokens are issued.  Invalid balances cause login to fail cleanly — no rounding, truncation, or silent clamping.
12. **No partial state on failure**: Any failed or rejected operation leaves zero side-effects.

---

## Failure Behavior

| Condition | Amount Module | Auth Module |
|---|---|---|
| Zero amount | `Err(AmountError::Zero)` | `Err(AuthError::AmountValidationFailed)` |
| Overflow | `Err(AmountError::Overflow)` | `Err(AuthError::AmountValidationFailed)` |
| Negative result | `Err(AmountError::NegativeResult)` | `Err(AuthError::AmountValidationFailed)` |
| Divide by zero | `Err(AmountError::DivisionByZero)` | N/A |
| Loss of precision | `Err(AmountError::LossOfPrecision)` | `Err(AuthError::AmountValidationFailed)` |
| Token expired | N/A | `Err(AuthError::TokenExpired)` |
| Token revoked | N/A | `Err(AuthError::TokenRevoked)` |
| Token replay | N/A | `Err(AuthError::TokenAlreadyUsed)` — revokes session |
| Account locked | N/A | `Err(AuthError::AccountLocked { retry_after_secs })` |
| Invalid credentials | N/A | `Err(AuthError::InvalidCredentials)` |
| Recovery already completed | N/A | `Err(AuthError::RecoveryAlreadyCompleted)` |
| Session not found | N/A | `Err(AuthError::SessionNotFound)` |

---

## Compatibility Impact

- **No breaking changes to existing public behavior.**  This module is new and does not modify existing code.
- The `Amount` type uses Stellar's native stroop representation, making it directly compatible with the Stellar SDK's `i64` convention via `as_i64()`.
- All error types are structured enums — callers can match on specific variants for recovery logic.

---

## Migration / Rollout Considerations

- This module is standalone and can be adopted incrementally by existing services.
- Services currently using raw `u64` or `i64` for amounts should migrate to `Amount` to gain overflow protection.
- Token management should replace any existing ad-hoc token handling.

---

## Security Assumptions

1. **System clock is monotonic**: Token expiry relies on `SystemTime`.  Clock skew is out of scope.
2. **Token store integrity**: The in-memory `TokenStore` is a reference implementation.  Production deployments must persist token state with appropriate locking.
3. **No cryptographic verification**: Token signatures are out of scope for this module.  The `TokenInvalid` variant exists for future JWT/signature validation.
4. **Subject uniqueness**: Token subjects (user identifiers) are assumed unique and externally validated.
5. **Recovery channel security**: The mechanism for delivering recovery tokens (email, SMS) is out of scope.  This module only handles the token lifecycle.

---

## Test Coverage

**112 tests** covering:

- **Amount module (50 tests):** Construction (zero, min, max, overflow), decimal parsing (whole, fractional, too many digits, negative, large values), i64 conversion, display formatting, all arithmetic operations (add, sub, mul, div), basis-point fees, percentage fees, balance accumulation/deduction, cross-multiply, roundtrip conversions, and 4 independent oracle tests against known Stellar values.

- **Auth tokens (10 tests):** Issue, verify, expiry, revocation, refresh rotation, replay detection, full session revocation, monotonic IDs, balance stroop preservation.

- **Auth flows (14 tests):** Login success, balance validation (valid, zero, overflow), empty password, lockout, attempt counter reset, logout (single, all), verification, multi-device concurrent sessions, session isolation, refresh, refresh replay.

- **Auth recovery (9 tests):** Request, idempotency, completion (revokes other sessions, issues fresh tokens), replay rejection, cancellation, already-completed rejection, balance non-exposure.

- **Auth validation (29 tests):** Amount validation, balance deltas (credit, debit, insufficient, unknown operation, overflow), fee validation, session ID, subject, password, recovery token expiry, recovery balance consistency, oracle fee/delta tests.

---

## Validation Commands

```bash
cargo fmt -- --check     # formatting
cargo clippy -- -D warnings  # linting
cargo test               # full test suite (112 tests)
```

All three pass cleanly as of 2026-08-28.

---

## Files Changed

| File | Lines | Description |
|---|---|---|
| `meridian-api/Cargo.toml` | 11 | Crate configuration |
| `meridian-api/src/lib.rs` | 25 | Crate root with module docs |
| `meridian-api/src/amount.rs` | ~720 | Amount type, arithmetic, 50 tests |
| `meridian-api/src/auth/mod.rs` | 30 | Auth module root |
| `meridian-api/src/auth/errors.rs` | 75 | AuthError enum |
| `meridian-api/src/auth/tokens.rs` | ~420 | Token lifecycle, 10 tests |
| `meridian-api/src/auth/flows.rs` | ~500 | Auth flows, 14 tests |
| `meridian-api/src/auth/recovery.rs` | ~400 | Recovery flow, 9 tests |
| `meridian-api/src/auth/validation.rs` | ~290 | Validation helpers, 29 tests |
| `meridian-api/DESIGN.md` | This file | Design documentation |

**No unrelated refactors, no disabled CI, no generated noise, no secrets.**
