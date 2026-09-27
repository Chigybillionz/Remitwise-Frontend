//! Meridian API — authentication flows and amount precision.
//!
//! This crate provides:
//!
//! - **[`amount`]** — type-safe, overflow-safe Stellar-compatible monetary
//!   amounts with exact integer/decimal rules.
//! - **[`auth`]** — sign-in, refresh, verification, logout, and account
//!   recovery flows that are safe across expiry, retries, multiple tabs,
//!   and device changes.
//!
//! # Design invariants
//!
//! 1. All monetary arithmetic uses checked operations; any overflow or
//!    underflow returns an error *before* any state change.
//! 2. Amounts reject negative values, zero, and values exceeding the
//!    Stellar `i64` range at the validation boundary.
//! 3. Auth flows are idempotent where possible: repeated or concurrent
//!    calls produce the same terminal state and leave no partial state.
//! 4. Stale, failed, or rejected operations never advance to an
//!    authoritative state.

pub mod amount;
pub mod auth;
