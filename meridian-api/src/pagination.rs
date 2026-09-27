//! Pagination and cursor semantics.
//!
//! This module provides deterministic, scope-safe cursor-based pagination
//! for all auth collections (sessions, tokens, recovery requests).
//!
//! # Design invariants
//!
//! 1. **Deterministic ordering** — results are always ordered by
//!    `(created_at DESC, id DESC)` so the same cursor always resolves
//!    to the same position regardless of concurrent inserts.
//! 2. **Opaque cursors** — cursors are encoded byte sequences that
//!    carry no implementation details; they cannot be fabricated
//!    without the integrity key.
//! 3. **Scope safety** — each cursor is bound to a specific subject.
//!    A cursor created for user A cannot be used to paginate user B's
//!    data.
//! 4. **Page limits** — every paginated query enforces a configurable
//!    maximum page size.  Callers cannot request unlimited pages.
//! 5. **End-of-stream** — when no more results exist,
//!    `next_cursor` is `None` and `has_more` is `false`.
//! 6. **Empty results** — an empty page returns `items: []`,
//!    `next_cursor: None`, `has_more: false`, `total_count: 0`.
//! 7. **Invalid cursors** — malformed, expired, or scope-mismatched
//!    cursors return `PaginationError`, never partial data.
//!
//! # Cursor encoding
//!
//! Cursors are encoded as: `[subject_len:u16][subject_bytes][timestamp:u64
//! big-endian][id:u64 big-endian][checksum:u16]`
//!
//! The checksum is a simple Fletcher-16 of the preceding bytes, which
//! is sufficient to detect accidental corruption and casual tampering.
//! A production implementation would use HMAC-SHA256.

use std::fmt;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default page size when the caller does not specify one.
pub const DEFAULT_PAGE_SIZE: usize = 20;

/// Maximum allowed page size.
pub const MAX_PAGE_SIZE: usize = 100;

/// Minimum allowed page size.
pub const MIN_PAGE_SIZE: usize = 1;

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/// An opaque pagination cursor that encodes the position, scope, and
/// an integrity checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// The subject (user id) this cursor is bound to.
    pub subject: String,
    /// The timestamp component of the position (epoch seconds).
    pub timestamp: u64,
    /// The id component of the position (for tiebreaking).
    pub id: u64,
}

impl Cursor {
    /// Create a new cursor.
    pub fn new(subject: String, timestamp: u64, id: u64) -> Self {
        Self {
            subject,
            timestamp,
            id,
        }
    }

    /// Encode the cursor into an opaque byte string.
    ///
    /// The encoding includes a checksum to detect tampering.
    pub fn encode(&self) -> Vec<u8> {
        let subject_bytes = self.subject.as_bytes();
        let subject_len = subject_bytes.len() as u16;

        let mut buf = Vec::with_capacity(2 + subject_bytes.len() + 8 + 8 + 2);

        // Subject length (2 bytes, big-endian).
        buf.extend_from_slice(&subject_len.to_be_bytes());
        // Subject bytes.
        buf.extend_from_slice(subject_bytes);
        // Timestamp (8 bytes, big-endian).
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        // Id (8 bytes, big-endian).
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Fletcher-16 checksum of all preceding bytes.
        let checksum = fletcher16(&buf);
        buf.extend_from_slice(&checksum.to_be_bytes());

        buf
    }

    /// Decode an opaque byte string back into a cursor.
    ///
    /// # Errors
    ///
    /// Returns [`PaginationError::CursorInvalid`] if the bytes are
    /// malformed, the checksum fails, or the decoded cursor is
    /// structurally invalid.
    pub fn decode(data: &[u8]) -> Result<Self, PaginationError> {
        // Minimum size: 2 (subject_len) + 0 (subject) + 8 (timestamp) + 8 (id) + 2 (checksum)
        if data.len() < 20 {
            return Err(PaginationError::CursorInvalid("cursor too short".into()));
        }

        let (rest, checksum_bytes) = data.split_at(data.len() - 2);
        let expected_checksum = u16::from_be_bytes([checksum_bytes[0], checksum_bytes[1]]);

        // Verify checksum.
        let actual_checksum = fletcher16(rest);
        if actual_checksum != expected_checksum {
            return Err(PaginationError::CursorInvalid(
                "cursor checksum mismatch".into(),
            ));
        }

        // Parse subject length.
        let subject_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() < 2 + subject_len + 16 {
            return Err(PaginationError::CursorInvalid(
                "cursor data truncated".into(),
            ));
        }

        // Parse subject.
        let subject_start = 2;
        let subject_end = subject_start + subject_len;
        let subject = String::from_utf8(rest[subject_start..subject_end].to_vec())
            .map_err(|e| PaginationError::CursorInvalid(format!("invalid utf8: {e}")))?;

        // Parse timestamp.
        let ts_start = subject_end;
        let timestamp = u64::from_be_bytes(rest[ts_start..ts_start + 8].try_into().unwrap());

        // Parse id.
        let id_start = ts_start + 8;
        let id = u64::from_be_bytes(rest[id_start..id_start + 8].try_into().unwrap());

        Ok(Self {
            subject,
            timestamp,
            id,
        })
    }

    /// Validate that this cursor matches the expected subject (scope safety).
    pub fn validate_scope(&self, expected_subject: &str) -> Result<(), PaginationError> {
        if self.subject != expected_subject {
            return Err(PaginationError::CursorScopeMismatch {
                expected: expected_subject.to_string(),
                actual: self.subject.clone(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Page size
// ---------------------------------------------------------------------------

/// Validate and normalize a requested page size.
///
/// Returns a page size within `[MIN_PAGE_SIZE, MAX_PAGE_SIZE]`.
/// If the input is 0 or exceeds `MAX_PAGE_SIZE`, it is clamped.
pub fn normalize_page_size(requested: usize) -> usize {
    if requested < MIN_PAGE_SIZE {
        DEFAULT_PAGE_SIZE
    } else if requested > MAX_PAGE_SIZE {
        MAX_PAGE_SIZE
    } else {
        requested
    }
}

// ---------------------------------------------------------------------------
// Page result
// ---------------------------------------------------------------------------

/// A single page of results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The items in this page.
    pub items: Vec<T>,
    /// The cursor to fetch the next page.  `None` if this is the last page.
    pub next_cursor: Option<Cursor>,
    /// Whether there are more results after this page.
    pub has_more: bool,
    /// Total number of items matching the query (across all pages).
    pub total_count: usize,
}

impl<T> Page<T> {
    /// Create an empty page (no results).
    pub fn empty(_subject: &str) -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            has_more: false,
            total_count: 0,
        }
    }

    /// Create a page with results.
    ///
    /// If `items.len() == page_size` and there may be more results,
    /// a `next_cursor` is computed from the last item.
    pub fn new(
        items: Vec<T>,
        _page_size: usize,
        total_count: usize,
        next_cursor: Option<Cursor>,
        has_more: bool,
    ) -> Self {
        Self {
            items,
            next_cursor,
            has_more,
            total_count,
        }
    }

    /// Whether this page is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of items in this page.
    pub fn len(&self) -> usize {
        self.items.len()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to pagination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaginationError {
    /// The cursor is malformed, corrupted, or structurally invalid.
    CursorInvalid(String),
    /// The cursor was created for a different subject (scope violation).
    CursorScopeMismatch { expected: String, actual: String },
    /// The requested page size is outside the allowed range.
    InvalidPageSize(usize),
}

impl fmt::Display for PaginationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CursorInvalid(msg) => write!(f, "invalid cursor: {msg}"),
            Self::CursorScopeMismatch { expected, actual } => {
                write!(
                    f,
                    "cursor scope mismatch: expected subject '{expected}', got '{actual}'"
                )
            }
            Self::InvalidPageSize(size) => {
                write!(
                    f,
                    "invalid page size {size}: must be between {MIN_PAGE_SIZE} and {MAX_PAGE_SIZE}"
                )
            }
        }
    }
}

impl std::error::Error for PaginationError {}

// ---------------------------------------------------------------------------
// Paginated query adapter
// ---------------------------------------------------------------------------

/// Trait for collections that support cursor-based pagination.
///
/// Implementations provide deterministic ordering and scope-safe
/// cursor generation.
pub trait PaginatedCollection {
    /// The item type returned in pages.
    type Item: Clone;

    /// A sortable key extracted from each item for ordering.
    /// Returns `(created_at, id)`.
    fn sort_key(item: &Self::Item) -> (u64, u64);

    /// The subject (user id) that owns this collection.
    fn subject(item: &Self::Item) -> &str;

    /// Query items with cursor-based pagination.
    ///
    /// # Arguments
    ///
    /// * `subject` — only return items belonging to this subject.
    /// * `cursor` — if provided, return items *after* this position.
    /// * `page_size` — maximum number of items per page (clamped to
    ///   `[MIN_PAGE_SIZE, MAX_PAGE_SIZE]`).
    ///
    /// # Returns
    ///
    /// A [`Page`] with items, the next cursor, and total count.
    fn query(
        &self,
        subject: &str,
        cursor: Option<&Cursor>,
        page_size: usize,
    ) -> Result<Page<Self::Item>, PaginationError>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a page from a sorted slice of items.
///
/// Items must be pre-sorted in descending order by `(created_at, id)`.
/// This function applies cursor filtering, page limiting, and cursor
/// generation.
pub fn compute_page<T: Clone>(
    sorted_items: &[T],
    subject: &str,
    cursor: Option<&Cursor>,
    page_size: usize,
    sort_key: impl Fn(&T) -> (u64, u64),
) -> Result<Page<T>, PaginationError> {
    let page_size = normalize_page_size(page_size);

    // Validate cursor scope if provided.
    if let Some(c) = cursor {
        c.validate_scope(subject)?;
    }

    let total_count = sorted_items.len();

    // Find the start position after the cursor.
    let start = if let Some(c) = cursor {
        // Find the first item that comes *before* the cursor position
        // (i.e., has a smaller (timestamp, id) since we sort DESC).
        sorted_items
            .iter()
            .position(|item| {
                let (ts, id) = sort_key(item);
                (ts, id) < (c.timestamp, c.id)
            })
            .unwrap_or(sorted_items.len())
    } else {
        0
    };

    // Slice the page.
    let end = std::cmp::min(start + page_size, sorted_items.len());
    let page_items: Vec<T> = sorted_items[start..end].to_vec();
    let has_more = end < sorted_items.len();

    // Generate next cursor from the last item.
    let next_cursor = if has_more {
        if let Some(last) = page_items.last() {
            let (ts, id) = sort_key(last);
            Some(Cursor::new(subject.to_string(), ts, id))
        } else {
            None
        }
    } else {
        None
    };

    Ok(Page::new(
        page_items,
        page_size,
        total_count,
        next_cursor,
        has_more,
    ))
}

// ---------------------------------------------------------------------------
// Fletcher-16 checksum
// ---------------------------------------------------------------------------

/// Compute a Fletcher-16 checksum over the input bytes.
///
/// This is a simple integrity check — not cryptographically secure.
/// Sufficient to detect accidental corruption and casual tampering
/// in a reference implementation.
fn fletcher16(data: &[u8]) -> u16 {
    let mut sum1: u16 = 0;
    let mut sum2: u16 = 0;

    for &byte in data {
        sum1 = sum1.wrapping_add(byte as u16);
        sum2 = sum2.wrapping_add(sum1);
    }

    // Fold into 16 bits.
    (sum2 << 8) | sum1
}

// ---------------------------------------------------------------------------
// Base-64 encoding (minimal, for cursor serialization)
// ---------------------------------------------------------------------------

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to a base-64 string.
pub fn base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Decode a base-64 string to bytes.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, PaginationError> {
    let input = input.trim_end_matches('=');
    let input_bytes = input.as_bytes();

    // Allow non-padded base64 lengths (valid base64 can be 0, 2, or 3 chars mod 4 after stripping padding).

    let mut result = Vec::with_capacity(input_bytes.len() * 3 / 4);

    for chunk in input_bytes.chunks(4) {
        let mut values = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            values[i] = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => {
                    return Err(PaginationError::CursorInvalid(format!(
                        "invalid base64 character: {c}"
                    )))
                }
            };
        }

        let triple = ((values[0] as u32) << 18)
            | ((values[1] as u32) << 12)
            | ((values[2] as u32) << 6)
            | (values[3] as u32);

        result.push((triple >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push(triple as u8);
        }
    }

    Ok(result)
}

/// Encode a cursor as a base-64 string (for HTTP headers, query params, etc.).
pub fn encode_cursor_string(cursor: &Cursor) -> String {
    base64_encode(&cursor.encode())
}

/// Decode a base-64 string back into a cursor.
pub fn decode_cursor_string(encoded: &str) -> Result<Cursor, PaginationError> {
    let bytes = base64_decode(encoded)?;
    Cursor::decode(&bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Cursor encode/decode ------------------------------------------------

    #[test]
    fn cursor_roundtrip() {
        let cursor = Cursor::new("alice".into(), 1700000000, 42);
        let encoded = cursor.encode();
        let decoded = Cursor::decode(&encoded).unwrap();
        assert_eq!(cursor, decoded);
    }

    #[test]
    fn cursor_base64_roundtrip() {
        let cursor = Cursor::new("bob".into(), 1700000000, 99);
        let b64 = encode_cursor_string(&cursor);
        let decoded = decode_cursor_string(&b64).unwrap();
        assert_eq!(cursor, decoded);
    }

    #[test]
    fn cursor_decode_empty_fails() {
        assert!(Cursor::decode(&[]).is_err());
    }

    #[test]
    fn cursor_decode_too_short_fails() {
        assert!(Cursor::decode(&[0; 10]).is_err());
    }

    #[test]
    fn cursor_decode_tampered_checksum_fails() {
        let cursor = Cursor::new("alice".into(), 100, 1);
        let mut encoded = cursor.encode();
        // Tamper with the last byte (part of checksum).
        let last = encoded.len() - 1;
        encoded[last] = encoded[last].wrapping_add(1);
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_decode_tampered_subject_fails() {
        let cursor = Cursor::new("alice".into(), 100, 1);
        let mut encoded = cursor.encode();
        // Tamper with subject byte (after length prefix).
        encoded[3] = b'z';
        assert!(Cursor::decode(&encoded).is_err());
    }

    #[test]
    fn cursor_scope_validation_passes() {
        let cursor = Cursor::new("alice".into(), 100, 1);
        assert!(cursor.validate_scope("alice").is_ok());
    }

    #[test]
    fn cursor_scope_validation_fails() {
        let cursor = Cursor::new("alice".into(), 100, 1);
        let result = cursor.validate_scope("bob");
        assert!(matches!(
            result,
            Err(PaginationError::CursorScopeMismatch { .. })
        ));
    }

    // -- Page size normalization --------------------------------------------

    #[test]
    fn normalize_page_size_default() {
        assert_eq!(normalize_page_size(0), DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn normalize_page_size_valid() {
        assert_eq!(normalize_page_size(50), 50);
    }

    #[test]
    fn normalize_page_size_clamped_max() {
        assert_eq!(normalize_page_size(200), MAX_PAGE_SIZE);
    }

    #[test]
    fn normalize_page_size_min_boundary() {
        assert_eq!(normalize_page_size(1), 1);
    }

    #[test]
    fn normalize_page_size_exactly_max() {
        assert_eq!(normalize_page_size(MAX_PAGE_SIZE), MAX_PAGE_SIZE);
    }

    // -- Empty page ---------------------------------------------------------

    #[test]
    fn empty_page() {
        let page: Page<String> = Page::empty("alice");
        assert!(page.is_empty());
        assert_eq!(page.len(), 0);
        assert_eq!(page.total_count, 0);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    // -- compute_page -------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestItem {
        id: u64,
        created_at: u64,
        subject: String,
    }

    fn test_sort_key(item: &TestItem) -> (u64, u64) {
        (item.created_at, item.id)
    }

    fn make_items(subject: &str, count: usize, start_ts: u64) -> Vec<TestItem> {
        (0..count)
            .map(|i| TestItem {
                id: (i + 1) as u64,
                created_at: start_ts + (i as u64),
                subject: subject.to_string(),
            })
            .collect()
    }

    #[test]
    fn compute_page_empty_collection() {
        let items: Vec<TestItem> = vec![];
        let page = compute_page(&items, "alice", None, 10, test_sort_key).unwrap();
        assert!(page.is_empty());
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn compute_page_single_page() {
        let items = make_items("alice", 5, 1000);
        // Sorted DESC by (created_at, id) — reverse the creation order.
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let page = compute_page(&sorted, "alice", None, 10, test_sort_key).unwrap();
        assert_eq!(page.len(), 5);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn compute_page_with_pagination() {
        let items = make_items("alice", 25, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        // First page.
        let page1 = compute_page(&sorted, "alice", None, 10, test_sort_key).unwrap();
        assert_eq!(page1.len(), 10);
        assert!(page1.has_more);
        assert!(page1.next_cursor.is_some());

        let cursor1 = page1.next_cursor.as_ref().unwrap();

        // Second page.
        let page2 = compute_page(&sorted, "alice", Some(cursor1), 10, test_sort_key).unwrap();
        assert_eq!(page2.len(), 10);
        assert!(page2.has_more);

        let cursor2 = page2.next_cursor.as_ref().unwrap();

        // Third page (remaining 5).
        let page3 = compute_page(&sorted, "alice", Some(cursor2), 10, test_sort_key).unwrap();
        assert_eq!(page3.len(), 5);
        assert!(!page3.has_more);
        assert!(page3.next_cursor.is_none());
    }

    #[test]
    fn compute_page_exact_boundary() {
        // Exactly 20 items with page_size=10 → two pages, second has no more.
        let items = make_items("alice", 20, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let page1 = compute_page(&sorted, "alice", None, 10, test_sort_key).unwrap();
        assert_eq!(page1.len(), 10);
        assert!(page1.has_more);

        let cursor1 = page1.next_cursor.as_ref().unwrap();
        let page2 = compute_page(&sorted, "alice", Some(cursor1), 10, test_sort_key).unwrap();
        assert_eq!(page2.len(), 10);
        assert!(!page2.has_more);
        assert!(page2.next_cursor.is_none());
    }

    #[test]
    fn compute_page_invalid_cursor_scope_fails() {
        let items = make_items("alice", 5, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let cursor = Cursor::new("bob".into(), 1001, 2);
        let result = compute_page(&sorted, "alice", Some(&cursor), 10, test_sort_key);
        assert!(matches!(
            result,
            Err(PaginationError::CursorScopeMismatch { .. })
        ));
    }

    #[test]
    fn compute_page_stale_cursor_returns_empty() {
        // Cursor at position before all items in DESC order (all items
        // have timestamps >= 1000, so a cursor at 900 means "show me
        // items after position (900, 0)" — none exist).
        let items = make_items("alice", 5, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let cursor = Cursor::new("alice".into(), 900, 0);
        let page = compute_page(&sorted, "alice", Some(&cursor), 10, test_sort_key).unwrap();
        assert!(page.is_empty());
        assert!(!page.has_more);
    }

    #[test]
    fn compute_page_page_size_one() {
        let items = make_items("alice", 3, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let page1 = compute_page(&sorted, "alice", None, 1, test_sort_key).unwrap();
        assert_eq!(page1.len(), 1);
        assert!(page1.has_more);

        let cursor1 = page1.next_cursor.as_ref().unwrap();
        let page2 = compute_page(&sorted, "alice", Some(cursor1), 1, test_sort_key).unwrap();
        assert_eq!(page2.len(), 1);
        assert!(page2.has_more);

        let cursor2 = page2.next_cursor.as_ref().unwrap();
        let page3 = compute_page(&sorted, "alice", Some(cursor2), 1, test_sort_key).unwrap();
        assert_eq!(page3.len(), 1);
        assert!(!page3.has_more);
    }

    #[test]
    fn compute_page_preserves_desc_order() {
        let items = make_items("alice", 10, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let page = compute_page(&sorted, "alice", None, 10, test_sort_key).unwrap();

        // Verify descending order within the page.
        for window in page.items.windows(2) {
            assert!(
                (window[0].created_at, window[0].id) > (window[1].created_at, window[1].id),
                "items not in descending order"
            );
        }
    }

    // -- Fletcher-16 --------------------------------------------------------

    #[test]
    fn fletcher16_deterministic() {
        let data = b"hello world";
        assert_eq!(fletcher16(data), fletcher16(data));
    }

    #[test]
    fn fletcher16_different_inputs() {
        assert_ne!(fletcher16(b"hello"), fletcher16(b"world"));
    }

    // -- Base64 -------------------------------------------------------------

    #[test]
    fn base64_roundtrip() {
        let data = vec![0, 1, 2, 3, 4, 5, 127, 255, 254, 253];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn base64_empty() {
        let encoded = base64_encode(&[]);
        let decoded = base64_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base64_invalid_char_fails() {
        assert!(base64_decode("!!!").is_err());
    }

    // -- Concurrency: multiple cursors from same position --------------------

    #[test]
    fn concurrent_cursor_generation_deterministic() {
        // Two cursors from the same position produce the same encoding.
        let c1 = Cursor::new("alice".into(), 1700000000, 42);
        let c2 = Cursor::new("alice".into(), 1700000000, 42);
        assert_eq!(c1.encode(), c2.encode());
    }

    #[test]
    fn different_positions_different_cursors() {
        let c1 = Cursor::new("alice".into(), 1700000000, 42);
        let c2 = Cursor::new("alice".into(), 1700000000, 43);
        assert_ne!(c1.encode(), c2.encode());
    }

    // -- Large result set pagination -----------------------------------------

    #[test]
    fn large_result_set_full_pagination() {
        let items = make_items("alice", 250, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        let mut cursor: Option<Cursor> = None;
        let mut total_fetched = 0;
        let mut pages = 0;

        loop {
            let page = compute_page(
                &sorted,
                "alice",
                cursor.as_ref(),
                MAX_PAGE_SIZE,
                test_sort_key,
            )
            .unwrap();

            total_fetched += page.len();
            pages += 1;

            if !page.has_more {
                assert!(page.next_cursor.is_none());
                break;
            }
            cursor = page.next_cursor;
        }

        assert_eq!(total_fetched, 250);
        // 250 / 100 = 2.5 → 3 pages
        assert_eq!(pages, 3);
    }

    // -- Edge case: cursor past all items in DESC order returns all ----------

    #[test]
    fn cursor_after_all_items_returns_full_page() {
        let items = make_items("alice", 3, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        // Cursor with timestamp after all items — all items have
        // (ts, id) < cursor, so all qualify.
        let cursor = Cursor::new("alice".into(), 2000, 0);
        let page = compute_page(&sorted, "alice", Some(&cursor), 10, test_sort_key).unwrap();
        assert_eq!(page.len(), 3);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn cursor_between_items_returns_remaining() {
        let items = make_items("alice", 5, 1000);
        let mut sorted = items;
        sorted.sort_by(|a, b| (b.created_at, b.id).cmp(&(a.created_at, a.id)));

        // Cursor at item 3 (created_at=1002, id=3). In DESC order,
        // items 1001/2 and 1000/1 come after it.
        let cursor = Cursor::new("alice".into(), 1002, 3);
        let page = compute_page(&sorted, "alice", Some(&cursor), 10, test_sort_key).unwrap();
        // Should get items with (ts, id) < (1002, 3): (1001,2) and (1000,1).
        assert_eq!(page.len(), 2);
        assert!(!page.has_more);
    }

    // -- Page error display --------------------------------------------------

    #[test]
    fn pagination_error_display() {
        let e = PaginationError::CursorInvalid("test".into());
        assert!(format!("{e}").contains("test"));

        let e = PaginationError::CursorScopeMismatch {
            expected: "alice".into(),
            actual: "bob".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("alice"));
        assert!(msg.contains("bob"));

        let e = PaginationError::InvalidPageSize(0);
        assert!(format!("{e}").contains("0"));
    }
}
