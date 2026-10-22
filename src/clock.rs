// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Time helpers.
//!
//! Two clocks are used and never mixed:
//!
//! * [`mono_ms`] — monotonic milliseconds since process start. Every interval,
//!   timeout, quarantine deadline and cooldown is expressed in this domain, so
//!   an NTP step can never make a node look "healthy" or "quarantined" by
//!   accident.
//! * [`unix_ms`] — wall clock, used *only* for log/audit timestamps.
//!
//! Formatting is hand-rolled (civil-from-days) instead of pulling a date crate:
//! the daemon logs a handful of lines per tick, and an RFC 3339 formatter is
//! ~30 lines with no allocation beyond the result string.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static START: OnceLock<Instant> = OnceLock::new();

/// Monotonic milliseconds since process start.
#[inline]
pub fn mono_ms() -> u64 {
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_millis() as u64
}

/// Milliseconds since the Unix epoch.
#[inline]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp with millisecond precision, e.g.
/// `2026-10-22T01:44:07.512Z`.
pub fn rfc3339_ms(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let millis = unix_ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let mut out = String::with_capacity(24);
    use std::fmt::Write as _;
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    );
    out
}

/// Howard Hinnant's `civil_from_days` (days since 1970-01-01 → y/m/d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn known_timestamp_formats() {
        // 2023-11-14T22:13:20Z
        assert_eq!(rfc3339_ms(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(rfc3339_ms(1_700_000_000_007), "2023-11-14T22:13:20.007Z");
    }

    #[test]
    fn leap_day_formats() {
        // 2024-02-29T12:00:00Z
        assert_eq!(rfc3339_ms(1_709_208_000_000), "2024-02-29T12:00:00.000Z");
    }

    #[test]
    fn mono_is_monotonic() {
        let a = mono_ms();
        let b = mono_ms();
        assert!(b >= a);
    }
}
