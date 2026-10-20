//! UTC timestamps for the two documents a release writes, without a date crate.
//!
//! `update.json` wants RFC 3339, an apt `Release` wants RFC 2822, and both want
//! the same instant. The arithmetic is Howard Hinnant's `civil_from_days`, which
//! is short enough to keep beside its tests.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Seconds since the epoch, refusing a clock that reads before 1970.
pub fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs())
}

/// RFC 3339 in UTC with second precision, e.g. `2026-10-20T00:00:00Z`.
pub fn rfc3339(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

/// RFC 2822 in UTC, the `Date:` an apt `Release` carries, e.g.
/// `Tue, 20 Oct 2026 00:00:00 UTC`.
pub fn rfc2822(seconds: u64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let weekday = WEEKDAYS[days.rem_euclid(7) as usize];
    format!(
        "{weekday}, {day:02} {} {year:04} {:02}:{:02}:{:02} UTC",
        MONTHS[(month - 1) as usize],
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn rfc2822_names_the_weekday_and_month() {
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 UTC");
        assert_eq!(rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 UTC");
        assert_eq!(rfc2822(1_767_225_600), "Thu, 01 Jan 2026 00:00:00 UTC");
    }
}
