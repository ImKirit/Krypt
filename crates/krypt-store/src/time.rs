use std::time::{SystemTime, UNIX_EPOCH};

/// Unix time in milliseconds.
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `20260913-182005-123` in UTC. Sorts chronologically as plain text.
pub(crate) fn stamp(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let of_day = secs.rem_euclid(86_400);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}-{millis:03}",
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
/// Howard Hinnant, "chrono-Compatible Low-Level Date Algorithms".
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_known_dates() {
        assert_eq!(stamp(0), "19700101-000000-000");
        assert_eq!(stamp(951_782_400_000), "20000229-000000-000");
        let evening = 1_789_257_600_000 + 18 * 3_600_000 + 20 * 60_000 + 5_123;
        assert_eq!(stamp(evening), "20260913-182005-123");
    }
}
