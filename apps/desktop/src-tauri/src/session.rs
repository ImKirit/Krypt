//! Locking together with Windows: when the session is locked (Win+L, lid, screen timeout)
//! and when the computer wakes up from standby or hibernation.

use std::time::{Duration, SystemTime};

/// The auto-lock thread ticks every few seconds. A much larger gap between two ticks means
/// the computer was asleep in between.
const STANDBY_GAP: Duration = Duration::from_secs(60);

pub fn woke_from_standby(previous_tick: SystemTime, now: SystemTime) -> bool {
    now.duration_since(previous_tick)
        .is_ok_and(|gap| gap > STANDBY_GAP)
}

/// True while the Windows session is locked.
#[cfg(windows)]
pub fn session_locked() -> bool {
    use windows::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK, WTSFreeMemory,
        WTSINFOEXW, WTSQuerySessionInformationW, WTSSessionInfoEx,
    };
    use windows::core::PWSTR;

    let mut buffer = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: Windows allocates `buffer`. It is read only after the call succeeded and only if
    // it is large enough for a WTSINFOEXW, and it is released with WTSFreeMemory as documented.
    unsafe {
        let queried = WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buffer,
            &mut bytes,
        );
        if queried.is_err() || buffer.is_null() {
            return false;
        }
        let locked = if bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
            let info = &*(buffer.0 as *const WTSINFOEXW);
            info.Level == 1
                && info.Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK as i32
        } else {
            false
        };
        WTSFreeMemory(buffer.0.cast());
        locked
    }
}

#[cfg(not(windows))]
pub fn session_locked() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_gap_between_ticks_means_standby() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(!woke_from_standby(start, start + Duration::from_secs(5)));
        assert!(!woke_from_standby(start, start + Duration::from_secs(60)));
        assert!(woke_from_standby(start, start + Duration::from_secs(61)));
        // A clock set backwards is not standby.
        assert!(!woke_from_standby(start, start - Duration::from_secs(600)));
    }
}
