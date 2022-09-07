
macro_rules! win32_try {
    (unsafe $e:expr) => {
        if unsafe { !($e).as_bool() } {
            return Err(::winfsp::error::FspError::from(unsafe { GetLastError() }));
        }
    };
}
use time::{Month, OffsetDateTime, Weekday};
use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows::Win32::System::Time::SystemTimeToFileTime;
pub(crate) use win32_try;

#[inline(always)]
pub const fn quadpart_to_u64(hi: u32, lo: u32) -> u64 {
    (hi as u64) << 32 | lo as u64
}

/// changes systemtime to filetime.
/// if the input time is invalid for SYSTEMTIME, panics.
pub fn systemtime_to_filetime(time: OffsetDateTime) -> u64 {
    assert!(time.year() >= 1601 && time.year() <= 30827);

    let sys_time = SYSTEMTIME {
        wYear: time.year() as u16,
        wMonth: time_month_to_u16(time.month()),
        wDayOfWeek: time_week_to_u16(time.weekday()),
        wDay: time.day() as u16,
        wHour: time.hour() as u16,
        wMinute: time.minute() as u16,
        wSecond: time.second() as u16,
        wMilliseconds: time.millisecond()
    };

    let mut ftime = FILETIME::default();
    unsafe {
        SystemTimeToFileTime(&sys_time, &mut ftime);
    }

    quadpart_to_u64(ftime.dwHighDateTime, ftime.dwLowDateTime)
}

const fn time_month_to_u16(m: Month) -> u16 {
    match m {
        Month::January => 1,
        Month::February => 2,
        Month::March => 3,
        Month::April => 4,
        Month::May => 5,
        Month::June => 6,
        Month::July => 7,
        Month::August => 8,
        Month::September => 9,
        Month::October => 10,
        Month::November => 11,
        Month::December => 12
    }
}

const fn time_week_to_u16(w: Weekday) -> u16 {
    match w {
        Weekday::Monday => 1,
        Weekday::Tuesday => 2,
        Weekday::Wednesday => 3,
        Weekday::Thursday => 4,
        Weekday::Friday => 5,
        Weekday::Saturday => 6,
        Weekday::Sunday => 0,
    }
}