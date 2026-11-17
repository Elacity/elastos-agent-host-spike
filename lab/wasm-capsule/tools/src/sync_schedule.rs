//! M3 P2-6 (P10, P12): when each owner device syncs pins.
//!
//! Every device is described by typed inputs: a [`Device`] name, a
//! [`Battery`] level, a [`Network`] state and a window length in minutes. The
//! schedule is pure: the same inputs always yield the same windows, so two
//! nodes agreeing on the inputs agree on when to sync.
//!
//! P10: a device on a metered network syncs only items whose size is under
//! [`MeteredCap`], so metered transfers stay bounded.
//! P12: sync windows are derived deterministically from the typed device
//! inputs; no wall clock, no randomness and no caller-supplied strings choose
//! a window.
//!
//! Chosen conservative presets (the task gives none):
//! - window length: 30 minutes;
//! - metered item size cap: 1 MiB (`METERED_CAP_BYTES`);
//! - low battery threshold: 20 percent, below which a device sleeps longer;
//! - a low battery device's window is twice `window_min`.

use std::fmt;

/// One mebibyte, the default metered-network item size cap (P10).
pub const METERED_CAP_BYTES: u64 = 1024 * 1024;

/// Low battery threshold in whole percent; below it a device sleeps longer.
pub const LOW_BATTERY_PERCENT: u8 = 20;

/// Battery level in whole percent, 0 to 100.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Battery(u8);

impl Battery {
    /// Build a battery level; more than 100 percent is clamped to 100.
    pub fn new(percent: u8) -> Self {
        Battery(percent.min(100))
    }

    /// The whole percent this level holds.
    pub fn percent(self) -> u8 {
        self.0
    }

    /// True when this device should sleep instead of syncing (P10).
    pub fn is_low(self) -> bool {
        self.0 < LOW_BATTERY_PERCENT
    }
}

/// Network state of a device, typed, never a caller string (P10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    /// Unmetered link: every item is eligible.
    Unmetered,
    /// Metered link: only items under the cap are eligible.
    Metered,
}

/// A metered item size cap in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeteredCap(u64);

impl MeteredCap {
    /// Build a cap from a byte count.
    pub fn new(bytes: u64) -> Self {
        MeteredCap(bytes)
    }

    /// The cap in bytes.
    pub fn bytes(self) -> u64 {
        self.0
    }

    /// True when an item of `size` bytes fits under this cap (P10).
    pub fn admits(self, size: u64) -> bool {
        size < self.0
    }
}

impl Default for MeteredCap {
    fn default() -> Self {
        MeteredCap(METERED_CAP_BYTES)
    }
}

/// One owner device that syncs pins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Device<'a> {
    /// A relative device name, never a host path.
    pub name: &'a str,
    /// Battery level of the device.
    pub battery: Battery,
    /// Network state of the device.
    pub network: Network,
}

/// One scheduled sync window for a device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window<'a> {
    /// The device this window belongs to.
    pub device: &'a str,
    /// Minutes from the schedule start until this window opens.
    pub starts_at_min: u64,
    /// Window length in minutes.
    pub length_min: u64,
    /// Whether this window may only sync items under the cap (P10).
    pub metered_only: bool,
}

/// Why a schedule could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncScheduleError {
    /// No devices were given.
    EmptyDeviceList,
    /// A device name is empty.
    EmptyDeviceName,
    /// A device name reaches outside the capsule (contains `/` or `\`).
    UnsafeDeviceName,
    /// Two devices share a name.
    DuplicateDevice,
    /// The window length is zero.
    ZeroWindow,
    /// The metered cap is zero, so no metered item could ever sync.
    ZeroMeteredCap,
}

impl SyncScheduleError {
    /// Stable snake_case code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            SyncScheduleError::EmptyDeviceList => "empty_device_list",
            SyncScheduleError::EmptyDeviceName => "empty_device_name",
            SyncScheduleError::UnsafeDeviceName => "unsafe_device_name",
            SyncScheduleError::DuplicateDevice => "duplicate_device",
            SyncScheduleError::ZeroWindow => "zero_window",
            SyncScheduleError::ZeroMeteredCap => "zero_metered_cap",
        }
    }
}

impl fmt::Display for SyncScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let explanation = match self {
            SyncScheduleError::EmptyDeviceList => "a schedule needs at least one device",
            SyncScheduleError::EmptyDeviceName => "a device name must not be empty",
            SyncScheduleError::UnsafeDeviceName => "a device name must not contain a path",
            SyncScheduleError::DuplicateDevice => "two devices share one name",
            SyncScheduleError::ZeroWindow => "a sync window must last at least one minute",
            SyncScheduleError::ZeroMeteredCap => "a metered cap must allow at least one byte",
        };
        write!(f, "{}: {}", self.code(), explanation)
    }
}

/// The schedule settings for one run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    /// Length of a normal (awake) window in minutes.
    pub window_min: u64,
    /// Size cap applied to metered devices (P10).
    pub metered_cap: MeteredCap,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            window_min: 30,
            metered_cap: MeteredCap::default(),
        }
    }
}

/// Build a deterministic P10, P12 sync window per device.
///
/// Devices are ordered by name, so the same set always yields the same
/// windows in the same order regardless of input order (P12). A device with
/// low battery gets one longer window; an awake device gets one window of
/// `window_min`. Windows are laid end to end in name order, so each start
/// follows the windows before it. A metered device's window admits only items
/// under `settings.metered_cap` (P10).
pub fn schedule<'a>(
    devices: &[Device<'a>],
    settings: &Settings,
) -> Result<Vec<Window<'a>>, SyncScheduleError> {
    if devices.is_empty() {
        return Err(SyncScheduleError::EmptyDeviceList);
    }
    if settings.window_min == 0 {
        return Err(SyncScheduleError::ZeroWindow);
    }
    if settings.metered_cap.bytes() == 0 {
        return Err(SyncScheduleError::ZeroMeteredCap);
    }
    for (i, device) in devices.iter().enumerate() {
        if device.name.is_empty() {
            return Err(SyncScheduleError::EmptyDeviceName);
        }
        if device.name.contains('/') || device.name.contains('\\') {
            return Err(SyncScheduleError::UnsafeDeviceName);
        }
        if devices[..i].iter().any(|other| other.name == device.name) {
            return Err(SyncScheduleError::DuplicateDevice);
        }
    }

    let mut ordered: Vec<Device<'a>> = devices.to_vec();
    ordered.sort_by(|a, b| a.name.cmp(b.name));

    let mut windows = Vec::with_capacity(ordered.len());
    let mut clock = 0u64;
    for device in ordered {
        let length_min = if device.battery.is_low() {
            settings.window_min.saturating_mul(2)
        } else {
            settings.window_min
        };
        windows.push(Window {
            device: device.name,
            starts_at_min: clock,
            length_min,
            metered_only: device.network == Network::Metered,
        });
        clock = clock.saturating_add(length_min);
    }
    Ok(windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device<'a>(name: &'a str, battery: u8, network: Network) -> Device<'a> {
        Device {
            name,
            battery: Battery::new(battery),
            network,
        }
    }

    // P12: the same inputs give the same schedule, whatever the input order.
    #[test]
    fn schedule_is_deterministic_for_same_inputs() {
        let a = device("laptop", 80, Network::Unmetered);
        let b = device("phone", 50, Network::Metered);
        let s = Settings::default();
        let one = schedule(&[a, b], &s).expect("schedule");
        let two = schedule(&[b, a], &s).expect("schedule");
        assert_eq!(one, two);
        let names: Vec<&str> = one.iter().map(|w| w.device).collect();
        assert_eq!(names, vec!["laptop", "phone"]);
    }

    // P10: a metered device's window admits only items under the cap.
    #[test]
    fn metered_device_syncs_only_under_cap() {
        let d = device("phone", 90, Network::Metered);
        let s = Settings {
            window_min: 30,
            metered_cap: MeteredCap::new(2048),
        };
        let windows = schedule(&[d], &s).expect("schedule");
        assert!(windows[0].metered_only);
        assert!(s.metered_cap.admits(0));
        assert!(s.metered_cap.admits(2047));
        assert!(!s.metered_cap.admits(2048));
    }

    // P10: an unmetered device sees every item, so its window is not capped.
    #[test]
    fn unmetered_device_window_is_uncapped() {
        let d = device("desktop", 90, Network::Unmetered);
        let windows = schedule(&[d], &Settings::default()).expect("schedule");
        assert!(!windows[0].metered_only);
    }

    // P12: windows are laid end to end so no device syncs at the same time.
    #[test]
    fn windows_do_not_overlap() {
        let devices = [
            device("a", 90, Network::Unmetered),
            device("b", 10, Network::Unmetered),
            device("c", 90, Network::Unmetered),
        ];
        let s = Settings::default();
        let windows = schedule(&devices, &s).expect("schedule");
        for pair in windows.windows(2) {
            assert_eq!(
                pair[1].starts_at_min,
                pair[0].starts_at_min + pair[0].length_min
            );
        }
        // Low battery lengthens a window so the device wakes less often.
        assert_eq!(windows[1].length_min, s.window_min * 2);
    }

    // P10: every limit at zero is refused with its own code.
    #[test]
    fn zero_limits_are_refused() {
        let d = device("a", 90, Network::Unmetered);
        let one = [d];
        let zero_window = Settings {
            window_min: 0,
            metered_cap: MeteredCap::new(1),
        };
        let err = schedule(&one, &zero_window).unwrap_err();
        assert_eq!(err.code(), "zero_window");
        let zero_cap = Settings {
            window_min: 1,
            metered_cap: MeteredCap::new(0),
        };
        let err = schedule(&one, &zero_cap).unwrap_err();
        assert_eq!(err.code(), "zero_metered_cap");
    }

    // P12: bad device inputs are refused by code, never a host path.
    #[test]
    fn bad_devices_are_refused_by_code() {
        let s = Settings::default();
        let err = schedule(&[], &s).unwrap_err();
        assert_eq!(err.code(), "empty_device_list");
        let empty = [device("", 90, Network::Unmetered)];
        let err = schedule(&empty, &s).unwrap_err();
        assert_eq!(err.code(), "empty_device_name");
        let unsafe_names = [device("../x", 90, Network::Unmetered)];
        let err = schedule(&unsafe_names, &s).unwrap_err();
        assert_eq!(err.code(), "unsafe_device_name");
        let dup = [
            device("x", 90, Network::Unmetered),
            device("x", 90, Network::Metered),
        ];
        let err = schedule(&dup, &s).unwrap_err();
        assert_eq!(err.code(), "duplicate_device");
    }

    // P12: Display renders the code first and adds no host path.
    #[test]
    fn display_renders_code_prefix() {
        let err = SyncScheduleError::DuplicateDevice;
        let text = err.to_string();
        assert!(text.starts_with("duplicate_device: "));
    }
}
