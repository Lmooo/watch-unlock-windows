//! Read-only list of Windows-paired Bluetooth LE devices for the desktop UI.
//! Never pairs, never reads keys. Names and addresses are public metadata.

use anyhow::Result;
use serde_json::{json, Value};
use windows::Devices::Bluetooth::BluetoothLEDevice;
use windows::Devices::Enumeration::DeviceInformation;
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

/// Formats the 48-bit identity address the same way `ble::Advertisement::address_string` does.
pub fn format_address(raw: u64) -> String {
    let bytes = raw.to_be_bytes();
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7])
}

/// Friendly name from Windows, with control characters and excess length removed.
fn clean_name(value: &str) -> Option<String> {
    let cleaned: String = value.chars().filter(|c| !c.is_control()).take(80).collect();
    (!cleaned.trim().is_empty()).then(|| cleaned.trim().to_owned())
}

/// Returns `(name, address)` for each device that Windows reports as paired over LE.
/// Devices whose WinRT object cannot be opened are skipped rather than failing the list.
pub fn list() -> Result<Vec<(Option<String>, String)>> {
    // Already-initialized apartments return an error that is safe to ignore.
    unsafe { let _ = RoInitialize(RO_INIT_MULTITHREADED); }
    let selector = BluetoothLEDevice::GetDeviceSelectorFromPairingState(true)?;
    let infos = DeviceInformation::FindAllAsyncAqsFilter(&selector)?.get()?;
    let mut paired = Vec::new();
    for info in infos {
        let Ok(id) = info.Id() else { continue };
        let Ok(device) = BluetoothLEDevice::FromIdAsync(&id).and_then(|op| op.get()) else { continue };
        let Ok(raw) = device.BluetoothAddress() else { continue };
        let name = device.Name().ok().map(|n| n.to_string()).and_then(|n| clean_name(&n));
        paired.push((name, format_address(raw)));
    }
    Ok(paired)
}

/// Snapshot for the UI. `bound` means a登记设备 already holds this identity address.
pub fn snapshot() -> Result<Value> {
    let bound: Vec<String> = crate::registry::load_devices()?
        .into_iter()
        .filter_map(|device| device.address)
        .collect();
    let devices = list()?.into_iter().map(|(name, address)| {
        let is_bound = bound.contains(&address);
        json!({"name": name, "address": address, "bound": is_bound})
    }).collect::<Vec<_>>();
    Ok(json!({"devices": devices}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_format_matches_scanner_byte_order() {
        // Scanner puts the most significant byte first in the low 48 bits.
        assert_eq!(format_address(0x00C0_FFEE_1122), "00:C0:FF:EE:11:22");
        assert_eq!(format_address(0xFFFF_FFFF_FFFF), "FF:FF:FF:FF:FF:FF");
    }

    #[test]
    fn names_drop_controls_and_blank_values() {
        assert_eq!(clean_name("  Watch\u{0007} "), Some("Watch".into()));
        assert_eq!(clean_name("\u{0001}   "), None);
    }
}
