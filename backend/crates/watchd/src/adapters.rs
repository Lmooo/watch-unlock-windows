//! Replaceable device recognition; never invent wearer state.

use crate::{ble::Advertisement, registry::Device};

pub struct Capabilities {
    pub authenticated_challenge: bool,
    pub wearer_state: bool,
}

pub trait DeviceAdapter: Send {
    fn matches(&self, advertisement: &Advertisement) -> bool;
    fn capabilities(&self) -> Capabilities;
}

pub struct AppleBle { identity: [u8; 16] }
impl DeviceAdapter for AppleBle {
    fn matches(&self, advertisement: &Advertisement) -> bool {
        advertisement.manufacturer.iter().any(|(company,_)| *company == 0x004c)
            && crate::irk::is_my_watch(&self.identity, &advertisement.address_string())
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities { authenticated_challenge:false, wearer_state:false }
    }
}

impl Drop for AppleBle {
    fn drop(&mut self) {
        for byte in &mut self.identity { unsafe { std::ptr::write_volatile(byte,0); } }
    }
}

pub fn create(device: &Device) -> anyhow::Result<Box<dyn DeviceAdapter>> {
    match device.adapter.as_str() {
        "apple-ble" => Ok(Box::new(AppleBle { identity:crate::registry::load_identity(&device.id)? })),
        _ => anyhow::bail!("Unsupported adapter"),
    }
}

pub fn scan_json(seconds: u64) -> anyhow::Result<()> {
    if !(1..=120).contains(&seconds) { anyhow::bail!("Scan duration out of range"); }
    let bound = crate::registry::load_devices()?.into_iter().filter_map(|device| {
        let name = device.name.clone();
        create(&device).ok().map(|adapter| (device.id, name, adapter))
    }).collect::<Vec<_>>();
    crate::ble::scan(move |advertisement| {
        use std::io::Write;
        let matched = bound.iter().find(|(_,_,adapter)| adapter.matches(advertisement));
        let event = serde_json::json!({
            "address":advertisement.address_string(),
            "name":advertisement.name,
            "rssi":advertisement.rssi,
            "apple":advertisement.manufacturer.iter().any(|(company,_)| *company == 0x004c),
            "matched_device_id":matched.map(|(id,_,_)| id),
            "matched_name":matched.map(|(_,name,_)| name)
        });
        println!("{event}");
        let _ = std::io::stdout().flush();
    },Some(seconds))
}
