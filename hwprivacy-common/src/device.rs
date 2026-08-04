use serde::{Deserialize, Serialize};
use std::fmt;

/// Categories of protected hardware devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceCategory {
    Microphone,
    Camera,
    Monitor, // playback monitor source (eavesdrop protection)
}

impl DeviceCategory {
    pub fn all() -> &'static [DeviceCategory] {
        &[
            DeviceCategory::Microphone,
            DeviceCategory::Camera,
            DeviceCategory::Monitor,
        ]
    }
}

impl fmt::Display for DeviceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceCategory::Microphone => write!(f, "microphone"),
            DeviceCategory::Camera => write!(f, "camera"),
            DeviceCategory::Monitor => write!(f, "monitor"),
        }
    }
}

impl std::str::FromStr for DeviceCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "microphone" | "mic" => Ok(DeviceCategory::Microphone),
            "camera" | "cam" => Ok(DeviceCategory::Camera),
            "monitor" | "mon" => Ok(DeviceCategory::Monitor),
            _ => Err(format!("Unknown device category: {}", s)),
        }
    }
}

/// A discovered PipeWire device that we protect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedDevice {
    pub category: DeviceCategory,
    /// PipeWire node name (e.g., "alsa_input.pci-0000_00_1f.3.analog-stereo")
    pub node_name: String,
    /// Human-readable description (e.g., "Built-in Audio Analog Stereo")
    pub description: String,
    /// PipeWire object serial
    pub object_serial: u32,
    /// Whether this device is currently guarded
    pub guarded: bool,
}
