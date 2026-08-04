//! Resolve a kernel `(major, minor)` device number to a real `/dev` path and a
//! role.
//!
//! The eBPF side deliberately does not decode this. ALSA's minor numbering is
//! not a stable arithmetic formula across cards — on this machine card 0's
//! control node is minor 11 while card 1's is minor 7 — so the mapping is
//! discovered by scanning `/dev`, where it can be verified and tested rather
//! than guessed at inside a verifier-constrained program.
//!
//! # Two incompatible dev_t encodings
//!
//! This bit an earlier version of this file and is worth stating plainly:
//!
//! * The **kernel's internal** `inode->i_rdev`, which is what the eBPF program
//!   reads, packs `major << 20 | minor`.
//! * **glibc's `st_rdev`**, which is what [`MetadataExt::rdev`] returns, uses a
//!   different split entirely (`major` lands at bits 8..20 plus a high part).
//!
//! Decoding one with the other's rules silently yields major 0 and matches
//! nothing. Use [`kernel_major`]/[`kernel_minor`] for values that came from
//! eBPF, and `libc::major`/`libc::minor` for values that came from `stat`.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const V4L2_MAJOR: u32 = 81;
pub const ALSA_MAJOR: u32 = 116;

/// What a device node is actually for. Drives how loud an event is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    /// Video capture — the thing with no protection at all today.
    Camera,
    /// Audio capture: `/dev/snd/pcmC*D*c`. The microphone.
    AudioCapture,
    /// Audio playback: `/dev/snd/pcmC*D*p`. Expected and uninteresting.
    AudioPlayback,
    /// Mixer/control: `/dev/snd/controlC*`. Opened constantly by anything
    /// that merely enumerates audio devices — noise, not access.
    AudioControl,
    /// `/dev/snd/hwC*D*`, timer, seq, and anything unrecognised.
    Other,
}

impl DeviceRole {
    /// Whether this is an actual privacy-relevant capture event.
    /// Playback and control opens are noise for our purposes.
    pub fn is_capture(self) -> bool {
        matches!(self, DeviceRole::Camera | DeviceRole::AudioCapture)
    }

    pub fn label(self) -> &'static str {
        match self {
            DeviceRole::Camera => "CAMERA",
            DeviceRole::AudioCapture => "MIC",
            DeviceRole::AudioPlayback => "playback",
            DeviceRole::AudioControl => "control",
            DeviceRole::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceNode {
    pub path: PathBuf,
    pub role: DeviceRole,
}

/// Lazily-refreshed map of `(major, minor)` -> device node.
pub struct DeviceIndex {
    map: HashMap<(u32, u32), DeviceNode>,
}

impl DeviceIndex {
    pub fn new() -> Self {
        let mut idx = DeviceIndex {
            map: HashMap::new(),
        };
        idx.rescan();
        idx
    }

    /// Rebuild from `/dev`. Cheap — a handful of `stat` calls.
    pub fn rescan(&mut self) {
        self.map.clear();
        self.scan_dir(Path::new("/dev"), false);
        self.scan_dir(Path::new("/dev/snd"), true);
    }

    /// Number of device nodes currently indexed.
    #[allow(dead_code)] // used by tests; kept as part of the type's contract
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)] // used by tests
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn scan_dir(&mut self, dir: &Path, take_all: bool) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();

            // In /dev itself we only care about video*; /dev/snd is scanned
            // whole. Avoids stat'ing several hundred unrelated nodes.
            if !take_all && !name.starts_with("video") {
                continue;
            }

            let md = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // glibc encoding here — this came from stat(), not from eBPF.
            let rdev = md.rdev();
            let major = libc::major(rdev);
            let minor = libc::minor(rdev);

            if major != V4L2_MAJOR && major != ALSA_MAJOR {
                continue;
            }

            self.map.insert(
                (major, minor),
                DeviceNode {
                    path: path.clone(),
                    role: classify(major, &name),
                },
            );
        }
    }

    /// Look up a device by the `(major, minor)` reported by the eBPF program.
    /// Rescans once on a miss, to pick up hotplugged hardware without polling.
    pub fn lookup(&mut self, major: u32, minor: u32) -> Option<DeviceNode> {
        if let Some(d) = self.map.get(&(major, minor)) {
            return Some(d.clone());
        }
        self.rescan();
        self.map.get(&(major, minor)).cloned()
    }
}

impl Default for DeviceIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode the **kernel's internal** `dev_t` (`inode->i_rdev`), as read by the
/// eBPF program. See `include/linux/kdev_t.h`: `major << MINORBITS | minor`
/// with `MINORBITS == 20`.
///
/// Do NOT use this on a `st_rdev` from `stat()` — that is glibc-encoded.
///
/// Currently unused at runtime: the eBPF program does the shift in C and sends
/// already-split `(major, minor)`. Kept because it is the executable
/// specification of that split, and because the regression test below uses it
/// to prove the two encodings really do disagree.
#[allow(dead_code)]
pub fn kernel_major(rdev: u64) -> u32 {
    (rdev >> 20) as u32
}

/// See [`kernel_major`].
#[allow(dead_code)]
pub fn kernel_minor(rdev: u64) -> u32 {
    (rdev & 0xF_FFFF) as u32
}

/// Classify by node name. ALSA encodes the role in the filename far more
/// reliably than in the minor number:
///   pcmC0D0c -> capture      pcmC0D0p -> playback
///   controlC0 -> control     hwC0D0   -> hwdep
fn classify(major: u32, name: &str) -> DeviceRole {
    if major == V4L2_MAJOR {
        return DeviceRole::Camera;
    }
    if name.starts_with("pcm") {
        if name.ends_with('c') {
            return DeviceRole::AudioCapture;
        }
        if name.ends_with('p') {
            return DeviceRole::AudioPlayback;
        }
        return DeviceRole::Other;
    }
    if name.starts_with("control") {
        return DeviceRole::AudioControl;
    }
    DeviceRole::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_kernel_internal_dev_t() {
        // What the eBPF program reads out of inode->i_rdev.
        let video0: u64 = 81 << 20;
        assert_eq!(kernel_major(video0), 81);
        assert_eq!(kernel_minor(video0), 0);

        let pcm: u64 = (116 << 20) | 9;
        assert_eq!(kernel_major(pcm), 116);
        assert_eq!(kernel_minor(pcm), 9);
    }

    /// Regression test for a real bug: an earlier version decoded `st_rdev`
    /// with the kernel's rules, which yields major 0 for every node, so the
    /// index came up empty while the synthetic unit tests all passed.
    #[test]
    fn glibc_and_kernel_dev_t_encodings_are_not_interchangeable() {
        let md = match std::fs::metadata("/dev/video0") {
            Ok(m) => m,
            Err(_) => return, // no camera on this machine — skip
        };
        let raw = md.rdev();

        assert_eq!(libc::major(raw), 81, "glibc decode must give 81");
        assert_ne!(
            kernel_major(raw),
            81,
            "if these ever agree this test is no longer proving anything"
        );
    }

    #[test]
    fn classifies_alsa_nodes_by_name_not_by_minor() {
        assert_eq!(classify(ALSA_MAJOR, "pcmC0D0c"), DeviceRole::AudioCapture);
        assert_eq!(classify(ALSA_MAJOR, "pcmC0D0p"), DeviceRole::AudioPlayback);
        assert_eq!(classify(ALSA_MAJOR, "pcmC1D7p"), DeviceRole::AudioPlayback);
        assert_eq!(classify(ALSA_MAJOR, "controlC0"), DeviceRole::AudioControl);
        assert_eq!(classify(ALSA_MAJOR, "hwC0D0"), DeviceRole::Other);
        assert_eq!(classify(ALSA_MAJOR, "timer"), DeviceRole::Other);
    }

    #[test]
    fn any_v4l2_node_is_a_camera_regardless_of_name() {
        assert_eq!(classify(V4L2_MAJOR, "video0"), DeviceRole::Camera);
        assert_eq!(classify(V4L2_MAJOR, "video1"), DeviceRole::Camera);
    }

    #[test]
    fn only_capture_roles_count_as_privacy_relevant() {
        assert!(DeviceRole::Camera.is_capture());
        assert!(DeviceRole::AudioCapture.is_capture());
        assert!(!DeviceRole::AudioPlayback.is_capture());
        assert!(!DeviceRole::AudioControl.is_capture());
        assert!(!DeviceRole::Other.is_capture());
    }

    /// The test that would have caught the encoding bug: the index must
    /// actually find hardware, keyed by the numbers eBPF will report.
    #[test]
    fn index_finds_real_hardware_keyed_by_kernel_numbers() {
        let mut idx = DeviceIndex::new();

        if std::path::Path::new("/dev/video0").exists() {
            let cam = idx
                .lookup(V4L2_MAJOR, 0)
                .expect("/dev/video0 exists but the index did not find it at (81, 0)");
            assert_eq!(cam.role, DeviceRole::Camera);
            assert_eq!(cam.path, PathBuf::from("/dev/video0"));
        }

        if std::path::Path::new("/dev/snd").exists() {
            assert!(!idx.is_empty(), "/dev/snd exists but nothing was indexed");
        }
    }
}
