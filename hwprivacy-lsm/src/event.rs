//! Wire format shared with `src/bpf/devices.bpf.c`.
//!
//! Parsed by hand rather than transmuted. The eBPF side writes a fixed C
//! layout; decoding it explicitly means a layout drift shows up as a failing
//! test instead of silently misread fields.

pub const COMM_LEN: usize = 16;

/// Byte size of `struct dev_event` in devices.bpf.c.
/// 8 + 4 + 4 + 4 + 4 + 4 + 4 + 16
pub const EVENT_SIZE: usize = 48;

/// A single open() of a video4linux or ALSA device node, as seen by the LSM
/// hook. The kernel reports raw `(major, minor)`; resolving that to a path and
/// a role is `device_index`'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevEvent {
    /// Inode of the calling process's executable.
    pub exe_ino: u64,
    /// Superblock device of that executable. Together with `exe_ino` this is
    /// the policy key — unspoofable, and stable across launches.
    pub exe_dev: u32,
    /// Thread id.
    pub pid: u32,
    /// Process id (thread group leader).
    pub tgid: u32,
    /// Device major: 81 (video4linux) or 116 (alsa).
    pub dev_major: u32,
    /// Device minor. Meaning is card/device-specific; resolve via DeviceIndex.
    pub dev_minor: u32,
    /// Whether the kernel denied this open. Always false in Phase 1.
    pub denied: bool,
    /// Kernel's short process name (comm), max 15 chars + NUL.
    pub comm: String,
}

impl DevEvent {
    /// Decode one event from the ring buffer. Returns `None` on a short read,
    /// which would mean the C and Rust layouts have drifted apart.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < EVENT_SIZE {
            return None;
        }

        let u32_at = |off: usize| -> u32 {
            u32::from_ne_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };

        let exe_ino = u64::from_ne_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let comm_bytes = &data[32..32 + COMM_LEN];
        let end = comm_bytes.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        let comm = String::from_utf8_lossy(&comm_bytes[..end]).into_owned();

        Some(DevEvent {
            exe_ino,
            exe_dev: u32_at(8),
            pid: u32_at(12),
            tgid: u32_at(16),
            dev_major: u32_at(20),
            dev_minor: u32_at(24),
            denied: u32_at(28) != 0,
            comm,
        })
    }

    /// Resolve the real executable behind the process.
    ///
    /// Worth doing even though we already have `(exe_dev, exe_ino)`:
    /// `/usr/bin/firefox` on this machine is a shell script, so the path a
    /// user would name and the path that actually opens the device are
    /// different things. Returns `None` if the process already exited — which
    /// is common for short-lived probes.
    pub fn resolve_exe(&self) -> Option<String> {
        std::fs::read_link(format!("/proc/{}/exe", self.tgid))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// Best-effort full command line, for telling apart several processes
    /// sharing one binary (browser content processes, ffmpeg invocations).
    pub fn resolve_cmdline(&self) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{}/cmdline", self.tgid)).ok()?;
        let s = raw
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a buffer matching struct dev_event in native byte order.
    fn encode(
        exe_ino: u64,
        exe_dev: u32,
        pid: u32,
        tgid: u32,
        major: u32,
        minor: u32,
        denied: u32,
        comm: &str,
    ) -> Vec<u8> {
        let mut v = Vec::with_capacity(EVENT_SIZE);
        v.extend_from_slice(&exe_ino.to_ne_bytes());
        for f in [exe_dev, pid, tgid, major, minor, denied] {
            v.extend_from_slice(&f.to_ne_bytes());
        }
        let mut c = [0u8; COMM_LEN];
        let b = comm.as_bytes();
        let n = b.len().min(COMM_LEN);
        c[..n].copy_from_slice(&b[..n]);
        v.extend_from_slice(&c);
        v
    }

    #[test]
    fn parses_a_well_formed_event() {
        let buf = encode(30027059, 66306, 4242, 4200, 81, 0, 0, "ffmpeg");
        let e = DevEvent::parse(&buf).expect("should parse");

        assert_eq!(e.exe_ino, 30027059);
        assert_eq!(e.exe_dev, 66306);
        assert_eq!(e.pid, 4242);
        assert_eq!(e.tgid, 4200);
        assert_eq!(e.dev_major, 81);
        assert_eq!(e.dev_minor, 0);
        assert!(!e.denied);
        assert_eq!(e.comm, "ffmpeg");
    }

    #[test]
    fn parses_an_alsa_capture_event() {
        // /dev/snd/pcmC0D0c is 116:9 on this machine.
        let buf = encode(1, 2, 3, 4, 116, 9, 0, "ffmpeg");
        let e = DevEvent::parse(&buf).unwrap();
        assert_eq!(e.dev_major, 116);
        assert_eq!(e.dev_minor, 9);
    }

    #[test]
    fn encoded_size_matches_the_c_struct() {
        assert_eq!(encode(0, 0, 0, 0, 0, 0, 0, "x").len(), EVENT_SIZE);
    }

    #[test]
    fn rejects_a_short_buffer() {
        assert!(DevEvent::parse(&[0u8; EVENT_SIZE - 1]).is_none());
    }

    #[test]
    fn comm_without_a_nul_terminator_uses_the_full_field() {
        // comm is exactly 16 bytes with no room for a NUL — must not panic
        // and must not read past the field.
        let buf = encode(1, 2, 3, 4, 81, 1, 1, "abcdefghijklmnop");
        let e = DevEvent::parse(&buf).expect("should parse");
        assert_eq!(e.comm, "abcdefghijklmnop");
        assert!(e.denied);
    }

    #[test]
    fn tolerates_a_longer_buffer_than_expected() {
        // Ring buffer records are 8-byte aligned; a future field addition
        // must not make the parser reject older records outright.
        let mut buf = encode(7, 8, 9, 10, 81, 0, 0, "x");
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(DevEvent::parse(&buf).unwrap().exe_ino, 7);
    }
}
