//! Wire protocol between `hwprivacy-lsm` (root, holds the eBPF maps) and
//! `hwprivacy-daemon` (user session, owns config and notifications).
//!
//! # Shape
//!
//! Newline-delimited JSON over a unix socket. One JSON object per line, in both
//! directions. Chosen over D-Bus deliberately: the root side must stay small,
//! and NDJSON is inspectable with `nc` when something goes wrong.
//!
//! ```text
//! root:  hwprivacy-lsm            user:  hwprivacy-daemon
//!        owns the BPF maps               owns config.toml + notifications
//!        /run/hwprivacy/lsm.sock  <----  connects, sends Hello + SetPolicy
//!                                 ---->  streams Event lines
//! ```
//!
//! # Direction of trust
//!
//! The daemon is an unprivileged client asking a privileged server to apply
//! policy. The server validates everything it is told: a path that does not
//! resolve is reported back, never guessed at. The socket's permissions are the
//! access control — the protocol itself grants nothing.

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change. Both sides exchange it in `Hello` and
/// refuse to continue on mismatch, rather than misinterpreting each other.
pub const PROTO_VERSION: u32 = 1;

/// Where the root helper listens. Directory mode 0755, socket mode 0660,
/// group-owned by the user who runs the daemon.
pub const DEFAULT_SOCKET: &str = "/run/hwprivacy/lsm.sock";

/// Permission bits. Must match the `PERM_*` defines in `devices.bpf.c`.
pub const PERM_CAMERA: u32 = 1 << 0;
/// Reserved. Audio is not enforced at the kernel layer — the kernel only ever
/// sees `/usr/bin/pipewire` holding the microphone and cannot attribute it to
/// an application. That identity lives in the PipeWire layer.
pub const PERM_AUDIO: u32 = 1 << 1;

/// One allowlist entry, as the daemon expresses it: a path, not an inode.
/// Resolution to `(dev, ino)` happens on the root side, because only it can
/// meaningfully report failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEntry {
    /// Absolute path to the REAL executable. Not a wrapper script:
    /// `/usr/lib/firefox-esr/firefox-esr`, never `/usr/bin/firefox`.
    ///
    /// Named `exe_path`, not `exe`: on a Linux tool `exe` reads like a Windows
    /// binary extension, which is exactly how it was first misread.
    pub exe_path: String,
    pub perms: u32,
}

/// An allowlist entry that could not be applied, and why.
///
/// Surfaced rather than dropped: under default-deny a typo'd path silently
/// costs an application its camera, which is the hardest failure to debug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedEntry {
    pub exe_path: String,
    pub reason: String,
}

/// Unprivileged daemon -> root helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "snake_case")]
pub enum Request {
    /// First line on every connection.
    Hello { version: u32 },
    /// Full replacement of the allowlist. Not a delta: a delta protocol makes
    /// "what does the kernel actually hold" unanswerable, and that question has
    /// already cost a debugging cycle here.
    SetPolicy {
        entries: Vec<PolicyEntry>,
        enforce_camera: bool,
        /// The ALSA capture backstop. `#[serde(default)]` so a helper and a
        /// daemon of different vintages still talk: an older daemon that omits
        /// the field means "off", which is the safe direction — the same
        /// compatibility trick as `AccessEvent.released`. No PROTO_VERSION bump.
        #[serde(default)]
        enforce_audio: bool,
    },
    /// Ask what the kernel currently holds, for diagnostics.
    GetPolicy,
    Ping,
}

/// Root helper -> unprivileged daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rep", rename_all = "snake_case")]
pub enum Reply {
    Hello {
        version: u32,
        enforcing_camera: bool,
        #[serde(default)]
        enforcing_audio: bool,
    },
    PolicyApplied {
        applied: usize,
        unresolved: Vec<UnresolvedEntry>,
    },
    Policy {
        entries: Vec<PolicyEntry>,
    },
    /// A device access, already coalesced by the kernel.
    Event(AccessEvent),
    Pong,
    Error {
        message: String,
    },
}

/// A device access as the kernel saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    /// Seconds since the unix epoch. Wall clock, because this is going into a
    /// user-visible log — the kernel's monotonic timestamp is useless there.
    pub ts_unix: i64,
    /// Resolved executable path, or a `<dev=..,ino=..>` placeholder if the
    /// process exited before it could be read.
    pub exe_path: String,
    pub pid: u32,
    /// e.g. `/dev/video0`.
    pub device: String,
    /// `CAMERA`, `MIC`, `playback`, `control`, `other`.
    pub role: String,
    /// Whether the kernel returned `-EPERM`.
    pub denied: bool,
    /// Further opens by the same executable on the same device class that were
    /// collapsed into this one event. A Firefox camera session is 13 opens;
    /// this is how the other 12 stay visible without 13 notifications.
    pub additional_opens: u32,
    /// This event is a RELEASE — the executable let the camera go — rather than
    /// an open.
    ///
    /// `#[serde(default)]` so a helper built before 2026-08-23 still speaks to
    /// a newer daemon: an absent field means an open, which is what every event
    /// was until the `lsm/file_release` hook existed.
    #[serde(default)]
    pub released: bool,
}

impl AccessEvent {
    /// Total device opens this single event stands for.
    pub fn total_opens(&self) -> u32 {
        1 + self.additional_opens
    }

    /// True when this event represents a collapsed burst rather than one open.
    pub fn is_burst(&self) -> bool {
        self.additional_opens > 0
    }
}

/// Encode one message as a single NDJSON line, newline included.
pub fn encode_line<T: Serialize>(msg: &T) -> Result<String, serde_json::Error> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let cases = vec![
            Request::Hello {
                version: PROTO_VERSION,
            },
            Request::SetPolicy {
                entries: vec![PolicyEntry {
                    exe_path: "/usr/lib/firefox-esr/firefox-esr".into(),
                    perms: PERM_CAMERA,
                }],
                enforce_camera: true,
                enforce_audio: true,
            },
            Request::GetPolicy,
            Request::Ping,
        ];
        for c in cases {
            let line = encode_line(&c).unwrap();
            assert!(line.ends_with('\n'), "must be one NDJSON line");
            assert_eq!(line.matches('\n').count(), 1, "no embedded newlines");
            let back: Request = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn replies_round_trip() {
        let cases = vec![
            Reply::Hello {
                version: PROTO_VERSION,
                enforcing_camera: false,
                enforcing_audio: false,
            },
            Reply::PolicyApplied {
                applied: 2,
                unresolved: vec![UnresolvedEntry {
                    exe_path: "/nope".into(),
                    reason: "cannot stat".into(),
                }],
            },
            Reply::Event(AccessEvent {
                ts_unix: 1_770_000_000,
                exe_path: "/usr/lib/firefox-esr/firefox-esr".into(),
                pid: 3271,
                device: "/dev/video0".into(),
                role: "CAMERA".into(),
                denied: true,
                additional_opens: 12,
                released: false,
            }),
            Reply::Pong,
            Reply::Error {
                message: "boom".into(),
            },
        ];
        for c in cases {
            let line = encode_line(&c).unwrap();
            let back: Reply = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(back, c);
        }
    }

    #[test]
    fn a_path_with_quotes_or_newlines_cannot_break_the_framing() {
        // Executable paths are attacker-influenced in the sense that anyone can
        // create a file with an awkward name. NDJSON framing must survive it.
        let nasty = "/tmp/we\"ird\\path\nwith-newline";
        let msg = Reply::Event(AccessEvent {
            ts_unix: 0,
            exe_path: nasty.into(),
            pid: 1,
            device: "/dev/video0".into(),
            role: "CAMERA".into(),
            denied: true,
            additional_opens: 0,
            released: false,
        });
        let line = encode_line(&msg).unwrap();
        assert_eq!(
            line.matches('\n').count(),
            1,
            "an embedded newline must be escaped, not framed"
        );
        let back: Reply = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn burst_accounting_is_explicit() {
        let single = AccessEvent {
            ts_unix: 0,
            exe_path: "/x".into(),
            pid: 1,
            device: "/dev/video0".into(),
            role: "CAMERA".into(),
            denied: true,
            additional_opens: 0,
            released: false,
        };
        assert_eq!(single.total_opens(), 1);
        assert!(!single.is_burst());

        let burst = AccessEvent {
            additional_opens: 12,
            released: false,
            ..single
        };
        assert_eq!(burst.total_opens(), 13, "the measured Firefox session");
        assert!(burst.is_burst());
    }

    #[test]
    fn version_mismatch_is_detectable_before_anything_else_is_parsed() {
        let old = r#"{"req":"hello","version":0}"#;
        match serde_json::from_str::<Request>(old).unwrap() {
            Request::Hello { version } => assert_ne!(version, PROTO_VERSION),
            other => panic!("expected hello, got {other:?}"),
        }
    }

    #[test]
    fn unknown_message_types_are_rejected_not_silently_ignored() {
        assert!(serde_json::from_str::<Request>(r#"{"req":"drop_tables"}"#).is_err());
        assert!(serde_json::from_str::<Reply>(r#"{"rep":"surprise"}"#).is_err());
    }
}
