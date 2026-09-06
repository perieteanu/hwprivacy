//! Camera allowlist: human-readable executable paths in, `(dev, ino)` policy
//! keys out.
//!
//! The kernel cannot match on paths — it sees the inode of the calling task's
//! executable. Resolution therefore happens here, where it can be tested and
//! where a missing file is a legible error rather than a silent miss.
//!
//! # Why paths are not the identity
//!
//! `/usr/bin/firefox` on this machine is a **shell script**. The binary that
//! actually opens `/dev/video0` is `/usr/lib/firefox-esr/firefox-esr`, and a
//! second Firefox lives in `$HOME`. Naming the wrapper would produce a rule
//! that can never match. `resolve()` follows symlinks but cannot follow an
//! `exec` inside a script — so the observer's reported exe path is the source
//! of truth for what to put in this file.

use crate::device_index::glibc_to_kernel_dev;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Permission bits. Must match the `PERM_*` defines in devices.bpf.c.
pub const PERM_CAMERA: u32 = 1 << 0;
pub const PERM_AUDIO: u32 = 1 << 1;

/// Render permission bits as the cache's leading word. Order is fixed so the
/// file is stable across writes and a diff means a real change.
pub fn perms_word(perms: u32) -> String {
    let mut parts = Vec::new();
    if perms & PERM_CAMERA != 0 {
        parts.push("camera");
    }
    if perms & PERM_AUDIO != 0 {
        parts.push("audio");
    }
    if parts.is_empty() {
        // An entry granting nothing is still written, so the path survives a
        // reboot and the state is visible rather than vanishing.
        parts.push("none");
    }
    parts.join(",")
}

/// Inverse of [`perms_word`]. `None` means the word was not understood.
pub fn parse_perms(word: &str) -> Option<u32> {
    let mut bits = 0;
    for part in word.split(',') {
        match part.trim() {
            "camera" => bits |= PERM_CAMERA,
            "audio" => bits |= PERM_AUDIO,
            "none" => {}
            "" => return None,
            _ => return None,
        }
    }
    Some(bits)
}

/// The policy map key, byte-identical to `struct policy_key` in the eBPF
/// program: `{ u64 exe_ino; u32 exe_dev; u32 _pad; }`.
///
/// The explicit pad matters. BPF hash keys are compared byte-for-byte, so if
/// the padding differs between what userspace inserts and what the kernel
/// builds, every lookup misses and enforcement silently denies everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyKey {
    pub exe_ino: u64,
    pub exe_dev: u32,
}

impl PolicyKey {
    /// Serialise to the exact 16 bytes the kernel expects, pad zeroed.
    pub fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.exe_ino.to_ne_bytes());
        b[8..12].copy_from_slice(&self.exe_dev.to_ne_bytes());
        // b[12..16] stays zero — this is the `_pad` field.
        b
    }

    /// Resolve an executable path to its policy key.
    ///
    /// `md.dev()` is glibc-encoded; the kernel compares against
    /// `inode->i_sb->s_dev`, which is not the same number. Converting is not
    /// optional — see [`glibc_to_kernel_dev`] for what happens when it is
    /// skipped (it was, and the allowlist silently matched nothing).
    pub fn from_path(path: &Path) -> Result<Self> {
        let md = std::fs::metadata(path)
            .with_context(|| format!("cannot stat {}", path.display()))?;
        Ok(PolicyKey {
            exe_ino: md.ino(),
            exe_dev: glibc_to_kernel_dev(md.dev()),
        })
    }
}

/// A resolved allowlist entry, kept alongside its source path for reporting.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub key: PolicyKey,
    pub perms: u32,
}

/// The camera allowlist.
#[derive(Debug, Default)]
pub struct Policy {
    pub entries: Vec<Entry>,
    /// Paths that could not be resolved, with the reason. Surfaced rather than
    /// swallowed: a typo'd path under default-deny means an app silently loses
    /// its camera, which is exactly the failure mode that is hardest to debug.
    pub unresolved: Vec<(PathBuf, String)>,
}

impl Policy {
    /// Parse an allowlist file.
    ///
    /// Two line shapes, both supported deliberately:
    ///
    /// ```text
    /// /usr/bin/pipewire                 # legacy: camera only
    /// camera,audio /usr/bin/pipewire    # explicit permissions
    /// ```
    ///
    /// A bare path still means camera, so a cache written by an older helper
    /// keeps working across an upgrade. Without the prefix form the audio
    /// grants would silently degrade to camera-only at the next boot — and
    /// with the backstop enforcing, that denies the AUDIO SERVER the
    /// microphone during the window before the user session pushes
    /// `config.toml`. That is the worst failure available in this phase, so
    /// the format has to carry perms.
    ///
    /// An unknown permission word is an error rather than a silent skip: under
    /// default-deny, quietly dropping a grant is indistinguishable from a
    /// typo'd path, and both cost an app its device.
    pub fn parse(text: &str) -> Self {
        let mut p = Policy::default();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let (perms, path_str) = match line.split_once(' ') {
                Some((head, rest)) if !head.starts_with('/') => {
                    match parse_perms(head) {
                        Some(bits) => (bits, rest.trim()),
                        None => {
                            p.unresolved.push((
                                PathBuf::from(rest.trim()),
                                format!("unknown permissions {head:?}"),
                            ));
                            continue;
                        }
                    }
                }
                _ => (PERM_CAMERA, line),
            };

            let path = PathBuf::from(path_str);
            if !path.is_absolute() {
                p.unresolved
                    .push((path, "not an absolute path".to_string()));
                continue;
            }
            match PolicyKey::from_path(&path) {
                Ok(key) => p.entries.push(Entry { path, key, perms }),
                Err(e) => p.unresolved.push((path, format!("{e:#}"))),
            }
        }
        p
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        Ok(Self::parse(&text))
    }

    /// Add a single path, as from a repeated `--allow` flag.
    pub fn allow_path(&mut self, path: &Path) {
        match PolicyKey::from_path(path) {
            Ok(key) => self.entries.push(Entry {
                path: path.to_path_buf(),
                key,
                perms: PERM_CAMERA,
            }),
            Err(e) => self
                .unresolved
                .push((path.to_path_buf(), format!("{e:#}"))),
        }
    }

    /// Collapse to the map contents, merging permission bits for paths that
    /// resolve to the same inode (hard links, or the same file listed twice).
    pub fn to_map(&self) -> BTreeMap<PolicyKey, u32> {
        let mut m = BTreeMap::new();
        for e in &self.entries {
            *m.entry(e.key).or_insert(0) |= e.perms;
        }
        m
    }
}

/// Render an allowlist to the on-disk cache format.
///
/// PATHS, deliberately, not `(dev, ino)`. An inode is the identity the kernel
/// matches on, but it changes the moment the package manager replaces the
/// binary — a cache of inodes would silently stop matching Firefox after the
/// next update, which is the hardest possible failure to notice. Paths are
/// re-resolved at every load.
pub fn render_cache(entries: &[(String, u32)]) -> String {
    let mut s = String::from(
        "# hwprivacy kernel allowlist cache — WRITTEN BY hwprivacy-lsm, DO NOT EDIT.\n\
         # Rewritten in full every time the daemon pushes a policy.\n\
         # Exists so enforcement survives a reboot: without it the helper starts\n\
         # with an empty allowlist and denies the camera to everything until the\n\
         # user session comes up and pushes config.toml.\n\
         # Enforcement on/off is NOT stored here — that comes from --enforce.\n\
         # Format: '<permissions> <path>'. A bare path means camera, so a cache\n\
         # written by an older helper still loads.\n",
    );
    for (p, perms) in entries {
        s.push_str(&perms_word(*perms));
        s.push(' ');
        s.push_str(p);
        s.push('\n');
    }
    s
}

/// Write the cache atomically.
///
/// Temp file plus rename, because the failure mode of a torn write is not a
/// missing allowlist but a TRUNCATED one — and a truncated allowlist under
/// `--enforce` denies the camera to everything that was dropped, while looking
/// exactly like working enforcement. A rename is atomic on the same
/// filesystem, so a reader sees either the old list or the new one.
pub fn write_cache(path: &Path, entries: &[(String, u32)]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, render_cache(entries))
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("cannot rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_serialises_to_sixteen_bytes_with_zero_padding() {
        let k = PolicyKey {
            exe_ino: 0x1122_3344_5566_7788,
            exe_dev: 0x99AA_BBCC,
        };
        let b = k.to_bytes();
        assert_eq!(b.len(), 16);
        assert_eq!(&b[0..8], &0x1122_3344_5566_7788u64.to_ne_bytes());
        assert_eq!(&b[8..12], &0x99AA_BBCCu32.to_ne_bytes());
        assert_eq!(
            &b[12..16],
            &[0, 0, 0, 0],
            "the _pad field must be zero or every kernel lookup misses"
        );
    }

    /// The cache exists so a reboot enforces the same list rather than an empty
    /// one. If what we write cannot be read back, that guarantee is gone and
    /// the next boot silently denies every camera on the machine.
    #[test]
    fn the_cache_round_trips_through_parse() {
        let entries = vec![
            ("/usr/bin/true".to_string(), PERM_CAMERA),
            ("/usr/bin/false".to_string(), PERM_AUDIO),
        ];
        let back = Policy::parse(&render_cache(&entries));
        assert_eq!(back.entries.len(), 2, "{back:?}");
        assert_eq!(back.unresolved.len(), 0);
        let got: Vec<_> = back
            .entries
            .iter()
            .map(|e| (e.path.to_string_lossy().to_string(), e.perms))
            .collect();
        assert_eq!(
            got, entries,
            "permissions must survive the cache — a grant that reloads as the \
             wrong kind is how the audio server loses the microphone at boot"
        );
    }

    /// A cache written by an older helper is bare paths with no permissions
    /// word. It must keep loading, as camera-only — the grant it actually
    /// represented — rather than failing or silently becoming nothing.
    #[test]
    fn a_legacy_bare_path_cache_still_loads_as_camera() {
        let p = Policy::parse("# old header\n/usr/bin/true\n");
        assert_eq!(p.entries.len(), 1, "{p:?}");
        assert_eq!(p.entries[0].perms, PERM_CAMERA);
        assert!(p.unresolved.is_empty());
    }

    /// An unrecognised permissions word must be reported, not skipped. Under
    /// default-deny a silently dropped line and a typo'd path have the same
    /// symptom — an app that mysteriously lost its device.
    #[test]
    fn an_unknown_permission_word_is_reported() {
        let p = Policy::parse("bogus /usr/bin/true\n");
        assert!(p.entries.is_empty());
        assert_eq!(p.unresolved.len(), 1);
        assert!(
            p.unresolved[0].1.contains("unknown permissions"),
            "{:?}",
            p.unresolved[0]
        );
    }

    /// Both bits on one line, which is what a binary allowed the camera AND the
    /// microphone must serialise to.
    #[test]
    fn combined_permissions_round_trip() {
        let text = render_cache(&[("/usr/bin/true".to_string(), PERM_CAMERA | PERM_AUDIO)]);
        assert!(text.contains("camera,audio /usr/bin/true"), "{text}");
        let back = Policy::parse(&text);
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].perms, PERM_CAMERA | PERM_AUDIO);
    }

    /// The header is comments, so a cache with no entries must parse to an
    /// empty allowlist rather than to garbage entries.
    #[test]
    fn an_empty_cache_is_empty_not_malformed() {
        let p = Policy::parse(&render_cache(&[]));
        assert!(p.entries.is_empty());
        assert!(p.unresolved.is_empty());
    }

    /// Paths with a space are ordinary on a desktop — `/opt/Some App/bin`. The
    /// format splits on newlines only, never on whitespace, or such an entry
    /// would be silently truncated into a path that resolves to nothing.
    #[test]
    fn a_path_containing_spaces_survives_the_cache() {
        let text = render_cache(&[("/opt/Some App/thing".to_string(), PERM_CAMERA)]);
        let line = text
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("an entry line");
        assert_eq!(line, "camera /opt/Some App/thing");

        // And it must come BACK whole: the parser splits on the FIRST space
        // only, so everything after the permissions word is the path.
        let back = Policy::parse(&text);
        assert_eq!(
            back.unresolved.len() + back.entries.len(),
            1,
            "the path must not be split on its internal spaces: {back:?}"
        );
        let seen = back
            .entries
            .first()
            .map(|e| e.path.clone())
            .or_else(|| back.unresolved.first().map(|u| u.0.clone()))
            .expect("one entry");
        assert_eq!(seen, PathBuf::from("/opt/Some App/thing"));
    }

    /// A binary can be absent at the moment the daemon pushes (mid-upgrade) and
    /// present at the next boot. `parse` must report it as unresolved rather
    /// than dropping it, so the reason is visible instead of the rule just
    /// vanishing.
    #[test]
    fn an_unresolvable_cached_path_is_reported_not_dropped() {
        let p = Policy::parse(&render_cache(&[
            ("/usr/bin/true".to_string(), PERM_CAMERA),
            ("/definitely/not/here".to_string(), PERM_CAMERA),
        ]));
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.unresolved.len(), 1);
        assert_eq!(p.unresolved[0].0, PathBuf::from("/definitely/not/here"));
    }

    #[test]
    fn parse_ignores_comments_and_blanks() {
        let p = Policy::parse(
            "\n\
             # a comment\n\
             \n\
             /usr/bin/true   # trailing comment\n\
             \n",
        );
        assert_eq!(p.entries.len(), 1, "{:?}", p);
        assert_eq!(p.entries[0].path, PathBuf::from("/usr/bin/true"));
        assert_eq!(p.entries[0].perms, PERM_CAMERA);
    }

    #[test]
    fn relative_paths_are_rejected_not_guessed() {
        let p = Policy::parse("firefox\n");
        assert!(p.entries.is_empty());
        assert_eq!(p.unresolved.len(), 1);
        assert!(p.unresolved[0].1.contains("absolute"));
    }

    #[test]
    fn a_missing_binary_is_reported_not_swallowed() {
        // Under default-deny, a typo'd path silently costs an app its camera.
        // That must be visible.
        let p = Policy::parse("/nonexistent/definitely/not/here\n");
        assert!(p.entries.is_empty());
        assert_eq!(p.unresolved.len(), 1);
    }

    #[test]
    fn resolves_a_real_binary_on_this_machine() {
        let p = Policy::parse("/usr/bin/true\n");
        assert_eq!(p.entries.len(), 1);
        let k = p.entries[0].key;
        assert!(k.exe_ino > 0, "inode should be non-zero");
        assert!(k.exe_dev > 0, "device should be non-zero");
    }

    /// Regression test for the Phase 2 acceptance failure: the key handed to
    /// the kernel must be in the KERNEL's dev_t encoding, not glibc's. Getting
    /// this wrong does not error — every lookup simply misses, so under
    /// default-deny an allowlisted binary stays denied.
    #[test]
    fn key_uses_the_kernel_dev_encoding_not_the_glibc_one() {
        use std::os::unix::fs::MetadataExt;

        let path = Path::new("/usr/bin/true");
        let md = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let key = PolicyKey::from_path(path).expect("should resolve");

        assert_eq!(
            key.exe_dev,
            glibc_to_kernel_dev(md.dev()),
            "must be the converted value"
        );
        assert_ne!(
            key.exe_dev,
            md.dev() as u32,
            "must NOT be the raw st_dev — that is the bug this test exists for"
        );
    }

    #[test]
    fn duplicate_entries_merge_rather_than_collide() {
        let p = Policy::parse("/usr/bin/true\n/usr/bin/true\n");
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.to_map().len(), 1, "same inode must yield one map entry");
    }

    #[test]
    fn a_symlink_resolves_to_its_target_inode() {
        // metadata() follows symlinks, which is what we want: the kernel sees
        // the inode of the real binary, never the link.
        let real = Policy::parse("/usr/bin/true\n");
        let dir = std::env::temp_dir().join(format!("hwp-policy-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let link = dir.join("true-link");
        let _ = std::fs::remove_file(&link);
        if std::os::unix::fs::symlink("/usr/bin/true", &link).is_ok() {
            let via_link = Policy::parse(&format!("{}\n", link.display()));
            assert_eq!(via_link.entries.len(), 1);
            assert_eq!(
                via_link.entries[0].key, real.entries[0].key,
                "symlink and target must produce the same policy key"
            );
            let _ = std::fs::remove_file(&link);
        }
        let _ = std::fs::remove_dir(&dir);
    }
}
