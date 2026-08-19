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
#[allow(dead_code)] // reserved: audio is not enforced in Phase 2
pub const PERM_AUDIO: u32 = 1 << 1;

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
    /// Format is deliberately trivial — one executable path per line, `#`
    /// comments, blank lines ignored. Phase 3 replaces this with the daemon's
    /// `config.toml`, so investing in a richer format now would be wasted.
    pub fn parse(text: &str) -> Self {
        let mut p = Policy::default();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let path = PathBuf::from(line);
            if !path.is_absolute() {
                p.unresolved
                    .push((path, "not an absolute path".to_string()));
                continue;
            }
            match PolicyKey::from_path(&path) {
                Ok(key) => p.entries.push(Entry {
                    path,
                    key,
                    perms: PERM_CAMERA,
                }),
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
pub fn render_cache(paths: &[String]) -> String {
    let mut s = String::from(
        "# hwprivacy kernel allowlist cache — WRITTEN BY hwprivacy-lsm, DO NOT EDIT.\n\
         # Rewritten in full every time the daemon pushes a policy.\n\
         # Exists so enforcement survives a reboot: without it the helper starts\n\
         # with an empty allowlist and denies the camera to everything until the\n\
         # user session comes up and pushes config.toml.\n\
         # Enforcement on/off is NOT stored here — that comes from --enforce.\n",
    );
    for p in paths {
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
pub fn write_cache(path: &Path, paths: &[String]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, render_cache(paths))
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
        let paths = vec![
            "/usr/bin/true".to_string(),
            "/usr/bin/false".to_string(),
        ];
        let back = Policy::parse(&render_cache(&paths));
        assert_eq!(back.entries.len(), 2, "{back:?}");
        assert_eq!(back.unresolved.len(), 0);
        let got: Vec<_> = back
            .entries
            .iter()
            .map(|e| e.path.to_string_lossy().to_string())
            .collect();
        assert_eq!(got, paths);
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
        let text = render_cache(&["/opt/Some App/thing".to_string()]);
        let line = text
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("an entry line");
        assert_eq!(line, "/opt/Some App/thing");
    }

    /// A binary can be absent at the moment the daemon pushes (mid-upgrade) and
    /// present at the next boot. `parse` must report it as unresolved rather
    /// than dropping it, so the reason is visible instead of the rule just
    /// vanishing.
    #[test]
    fn an_unresolvable_cached_path_is_reported_not_dropped() {
        let p = Policy::parse(&render_cache(&[
            "/usr/bin/true".to_string(),
            "/definitely/not/here".to_string(),
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
