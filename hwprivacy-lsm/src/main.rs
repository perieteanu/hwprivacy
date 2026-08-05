//! hwprivacy-lsm — kernel-level hardware access control.
//!
//! Loads an eBPF LSM program on `security_file_open` and reports — and, with
//! `--enforce`, denies — opens of video4linux and ALSA device nodes.
//!
//! # Scope
//!
//! * **Camera** (major 81) is enforced under `--enforce`: any executable not on
//!   the allowlist gets `-EPERM`. Default posture is deny.
//! * **Audio** (major 116) is observe-only and is never denied here. The kernel
//!   sees only `/usr/bin/pipewire` holding the microphone and cannot tell which
//!   application is behind it — that identity lives in the PipeWire layer.
//!   Audio enforcement is a separate feature.
//!
//! # Safety
//!
//! Enforcement is off unless explicitly requested, and the program is **never
//! pinned**: when this process exits the kernel detaches it and device access
//! returns to normal. Killing it is the escape hatch, and that is deliberate.
//!
//! # Identity
//!
//! Policy keys on `(exe_dev, exe_ino)` — the inode of the calling task's
//! executable. A process cannot lie about which binary it exec'd. `comm` is
//! useless for this: Firefox's camera thread reports `VideoCapture`.

mod device_index;
mod event;
mod policy;

use anyhow::{bail, Context, Result};
use chrono::Local;
use clap::Parser;
use device_index::{DeviceIndex, DeviceRole};
use event::{monotonic_ns, CoalesceEntry, DevEvent};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use policy::Policy;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod devices_skel {
    include!(concat!(env!("OUT_DIR"), "/devices.skel.rs"));
}
use devices_skel::DevicesSkelBuilder;

#[derive(Parser)]
#[command(
    name = "hwprivacy-lsm",
    version,
    about = "HWPrivacy — kernel-level camera/microphone access observer (eBPF LSM)",
    long_about = "Reports every open() of a video4linux or ALSA device node, seen \
                  from inside the kernel — including the direct V4L2 and ALSA \
                  access that the PipeWire layer is structurally blind to.\n\n\
                  Phase 1 denies nothing. Requires root to load the eBPF program."
)]
struct Cli {
    /// Show playback and mixer-control opens too. Off by default: these fire
    /// constantly and are not privacy-relevant.
    #[arg(long)]
    all: bool,

    /// Emit one JSON object per line instead of the human table.
    #[arg(long)]
    json: bool,

    /// Collapse repeats of the same (exe, device) pair into a counter, and
    /// print a summary on exit. Best for a long observation run.
    #[arg(long)]
    summarize: bool,

    /// Exit after this many reported events (0 = no event limit).
    #[arg(long, default_value = "0")]
    max_events: u64,

    /// Exit automatically after this many seconds (0 = no time limit).
    #[arg(long, default_value = "0")]
    duration: u64,

    /// ENFORCE camera policy: deny /dev/video* to any executable not on the
    /// allowlist. Without this flag nothing is ever denied.
    #[arg(long)]
    enforce: bool,

    /// Allow an executable to use the camera. Repeatable. Must be the REAL
    /// binary, not a wrapper script — `/usr/lib/firefox-esr/firefox-esr`, not
    /// `/usr/bin/firefox`.
    #[arg(long, value_name = "EXE")]
    allow: Vec<PathBuf>,

    /// Read the camera allowlist from a file (one executable path per line).
    #[arg(long, value_name = "FILE")]
    policy_file: Option<PathBuf>,

    /// Coalescing window in milliseconds. Repeat opens by the same executable
    /// on the same device class inside this window are counted, not reported
    /// again — one camera session is 13 opens.
    #[arg(long, default_value = "2000")]
    coalesce_ms: u64,

    /// Read the policy map back out of the kernel and print it, then continue.
    ///
    /// Exists because a policy-key mismatch is invisible: userspace writes a
    /// valid key, the kernel reads a valid key, and they are simply never
    /// equal. Under default-deny that presents as "enforcement works, the
    /// allowlist does not", which is indistinguishable from a policy mistake
    /// unless you can see both numbers.
    #[arg(long)]
    dump_policy: bool,
}

impl Cli {
    /// One plain sentence saying exactly how this run terminates.
    ///
    /// House rule (global): a run announces three things before doing any work
    /// — how it ends, where its results appear, and what to hand back. Leaving
    /// the operator guessing about any of the three has already cost a run
    /// each. See also [`Cli::results_location`] and [`Cli::what_to_do`].
    fn exit_condition(&self) -> String {
        match (self.duration, self.max_events) {
            (0, 0) => "press Ctrl-C. Nothing else stops it — no timer, no event limit.".into(),
            (d, 0) => format!("automatically after {d}s, or Ctrl-C sooner."),
            (0, m) => format!("automatically after {m} reported event(s), or Ctrl-C sooner."),
            (d, m) => format!("after {d}s or {m} event(s), whichever comes first — or Ctrl-C sooner."),
        }
    }

    /// Where the results show up — and, just as importantly, where they do NOT.
    ///
    /// This tool is standalone: it has no D-Bus connection, no socket, and no
    /// notification code. The hwprivacy daemon, the tray icon and the GUI have
    /// never heard of it. Saying so prevents watching the wrong surface.
    fn results_location(&self) -> String {
        let base = if self.json {
            "this terminal, one JSON object per line on stdout"
        } else {
            "this terminal, as the table below"
        };
        format!(
            "{base}. NOT in the tray icon, NOT as a desktop notification, \
             NOT in hwprivacy-ctl/tui/gui — those are the separate PipeWire layer."
        )
    }

    /// What the operator should hand back afterwards.
    fn what_to_do(&self) -> String {
        if self.summarize {
            "copy the summary table printed at exit into the Claude chat.".into()
        } else {
            "copy the lines below (or the whole terminal) into the Claude chat.".into()
        }
    }
}

/// Why the observation loop stopped, so the closing line can say so.
#[derive(Debug, Clone, Copy, PartialEq)]
enum StopReason {
    Interrupted,
    DurationElapsed,
    EventLimit,
}

impl StopReason {
    fn describe(self) -> &'static str {
        match self {
            StopReason::Interrupted => "interrupted by Ctrl-C",
            StopReason::DurationElapsed => "time limit reached",
            StopReason::EventLimit => "event limit reached",
        }
    }
}

/// One row of the --summarize table.
#[derive(Default)]
struct Tally {
    count: u64,
    /// Opens swallowed by kernel-side coalescing. `count` alone understates
    /// real activity by ~13x for a camera session.
    suppressed: u64,
    denied: u64,
    exe: String,
    device: String,
    role: &'static str,
    first_seen: String,
    last_seen: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // SAFETY: geteuid() has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "hwprivacy-lsm must run as root to load an eBPF LSM program.\n\
             Try:  sudo ./target/debug/hwprivacy-lsm"
        );
    }

    preflight()?;

    let skel_builder = DevicesSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();

    let open_skel = skel_builder
        .open(&mut open_object)
        .context("failed to open the eBPF skeleton")?;

    let mut skel = open_skel.load().context(
        "failed to load the eBPF program — the verifier rejected it, \
         or BPF LSM is unavailable on this kernel",
    )?;

    // ---------------------- policy, loaded BEFORE attaching ----------------
    // Order matters: the program must never be live with enforcement on and an
    // empty allowlist, or every camera open on the machine is denied for the
    // window between attach and map population.
    let mut pol = Policy::default();
    if let Some(f) = &cli.policy_file {
        pol = Policy::from_file(f)?;
    }
    for p in &cli.allow {
        pol.allow_path(p);
    }

    for (path, why) in &pol.unresolved {
        eprintln!("hwprivacy-lsm: WARNING unusable allowlist entry {}: {}", path.display(), why);
    }
    if cli.enforce && !pol.unresolved.is_empty() {
        eprintln!(
            "hwprivacy-lsm: {} allowlist entr(ies) could not be resolved. Under \
             --enforce those applications WILL be denied the camera.",
            pol.unresolved.len()
        );
    }

    let map = pol.to_map();
    for (key, perms) in &map {
        skel.maps
            .policy
            .update(&key.to_bytes(), &perms.to_ne_bytes(), MapFlags::ANY)
            .context("failed to write a policy map entry")?;
    }

    // struct config { u32 enforce_camera; u32 _pad; u64 coalesce_ns; }
    let mut cfg = [0u8; 16];
    cfg[0..4].copy_from_slice(&(cli.enforce as u32).to_ne_bytes());
    cfg[8..16].copy_from_slice(&(cli.coalesce_ms * 1_000_000).to_ne_bytes());
    skel.maps
        .config_map
        .update(&0u32.to_ne_bytes(), &cfg, MapFlags::ANY)
        .context("failed to write the config map")?;

    if cli.dump_policy {
        dump_policy_map(&skel.maps.policy, &pol)?;
    }

    skel.attach()
        .context("failed to attach to the security_file_open LSM hook")?;

    if !cli.json {
        eprintln!("hwprivacy-lsm: attached to lsm/file_open");
        eprintln!("hwprivacy-lsm: watching major 81 (video4linux) + 116 (alsa)");
        if !cli.all {
            eprintln!("hwprivacy-lsm: showing CAMERA and MIC only — pass --all for playback/control");
        }
        if cli.enforce {
            eprintln!(
                "hwprivacy-lsm: ENFORCING camera — /dev/video* denied (-EPERM) to \
                 anything not on the allowlist"
            );
            eprintln!("hwprivacy-lsm: audio is NOT enforced; it stays observe-only");
            if map.is_empty() {
                eprintln!(
                    "hwprivacy-lsm: !! allowlist is EMPTY — every application will be \
                     denied the camera"
                );
            } else {
                eprintln!("hwprivacy-lsm: camera allowed for {} executable(s):", map.len());
                for e in &pol.entries {
                    eprintln!("hwprivacy-lsm:   {}", e.path.display());
                }
            }
            eprintln!(
                "hwprivacy-lsm: the program is NOT pinned — stopping this process \
                 restores normal access immediately"
            );
        } else {
            eprintln!("hwprivacy-lsm: OBSERVE ONLY — nothing will be denied (pass --enforce to gate the camera)");
        }
        eprintln!("hwprivacy-lsm: coalescing repeat opens within {} ms", cli.coalesce_ms);
        eprintln!();
        eprintln!("  ─────────────────────────────────────────────────────────────");
        eprintln!("  HOW THIS ENDS:   {}", cli.exit_condition());
        eprintln!("  RESULTS APPEAR:  {}", cli.results_location());
        eprintln!("  WHAT TO DO:      {}", cli.what_to_do());
        eprintln!("  ─────────────────────────────────────────────────────────────");
        eprintln!();
        if !cli.summarize {
            eprintln!(
                "{:<8}  {:<8}  {:<7}  {:<18}  {:<15}  {:<7}  {}",
                "TIME", "VERDICT", "ROLE", "DEVICE", "COMM", "PID", "EXE"
            );
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        install_signal_handler(move || r.store(false, Ordering::SeqCst))?;
    }

    let reported = Arc::new(AtomicU64::new(0));
    let index = Arc::new(Mutex::new(DeviceIndex::new()));
    // (exe_dev, exe_ino) -> path, so a burst summary can name the binary even
    // after the process has exited.
    let seen_exe: Arc<Mutex<HashMap<(u32, u64), String>>> = Arc::new(Mutex::new(HashMap::new()));
    let tallies: Arc<Mutex<HashMap<(u64, u32, u32), Tally>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut builder = RingBufferBuilder::new();
    {
        let cli_all = cli.all;
        let cli_json = cli.json;
        let cli_sum = cli.summarize;
        let reported = reported.clone();
        let index = index.clone();
        let tallies = tallies.clone();
        let seen_exe = seen_exe.clone();

        builder
            .add(&skel.maps.events, move |data: &[u8]| {
                let Some(e) = DevEvent::parse(data) else {
                    eprintln!(
                        "hwprivacy-lsm: malformed event ({} bytes, expected {}) — \
                         the C and Rust layouts have drifted",
                        data.len(),
                        event::EVENT_SIZE
                    );
                    return 0;
                };

                let node = index
                    .lock()
                    .unwrap()
                    .lookup(e.dev_major, e.dev_minor);

                let (device, role) = match node {
                    Some(n) => (n.path.to_string_lossy().into_owned(), n.role),
                    // Unresolvable: report it rather than hide it. A device
                    // node we cannot name is more interesting, not less.
                    None => (
                        format!("<{}:{}>", e.dev_major, e.dev_minor),
                        DeviceRole::Other,
                    ),
                };

                if !cli_all && !role.is_capture() {
                    return 0;
                }

                reported.fetch_add(1, Ordering::SeqCst);

                let exe = e
                    .resolve_exe()
                    .unwrap_or_else(|| format!("<exited:{}>", e.comm));
                seen_exe
                    .lock()
                    .unwrap()
                    .insert((e.exe_dev, e.exe_ino), exe.clone());

                if cli_sum {
                    let now = Local::now().format("%H:%M:%S").to_string();
                    let mut t = tallies.lock().unwrap();
                    let entry = t
                        .entry((e.exe_ino, e.exe_dev, e.dev_minor))
                        .or_insert_with(|| Tally {
                            exe: exe.clone(),
                            device: device.clone(),
                            role: role.label(),
                            first_seen: now.clone(),
                            ..Default::default()
                        });
                    entry.count += 1;
                    entry.suppressed += e.suppressed as u64;
                    if e.denied {
                        entry.denied += 1;
                    }
                    entry.last_seen = now;
                } else {
                    print_event(&e, &device, role, &exe, cli_json);
                }
                0
            })
            .context("failed to register the ring buffer callback")?;
    }
    let ring = builder.build().context("failed to build the ring buffer")?;

    let started = std::time::Instant::now();
    let mut stop_reason = StopReason::Interrupted;
    let mut last_flush = std::time::Instant::now();
    let coalesce_ns = cli.coalesce_ms * 1_000_000;
    let accounted = Arc::new(AtomicU64::new(0));

    while running.load(Ordering::SeqCst) {
        // Errors here are almost always EINTR from our own signal handler.
        if let Err(e) = ring.poll(Duration::from_millis(200)) {
            if !running.load(Ordering::SeqCst) {
                break;
            }
            eprintln!("hwprivacy-lsm: ring buffer poll failed: {e}");
        }
        if cli.max_events > 0 && reported.load(Ordering::SeqCst) >= cli.max_events {
            stop_reason = StopReason::EventLimit;
            break;
        }
        if cli.duration > 0 && started.elapsed().as_secs() >= cli.duration {
            stop_reason = StopReason::DurationElapsed;
            break;
        }

        // Report bursts that have gone quiet. Cheap: the map holds one entry
        // per (executable, device class) that has been active.
        if last_flush.elapsed() >= Duration::from_millis(500) {
            last_flush = std::time::Instant::now();
            let seen = seen_exe.lock().unwrap().clone();
            match flush_stale_bursts(&skel.maps.coalesce, coalesce_ns, &seen, cli.json) {
                Ok(n) => accounted.fetch_add(n, Ordering::SeqCst),
                Err(e) => {
                    eprintln!("hwprivacy-lsm: burst flush failed: {e:#}");
                    0
                }
            };
        }
    }

    // Final flush: a burst that ended moments before exit must still be
    // accounted for, otherwise the closing count under-reports.
    {
        let seen = seen_exe.lock().unwrap().clone();
        if let Ok(n) = flush_stale_bursts(&skel.maps.coalesce, 0, &seen, cli.json) {
            accounted.fetch_add(n, Ordering::SeqCst);
        }
    }

    if cli.summarize {
        print_summary(&tallies.lock().unwrap());
    }

    if !cli.json {
        let ev = reported.load(Ordering::SeqCst);
        let extra = accounted.load(Ordering::SeqCst);
        eprintln!(
            "\nhwprivacy-lsm: stopped ({}) after {}s. {} event(s) reported, \
             covering {} device open(s).",
            stop_reason.describe(),
            started.elapsed().as_secs(),
            ev,
            ev + extra
        );
        eprintln!("hwprivacy-lsm: detached — device access is now unmonitored again.");
    }

    Ok(())
}

/// Report bursts that have gone quiet, then clear their counters.
///
/// The kernel attaches a burst's suppressed count to the NEXT emitted event.
/// A burst that happens once never gets a next event, so the count is stranded
/// in the map. Measured 2026-08-05: a Firefox camera session produced 13 opens,
/// exactly one was reported, and the other twelve were invisible — a security
/// log claiming "1 denied" when 13 were denied.
///
/// Returns how many opens were newly accounted for.
fn flush_stale_bursts(
    map: &libbpf_rs::Map,
    window_ns: u64,
    seen_exe: &HashMap<(u32, u64), String>,
    json: bool,
) -> Result<u64> {
    let now = monotonic_ns();
    let mut pending: Vec<CoalesceEntry> = Vec::new();

    for key in map.keys() {
        let Some(val) = map.lookup(&key, MapFlags::ANY)? else {
            continue;
        };
        if let Some(e) = CoalesceEntry::parse(&key, &val) {
            if e.is_stale(now, window_ns) {
                pending.push(e);
            }
        }
    }

    let mut total = 0u64;
    for e in &pending {
        total += e.suppressed as u64;
        let who = seen_exe
            .get(&(e.exe_dev, e.exe_ino))
            .cloned()
            .unwrap_or_else(|| format!("<dev={} ino={}>", e.exe_dev, e.exe_ino));
        let kind = if e.dev_major == device_index::V4L2_MAJOR {
            "CAMERA"
        } else {
            "AUDIO"
        };

        if json {
            println!(
                r#"{{"ts":"{}","kind":"burst_summary","role":"{}","exe":"{}","exe_dev":{},"exe_ino":{},"additional_opens":{}}}"#,
                Local::now().to_rfc3339(),
                kind,
                escape(&who),
                e.exe_dev,
                e.exe_ino,
                e.suppressed,
            );
        } else {
            println!(
                "{:<8}  {:<8}  {:<7}  burst closed: {} further open(s) by {}",
                Local::now().format("%H:%M:%S"),
                "(burst)",
                kind,
                e.suppressed,
                who,
            );
        }

        // Clear the counter but KEEP last_ns — restarting the window here would
        // make a long burst re-notify on every flush.
        let mut k = [0u8; 16];
        k[0..8].copy_from_slice(&e.exe_ino.to_ne_bytes());
        k[8..12].copy_from_slice(&e.exe_dev.to_ne_bytes());
        k[12..16].copy_from_slice(&e.dev_major.to_ne_bytes());
        map.update(&k, &e.cleared_value(), MapFlags::EXIST)
            .context("failed to clear a coalescing counter")?;
    }

    Ok(total)
}

/// Read the policy map back out of the kernel and print what it actually
/// holds, next to what userspace intended.
///
/// The two can disagree without either side erroring — that is precisely how
/// the Phase 2 acceptance test failed, twice. Showing both numbers turns a
/// hypothesis into a thirty-second diagnosis.
fn dump_policy_map(map: &libbpf_rs::Map, pol: &Policy) -> Result<()> {
    eprintln!("hwprivacy-lsm: --- policy as USERSPACE resolved it ---");
    if pol.entries.is_empty() {
        eprintln!("hwprivacy-lsm:   (empty)");
    }
    for e in &pol.entries {
        eprintln!(
            "hwprivacy-lsm:   dev={:<12} ino={:<12} perms=0x{:02x}  {}",
            e.key.exe_dev,
            e.key.exe_ino,
            e.perms,
            e.path.display()
        );
    }

    eprintln!("hwprivacy-lsm: --- policy as the KERNEL now holds it ---");
    let mut n = 0usize;
    for key in map.keys() {
        if key.len() < 12 {
            eprintln!("hwprivacy-lsm:   <short key: {} bytes>", key.len());
            continue;
        }
        let ino = u64::from_ne_bytes(key[0..8].try_into().unwrap());
        let dev = u32::from_ne_bytes(key[8..12].try_into().unwrap());
        let perms = match map.lookup(&key, MapFlags::ANY)? {
            Some(v) if v.len() >= 4 => u32::from_ne_bytes(v[0..4].try_into().unwrap()),
            _ => 0,
        };
        eprintln!("hwprivacy-lsm:   dev={dev:<12} ino={ino:<12} perms=0x{perms:02x}");
        n += 1;
    }
    if n == 0 {
        eprintln!("hwprivacy-lsm:   (empty — under --enforce EVERYTHING is denied)");
    }

    if n != pol.entries.len() {
        eprintln!(
            "hwprivacy-lsm: NOTE {} intended vs {} in the kernel (duplicates merge, \
             so a smaller number here can be correct)",
            pol.entries.len(),
            n
        );
    }
    eprintln!("hwprivacy-lsm: ---");
    Ok(())
}

/// Fail early and legibly rather than deep inside libbpf.
fn preflight() -> Result<()> {
    let lsm = std::fs::read_to_string("/sys/kernel/security/lsm")
        .context("cannot read /sys/kernel/security/lsm — is securityfs mounted?")?;
    if !lsm.split(',').any(|s| s.trim() == "bpf") {
        bail!(
            "'bpf' is not in the active LSM list ({}).\n\
             BPF LSM programs cannot be attached without an lsm= boot parameter \
             change and a reboot.",
            lsm.trim()
        );
    }

    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        bail!("/sys/kernel/btf/vmlinux is missing — CO-RE needs kernel BTF");
    }

    Ok(())
}

fn print_event(e: &DevEvent, device: &str, role: DeviceRole, exe: &str, json: bool) {
    if json {
        // Hand-built so this crate needs no serde dependency.
        // cmdline is resolved only here: it costs an extra /proc read, and it
        // is what tells apart several processes sharing one binary (browser
        // content processes, repeated ffmpeg invocations).
        let cmdline = e.resolve_cmdline().unwrap_or_default();
        println!(
            r#"{{"ts":"{}","role":"{}","device":"{}","comm":"{}","pid":{},"tgid":{},"exe":"{}","cmdline":"{}","exe_dev":{},"exe_ino":{},"denied":{}}}"#,
            Local::now().to_rfc3339(),
            role.label(),
            escape(device),
            escape(&e.comm),
            e.pid,
            e.tgid,
            escape(exe),
            escape(&cmdline),
            e.exe_dev,
            e.exe_ino,
            e.denied,
        );
    } else {
        // The suppressed count is the honest bit: it says "this is one line
        // standing in for N opens", so a quiet display is never mistaken for
        // a quiet system.
        let burst = if e.suppressed > 0 {
            format!("  (+{} more suppressed)", e.suppressed)
        } else {
            String::new()
        };
        println!(
            "{:<8}  {:<8}  {:<7}  {:<18}  {:<15}  {:<7}  {}{}",
            Local::now().format("%H:%M:%S"),
            if e.denied { "DENIED" } else { "allow" },
            role.label(),
            device,
            e.comm,
            e.tgid,
            exe,
            burst,
        );
    }
}

fn print_summary(tallies: &HashMap<(u64, u32, u32), Tally>) {
    if tallies.is_empty() {
        eprintln!("\nNo camera or microphone access observed.");
        return;
    }

    let mut rows: Vec<&Tally> = tallies.values().collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then(a.exe.cmp(&b.exe)));

    eprintln!("\n=== observed consumers ===");
    eprintln!(
        "{:<7}  {:<7}  {:<7}  {:<7}  {:<18}  {:<9}  {}",
        "EVENTS", "OPENS", "DENIED", "ROLE", "DEVICE", "WINDOW", "EXE"
    );
    for t in rows {
        eprintln!(
            "{:<7}  {:<7}  {:<7}  {:<7}  {:<18}  {}-{}  {}",
            t.count,
            t.count + t.suppressed,
            t.denied,
            t.role,
            t.device,
            t.first_seen,
            t.last_seen,
            t.exe
        );
    }
    eprintln!(
        "\nThese exe paths are the policy keys. Anything not listed here has \
         not touched the camera or mic during this run."
    );
}

fn escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', "\\\"")
}

/// Minimal SIGINT/SIGTERM handler. Avoids pulling in the `ctrlc` crate for
/// what is two `signal()` calls.
fn install_signal_handler<F>(f: F) -> Result<()>
where
    F: Fn() + Send + Sync + 'static,
{
    static HANDLER: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();
    HANDLER
        .set(Box::new(f))
        .map_err(|_| anyhow::anyhow!("signal handler already installed"))?;

    extern "C" fn trampoline(_sig: libc::c_int) {
        if let Some(h) = HANDLER.get() {
            h();
        }
    }

    // SAFETY: the handler only flips an AtomicBool. No allocation, no
    // reentrancy hazard.
    unsafe {
        libc::signal(libc::SIGINT, trampoline as libc::sighandler_t);
        libc::signal(libc::SIGTERM, trampoline as libc::sighandler_t);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(duration: u64, max_events: u64) -> Cli {
        Cli {
            all: false,
            json: false,
            summarize: false,
            max_events,
            duration,
            enforce: false,
            allow: Vec::new(),
            policy_file: None,
            coalesce_ms: 2000,
            dump_policy: false,
        }
    }

    /// House rule: a run must state up front whether it stops by itself or
    /// waits for a specific human action. These assertions are the contract.
    #[test]
    fn default_run_says_it_ends_only_on_ctrl_c() {
        let s = cli(0, 0).exit_condition();
        assert!(s.contains("Ctrl-C"), "must name the required action: {s}");
        assert!(
            s.contains("Nothing else stops it"),
            "must be explicit that it will not self-terminate: {s}"
        );
    }

    #[test]
    fn timed_run_states_the_time() {
        let s = cli(120, 0).exit_condition();
        assert!(s.contains("120s"), "must state the duration: {s}");
        assert!(s.contains("Ctrl-C"), "must still offer the manual exit: {s}");
    }

    #[test]
    fn event_limited_run_states_the_count() {
        let s = cli(0, 50).exit_condition();
        assert!(s.contains("50"), "must state the event count: {s}");
        assert!(s.contains("Ctrl-C"), "must still offer the manual exit: {s}");
    }

    #[test]
    fn both_limits_says_whichever_comes_first() {
        let s = cli(120, 50).exit_condition();
        assert!(s.contains("120s") && s.contains("50"), "must state both: {s}");
        assert!(s.contains("whichever"), "must resolve the ambiguity: {s}");
    }

    #[test]
    fn every_mode_names_a_concrete_stopping_condition() {
        for (d, m) in [(0, 0), (30, 0), (0, 5), (30, 5)] {
            let s = cli(d, m).exit_condition();
            assert!(!s.is_empty());
            assert!(
                s.contains("Ctrl-C"),
                "every mode must tell the operator how to stop early: {s}"
            );
        }
    }

    /// The global three-part contract: how it ends, where results appear, what
    /// to hand back. Each of these was a real confusion that cost a run.
    #[test]
    fn results_location_names_the_terminal_and_rules_out_the_other_surfaces() {
        let s = cli(0, 0).results_location();
        assert!(s.contains("terminal"), "must name where to look: {s}");
        for absent in ["tray", "notification", "hwprivacy-ctl"] {
            assert!(
                s.contains(absent),
                "must explicitly rule out {absent}, or the wrong surface gets watched: {s}"
            );
        }
    }

    #[test]
    fn what_to_do_tells_the_operator_to_hand_results_back() {
        for summarize in [false, true] {
            let mut c = cli(0, 0);
            c.summarize = summarize;
            let s = c.what_to_do();
            assert!(s.contains("Claude"), "must say where it goes: {s}");
            assert!(s.contains("copy"), "must name the action: {s}");
        }
    }

    #[test]
    fn the_full_contract_is_three_non_empty_parts() {
        let c = cli(0, 0);
        for (name, part) in [
            ("HOW THIS ENDS", c.exit_condition()),
            ("RESULTS APPEAR", c.results_location()),
            ("WHAT TO DO", c.what_to_do()),
        ] {
            assert!(part.len() > 20, "{name} is too thin to be useful: {part}");
        }
    }

    #[test]
    fn stop_reasons_are_all_describable() {
        for r in [
            StopReason::Interrupted,
            StopReason::DurationElapsed,
            StopReason::EventLimit,
        ] {
            assert!(!r.describe().is_empty());
        }
    }
}
