//! hwprivacy-lsm — kernel-level hardware access observer (Phase 1).
//!
//! Loads an eBPF LSM program on `security_file_open` and reports every open()
//! of a video4linux or ALSA device node.
//!
//! Phase 1 is OBSERVE ONLY. The eBPF program returns the incoming LSM verdict
//! unchanged and cannot deny anything. Its purpose is twofold: prove that BPF
//! LSM attaches and that CO-RE struct reads work on this kernel, and — just as
//! importantly — find out which executables actually touch the camera and
//! microphone on this machine, since that is the input to writing any policy
//! at all.
//!
//! The program is never pinned. When this process exits the program is
//! detached and the kernel returns to its normal behaviour. That is the
//! escape hatch, and it is deliberate.

mod device_index;
mod event;

use anyhow::{bail, Context, Result};
use chrono::Local;
use clap::Parser;
use device_index::{DeviceIndex, DeviceRole};
use event::DevEvent;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use std::collections::HashMap;
use std::mem::MaybeUninit;
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
}

impl Cli {
    /// One plain sentence saying exactly how this run terminates.
    ///
    /// House rule: a test must announce up front whether it stops on its own
    /// or waits for a specific human action. Leaving the operator guessing
    /// whether something is still working is its own kind of bug.
    fn exit_condition(&self) -> String {
        match (self.duration, self.max_events) {
            (0, 0) => "press Ctrl-C. Nothing else stops it — no timer, no event limit.".into(),
            (d, 0) => format!("automatically after {d}s, or Ctrl-C sooner."),
            (0, m) => format!("automatically after {m} reported event(s), or Ctrl-C sooner."),
            (d, m) => format!("after {d}s or {m} event(s), whichever comes first — or Ctrl-C sooner."),
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

    skel.attach()
        .context("failed to attach to the security_file_open LSM hook")?;

    if !cli.json {
        eprintln!("hwprivacy-lsm: attached to lsm/file_open");
        eprintln!("hwprivacy-lsm: watching major 81 (video4linux) + 116 (alsa)");
        if !cli.all {
            eprintln!("hwprivacy-lsm: showing CAMERA and MIC only — pass --all for playback/control");
        }
        eprintln!("hwprivacy-lsm: OBSERVE ONLY — nothing will be denied");
        eprintln!();
        eprintln!("  HOW THIS ENDS: {}", cli.exit_condition());
        eprintln!();
        if !cli.summarize {
            eprintln!(
                "{:<8}  {:<7}  {:<18}  {:<16}  {:<7}  {}",
                "TIME", "ROLE", "DEVICE", "COMM", "PID", "EXE"
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
    let tallies: Arc<Mutex<HashMap<(u64, u32, u32), Tally>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut builder = RingBufferBuilder::new();
    {
        let cli_all = cli.all;
        let cli_json = cli.json;
        let cli_sum = cli.summarize;
        let reported = reported.clone();
        let index = index.clone();
        let tallies = tallies.clone();

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
    }

    if cli.summarize {
        print_summary(&tallies.lock().unwrap());
    }

    if !cli.json {
        eprintln!(
            "\nhwprivacy-lsm: stopped ({}) after {}s. {} event(s) reported.",
            stop_reason.describe(),
            started.elapsed().as_secs(),
            reported.load(Ordering::SeqCst)
        );
        eprintln!("hwprivacy-lsm: detached — device access is now unmonitored again.");
    }

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
        println!(
            "{:<8}  {:<7}  {:<18}  {:<16}  {:<7}  {}",
            Local::now().format("%H:%M:%S"),
            role.label(),
            device,
            e.comm,
            e.tgid,
            exe,
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
        "{:<7}  {:<7}  {:<18}  {:<9}  {}",
        "OPENS", "ROLE", "DEVICE", "WINDOW", "EXE"
    );
    for t in rows {
        eprintln!(
            "{:<7}  {:<7}  {:<18}  {}-{}  {}",
            t.count, t.role, t.device, t.first_seen, t.last_seen, t.exe
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
