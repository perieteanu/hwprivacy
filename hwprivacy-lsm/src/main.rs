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
mod socket;

use anyhow::{bail, Context, Result};
use chrono::Local;
use clap::Parser;
use device_index::{DeviceIndex, DeviceRole};
use event::{monotonic_ns, CoalesceEntry, DevEvent};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use hwprivacy_proto::{AccessEvent, PolicyEntry, Reply, Request, UnresolvedEntry, PROTO_VERSION};
use policy::{Policy, PolicyKey};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
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
                  Observes by default. --enforce denies /dev/video* to any \
                  executable not on the allowlist; audio is never denied here. \
                  Requires root to load the eBPF program."
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

    /// ENFORCE the audio backstop: deny ALSA CAPTURE nodes
    /// (`/dev/snd/pcmC*D*c`) to any executable without PERM_AUDIO. Playback,
    /// control, seq and timer nodes are never touched.
    ///
    /// This is not per-application microphone policy and cannot be: /dev/snd is
    /// opened by the audio server for everyone. It restricts capture to the
    /// audio stack, closing the direct-ALSA bypass.
    #[arg(long)]
    enforce_audio: bool,

    /// Allow an executable to use the camera. Repeatable. Must be the REAL
    /// binary, not a wrapper script — `/usr/lib/firefox-esr/firefox-esr`, not
    /// `/usr/bin/firefox`.
    #[arg(long, value_name = "EXE")]
    allow: Vec<PathBuf>,

    /// Read the camera allowlist from a file (one executable path per line).
    #[arg(long, value_name = "FILE")]
    policy_file: Option<PathBuf>,

    /// Persist the daemon's allowlist here, and reload it at startup.
    ///
    /// Without this the helper starts with an EMPTY allowlist, so under
    /// `--enforce` it denies the camera to everything until the user session
    /// comes up and pushes config.toml over the socket. That window is the
    /// whole machine's camera, and after a daemon restart it was measured at
    /// ~51 seconds. The cache closes it: enforcement is correct from boot.
    ///
    /// Ignored when `--allow` or `--policy-file` is given, so the acceptance
    /// tests keep driving policy explicitly.
    #[arg(long, value_name = "FILE")]
    policy_cache: Option<PathBuf>,

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

    /// Serve the control socket so hwprivacy-daemon can push policy and
    /// receive events. Without this the helper is standalone and talks to
    /// nobody.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Group that owns the socket, so the unprivileged daemon can connect.
    /// Defaults to $SUDO_USER (the human who ran this under sudo).
    #[arg(long, value_name = "GROUP")]
    socket_group: Option<String>,
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
    /// This answer CHANGES with `--socket`. Without it the tool is standalone
    /// and the terminal is the only surface. With it, events are also pushed to
    /// `hwprivacy-daemon`, which owns the event log and notifications — so the
    /// tray and `hwprivacy-ctl` start showing camera events for the first time.
    /// Saying which of the two is in force prevents watching the wrong thing.
    fn results_location(&self) -> String {
        let base = if self.json {
            "this terminal, one JSON object per line on stdout"
        } else {
            "this terminal, as the table below"
        };
        match &self.socket {
            None => format!(
                "{base}. NOT in the tray icon, NOT as a desktop notification, \
                 NOT in hwprivacy-ctl/tui/gui — those are the separate PipeWire \
                 layer, and nothing here is connected to them."
            ),
            Some(p) => format!(
                "{base} — AND pushed to hwprivacy-daemon over {}. If the daemon \
                 is connected, camera events also reach the tray, notifications \
                 and hwprivacy-ctl/tui/gui.",
                p.display()
            ),
        }
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

    // Explicit policy wins. Only fall back to the cache when the caller gave
    // none, so a test driving `--allow` is never silently merged with whatever
    // the last daemon push happened to leave on disk.
    //
    // A cache that exists but cannot be read is FATAL under --enforce. Carrying
    // on would mean enforcing an empty allowlist — denying every camera on the
    // machine — while looking like a healthy start. That is the exact shape of
    // "enforcement works, the allowlist doesn't", which has already cost this
    // project two debugging cycles.
    if pol.entries.is_empty() && cli.policy_file.is_none() && cli.allow.is_empty() {
        if let Some(cache) = &cli.policy_cache {
            match Policy::from_file(cache) {
                Ok(cached) => {
                    // NOT gated on !cli.json, deliberately.
                    //
                    // The unit runs with --json, and --json suppresses the human
                    // startup banner. On 2026-08-19 that meant the installed
                    // service logged "serving the socket" and nothing about
                    // whether the allowlist had loaded — the single fact an
                    // operator most needs about a service whose whole job
                    // depends on that file. It goes to stderr, so it lands in
                    // the journal without polluting the NDJSON event stream on
                    // stdout.
                    //
                    // Same root cause as the readiness grep that killed a
                    // working helper earlier the same evening: --json gating a
                    // message that is not debug chatter.
                    eprintln!(
                        "hwprivacy-lsm: loaded {} allowlist entr(ies) from {}",
                        cached.entries.len(),
                        cache.display()
                    );
                    for e in &cached.entries {
                        eprintln!("hwprivacy-lsm:   allowed: {}", e.path.display());
                    }
                    for (path, why) in &cached.unresolved {
                        eprintln!(
                            "hwprivacy-lsm:   UNUSABLE: {} ({why}) — this app WILL be denied",
                            path.display()
                        );
                    }
                    pol = cached;
                }
                Err(e) if cache.exists() => {
                    anyhow::bail!(
                        "the policy cache {} exists but could not be read: {e:#}\n\
                         Refusing to start: continuing would enforce an EMPTY \
                         allowlist and deny the camera to everything.",
                        cache.display()
                    );
                }
                Err(_) => {
                    // Also ungated: "the allowlist is empty and everything is
                    // denied" is the most consequential state this program can
                    // be in, and it must never be invisible.
                    eprintln!(
                        "hwprivacy-lsm: no policy cache at {} yet — starting with an \
                         EMPTY allowlist. Under --enforce every application is \
                         denied the camera until the daemon connects and pushes one.",
                        cache.display()
                    );
                }
            }
        }
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

    let cfg = config_bytes(
        cli.enforce,
        cli.enforce_audio,
        cli.coalesce_ms * 1_000_000,
    );
    skel.maps
        .config_map
        .update(&0u32.to_ne_bytes(), &cfg, MapFlags::ANY)
        .context("failed to write the config map")?;

    if cli.dump_policy {
        dump_policy_map(&skel.maps.policy, &pol)?;
    }

    // Seed the capture-minor set BEFORE attaching, exactly as the policy and
    // config maps are. An empty minors map gates nothing, so seeding after
    // attach leaves a window in which the backstop is live and blind — and a
    // blind backstop is indistinguishable from a working one, which is the
    // failure mode this project keeps paying for.
    let index = Arc::new(Mutex::new(DeviceIndex::new()));
    push_capture_minors(&skel.maps.capture_minors, &index)
        .context("failed to seed the ALSA capture minors")?;

    skel.attach()
        .context("failed to attach the LSM programs (file_open, file_release)")?;

    if !cli.json {
        eprintln!("hwprivacy-lsm: attached to lsm/file_open and lsm/file_release");
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

    // (exe_dev, exe_ino) -> path, so a burst summary can name the binary even
    // after the process has exited.
    let seen_exe: Arc<Mutex<HashMap<(u32, u64), String>>> = Arc::new(Mutex::new(HashMap::new()));
    let tallies: Arc<Mutex<HashMap<(u64, u32, u32), Tally>>> = Arc::new(Mutex::new(HashMap::new()));

    // Control socket, if asked for. Started AFTER the program is attached and
    // policy is loaded, so a client can never observe a half-configured kernel.
    let server = match &cli.socket {
        Some(path) => {
            let group = cli
                .socket_group
                .clone()
                .or_else(|| std::env::var("SUDO_USER").ok())
                .context(
                    "cannot determine the socket group: pass --socket-group, \
                     or run under sudo so SUDO_USER is set",
                )?;
            let s = socket::serve(path, &group)?;
            eprintln!(
                "hwprivacy-lsm: serving {} (mode 0660, group {})",
                s.path.display(),
                group
            );
            Some(s)
        }
        None => None,
    };

    let mut builder = RingBufferBuilder::new();
    {
        let cli_all = cli.all;
        let cli_json = cli.json;
        let cli_sum = cli.summarize;
        let reported = reported.clone();
        let index = index.clone();
        let tallies = tallies.clone();
        let seen_exe = seen_exe.clone();
        let to_daemon = server.as_ref().map(|s| s.events.clone());

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

                // Forward to the daemon, which owns config, the event log and
                // notifications. Send failures mean nobody is connected — that
                // is normal, not an error.
                if let Some(tx) = &to_daemon {
                    let _ = tx.send(Reply::Event(AccessEvent {
                        ts_unix: Local::now().timestamp(),
                        exe_path: exe.clone(),
                        pid: e.tgid,
                        device: device.clone(),
                        role: role.label().to_string(),
                        denied: e.denied,
                        additional_opens: e.suppressed,
                        released: e.kind == crate::event::EventKind::Release,
                    }));
                }

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
    let mut enforcing = cli.enforce;
    let mut enforcing_audio = cli.enforce_audio;

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

        // Answer anything the daemon asked for. Only this thread touches the
        // BPF maps, so all kernel mutation is serialised here.
        if let Some(srv) = &server {
            while let Ok((req, rep_tx)) = srv.requests.try_recv() {
                let rep = handle_request(
                    &skel.maps.policy,
                    &skel.maps.config_map,
                    &skel.maps.capture_minors,
                    &index,
                    req,
                    &mut enforcing,
                    &mut enforcing_audio,
                    coalesce_ns,
                    cli.policy_cache.as_deref(),
                );
                let _ = rep_tx.send(rep);
            }
        }

        // Report bursts that have gone quiet. Cheap: the map holds one entry
        // per (executable, device class) that has been active.
        if last_flush.elapsed() >= Duration::from_millis(500) {
            last_flush = std::time::Instant::now();
            let seen = seen_exe.lock().unwrap().clone();
            match flush_stale_bursts(
                &skel.maps.coalesce,
                coalesce_ns,
                &seen,
                cli.json,
                server.as_ref().map(|s| &s.events),
            ) {
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
        if let Ok(n) = flush_stale_bursts(
            &skel.maps.coalesce,
            0,
            &seen,
            cli.json,
            server.as_ref().map(|s| &s.events),
        ) {
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

/// Answer one request from the daemon.
///
/// Runs on the main thread, which is the only thing that touches the BPF maps —
/// all kernel mutation is serialised here by construction rather than by lock.
#[allow(clippy::too_many_arguments)]
fn handle_request(
    policy_map: &libbpf_rs::Map,
    config_map: &libbpf_rs::Map,
    minors_map: &libbpf_rs::Map,
    index: &std::sync::Arc<std::sync::Mutex<DeviceIndex>>,
    req: Request,
    enforcing: &mut bool,
    enforcing_audio: &mut bool,
    coalesce_ns: u64,
    policy_cache: Option<&Path>,
) -> Reply {
    match req {
        Request::Hello { .. } => Reply::Hello {
            version: PROTO_VERSION,
            enforcing_camera: *enforcing,
            enforcing_audio: *enforcing_audio,
        },

        Request::Ping => Reply::Pong,

        Request::SetPolicy {
            entries,
            enforce_camera,
            enforce_audio,
        } => match replace_policy(policy_map, &entries) {
            Ok((applied, unresolved)) => {
                // Re-scan /dev/snd and re-push the capture minors on every
                // policy push. DeviceIndex otherwise only rescans on a lookup
                // MISS, which is too late: the kernel has already decided. A
                // microphone hotplugged since the last scan would sit silently
                // unenforced. A readdir is cheap; this is the same reasoning
                // that rejected inotify for the exe recheck.
                if let Err(e) = push_capture_minors(minors_map, index) {
                    return Reply::Error {
                        message: format!("policy written but capture minors failed: {e:#}"),
                    };
                }
                if let Err(e) =
                    write_config(config_map, enforce_camera, enforce_audio, coalesce_ns)
                {
                    return Reply::Error {
                        message: format!("policy written but enforcement flag failed: {e:#}"),
                    };
                }
                *enforcing = enforce_camera;
                *enforcing_audio = enforce_audio;
                eprintln!(
                    "hwprivacy-lsm: policy set by daemon — {} allowed, {} unusable, \
                     enforcement {}",
                    applied,
                    unresolved.len(),
                    if enforce_camera { "ON" } else { "OFF" }
                );
                eprintln!(
                    "hwprivacy-lsm: audio backstop {} — capture nodes restricted to \
                     allowlisted executables",
                    if enforce_audio { "ON" } else { "OFF" }
                );

                // Persist so the next boot enforces this same list rather than
                // an empty one. Cache every path the daemon SENT, including any
                // that failed to resolve right now — a binary can be missing at
                // this instant (mid-upgrade) and present at the next boot, and
                // dropping it here would silently revoke the user's rule.
                //
                // A cache write failure must not fail the push: the kernel is
                // already correctly programmed, and refusing here would trade a
                // working policy for a persistence problem.
                if let Some(cache) = policy_cache {
                    // Perms travel with the path. Writing bare paths would make
                    // every audio grant reload as camera-only, which under the
                    // backstop denies the AUDIO SERVER the microphone for the
                    // whole boot window.
                    let cached: Vec<(String, u32)> = entries
                        .iter()
                        .map(|e| (e.exe_path.clone(), e.perms))
                        .collect();
                    if let Err(e) = policy::write_cache(cache, &cached) {
                        eprintln!(
                            "hwprivacy-lsm: WARNING policy applied but the cache at {} \
                             could not be written: {e:#}. Enforcement is correct now, \
                             but the next boot will start with an empty allowlist.",
                            cache.display()
                        );
                    }
                }

                Reply::PolicyApplied {
                    applied,
                    unresolved,
                }
            }
            Err(e) => Reply::Error {
                message: format!("{e:#}"),
            },
        },

        Request::GetPolicy => match read_policy(policy_map) {
            Ok(entries) => Reply::Policy { entries },
            Err(e) => Reply::Error {
                message: format!("{e:#}"),
            },
        },
    }
}

/// Replace the kernel allowlist wholesale.
///
/// Full replacement, never a delta: a delta protocol makes "what does the
/// kernel actually hold?" unanswerable, and that question has already cost a
/// debugging cycle on this project.
///
/// Order matters. New entries are written BEFORE stale ones are removed, so
/// there is no instant where a still-authorised application would be denied.
fn replace_policy(
    map: &libbpf_rs::Map,
    entries: &[PolicyEntry],
) -> Result<(usize, Vec<UnresolvedEntry>)> {
    let mut wanted: HashMap<[u8; 16], u32> = HashMap::new();
    let mut unresolved = Vec::new();

    for e in entries {
        let path = std::path::Path::new(&e.exe_path);
        if !path.is_absolute() {
            unresolved.push(UnresolvedEntry {
                exe_path: e.exe_path.clone(),
                reason: "not an absolute path".into(),
            });
            continue;
        }
        match PolicyKey::from_path(path) {
            Ok(k) => {
                *wanted.entry(k.to_bytes()).or_insert(0) |= e.perms;
            }
            Err(err) => unresolved.push(UnresolvedEntry {
                exe_path: e.exe_path.clone(),
                reason: format!("{err:#}"),
            }),
        }
    }

    // 1. add/update
    for (key, perms) in &wanted {
        map.update(key, &perms.to_ne_bytes(), MapFlags::ANY)
            .context("failed to write a policy entry")?;
    }

    // 2. remove anything no longer wanted
    let stale: Vec<Vec<u8>> = map
        .keys()
        .filter(|k| {
            k.len() != 16 || !wanted.contains_key(&<[u8; 16]>::try_from(k.as_slice()).unwrap())
        })
        .collect();
    for k in stale {
        let _ = map.delete(&k);
    }

    Ok((wanted.len(), unresolved))
}

/// Read the allowlist back out of the kernel, for diagnostics.
///
/// Paths cannot be recovered from inodes, so entries come back as
/// `<dev=..,ino=..>`. Answering "what does the kernel hold" honestly beats
/// echoing back what we believe we sent.
fn read_policy(map: &libbpf_rs::Map) -> Result<Vec<PolicyEntry>> {
    let mut out = Vec::new();
    for key in map.keys() {
        if key.len() < 12 {
            continue;
        }
        let ino = u64::from_ne_bytes(key[0..8].try_into().unwrap());
        let dev = u32::from_ne_bytes(key[8..12].try_into().unwrap());
        let perms = match map.lookup(&key, MapFlags::ANY)? {
            Some(v) if v.len() >= 4 => u32::from_ne_bytes(v[0..4].try_into().unwrap()),
            _ => 0,
        };
        out.push(PolicyEntry {
            exe_path: format!("<dev={dev} ino={ino}>"),
            perms,
        });
    }
    Ok(out)
}

/// Replace the kernel's `capture_minors` set from a fresh `/dev/snd` scan.
///
/// Rescans first — the whole point is to notice a microphone that appeared
/// since the last push. Deletes minors that are gone before adding the current
/// ones, so an unplugged device stops being enforced rather than lingering.
///
/// An empty result is not an error: a machine with no capture hardware simply
/// enforces nothing, which is the correct fail-open direction. It IS worth a
/// log line, because "the backstop is on and nothing is gated" is otherwise
/// indistinguishable from working.
fn push_capture_minors(
    map: &libbpf_rs::Map,
    index: &std::sync::Arc<std::sync::Mutex<DeviceIndex>>,
) -> Result<()> {
    let wanted = {
        let mut idx = index.lock().unwrap();
        idx.rescan();
        idx.capture_minors()
    };

    let existing: Vec<[u8; 4]> = map.keys().filter_map(|k| k.try_into().ok()).collect();
    for key in existing {
        let minor = u32::from_ne_bytes(key);
        if !wanted.contains(&minor) {
            let _ = map.delete(&key);
        }
    }

    for minor in &wanted {
        map.update(&minor.to_ne_bytes(), &[1u8], MapFlags::ANY)
            .with_context(|| format!("failed to add capture minor {minor}"))?;
    }

    if wanted.is_empty() {
        eprintln!(
            "hwprivacy-lsm: WARNING — no ALSA capture device found; the audio \
             backstop will gate nothing"
        );
    } else {
        let list: Vec<String> = wanted.iter().map(|m| m.to_string()).collect();
        eprintln!(
            "hwprivacy-lsm: audio capture minors: {} ({})",
            wanted.len(),
            list.join(", ")
        );
    }
    Ok(())
}

/// The 16 bytes of `struct config` in devices.bpf.c:
/// `{ u32 enforce_camera; u32 enforce_audio; u64 coalesce_ns; }`.
///
/// There is deliberately ONE writer. The layout used to be open-coded as
/// `[0u8; 16]` in two separate places with a comment as the only spec, and
/// nothing asserting it — unlike `DevEvent`, which has `EVENT_SIZE` and a
/// runtime drift check. Claiming the old `_pad` slot for `enforce_audio` is
/// safe only because the size is unchanged, so `config_layout_is_stable`
/// pins both the size and the offsets.
fn config_bytes(enforce_camera: bool, enforce_audio: bool, coalesce_ns: u64) -> [u8; 16] {
    let mut cfg = [0u8; 16];
    cfg[0..4].copy_from_slice(&(enforce_camera as u32).to_ne_bytes());
    cfg[4..8].copy_from_slice(&(enforce_audio as u32).to_ne_bytes());
    cfg[8..16].copy_from_slice(&coalesce_ns.to_ne_bytes());
    cfg
}

fn write_config(
    map: &libbpf_rs::Map,
    enforce_camera: bool,
    enforce_audio: bool,
    coalesce_ns: u64,
) -> Result<()> {
    let cfg = config_bytes(enforce_camera, enforce_audio, coalesce_ns);
    map.update(&0u32.to_ne_bytes(), &cfg, MapFlags::ANY)
        .context("failed to write the config map")
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
    to_daemon: Option<&std::sync::mpsc::Sender<Reply>>,
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

        // Send it to the daemon as well, not just this terminal.
        //
        // This is the C5 failure from the Phase 3 test: the helper printed
        // "burst closed: 12 further open(s)" perfectly, to its own stdout, and
        // the daemon's blocked-attempts counter still rose by 1. A summary
        // nobody receives is not accounting.
        if let Some(tx) = to_daemon {
            let _ = tx.send(Reply::Event(AccessEvent {
                ts_unix: Local::now().timestamp(),
                exe_path: who.clone(),
                pid: 0, // the burst spans opens; no single pid owns it
                device: if e.dev_major == device_index::V4L2_MAJOR {
                    "/dev/video*".to_string()
                } else {
                    "/dev/snd/*".to_string()
                },
                role: kind.to_string(),
                denied: e.denied,
                // The whole point: the opens this summary stands for.
                additional_opens: e.suppressed,
                // A burst summary is always about opens. A release is emitted
                // once, at the end, and is never coalesced.
                released: false,
            }));
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
            r#"{{"ts":"{}","event":"{}","role":"{}","device":"{}","comm":"{}","pid":{},"tgid":{},"exe":"{}","cmdline":"{}","exe_dev":{},"exe_ino":{},"denied":{}}}"#,
            Local::now().to_rfc3339(),
            if e.kind == crate::event::EventKind::Release { "release" } else { "open" },
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
        } else if e.kind == crate::event::EventKind::Release {
            "  RELEASED".to_string()
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
            enforce_audio: false,
            allow: Vec::new(),
            policy_file: None,
            coalesce_ms: 2000,
            dump_policy: false,
            policy_cache: None,
            socket: None,
            socket_group: None,
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

    /// With a socket the answer flips: events DO reach the tray and ctl. Saying
    /// "not in the tray" while pushing events to the daemon would be a lie the
    /// operator acts on.
    #[test]
    fn results_location_changes_when_a_socket_is_served() {
        let mut c = cli(0, 0);
        c.socket = Some(PathBuf::from("/run/hwprivacy/lsm.sock"));
        let s = c.results_location();

        assert!(s.contains("/run/hwprivacy/lsm.sock"), "must name the socket: {s}");
        assert!(s.contains("hwprivacy-daemon"), "must say who receives them: {s}");
        assert!(
            !s.contains("NOT in the tray"),
            "must not still claim the tray is excluded once events are forwarded: {s}"
        );
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

#[cfg(test)]
mod config_layout_tests {
    use super::*;

    /// `struct config` is written to the kernel as raw bytes with NO
    /// `#[repr(C)]` mirror on the Rust side — the layout lives only in
    /// `config_bytes()` and in the C declaration, and nothing but this test
    /// connects the two.
    ///
    /// `enforce_audio` occupies what was `_pad` until 2026-09-06. That is safe
    /// ONLY while the struct stays 16 bytes with `coalesce_ns` at offset 8. If
    /// someone widens a field, the C side reads `coalesce_ns` out of the wrong
    /// place and the burst window becomes garbage — silently, because a wrong
    /// coalesce window still "works".
    #[test]
    fn config_layout_is_stable() {
        let cfg = config_bytes(true, false, 0);
        assert_eq!(cfg.len(), 16, "struct config must stay 16 bytes");
        assert_eq!(&cfg[0..4], &1u32.to_ne_bytes(), "enforce_camera at 0");
        assert_eq!(&cfg[4..8], &0u32.to_ne_bytes(), "enforce_audio at 4");

        let cfg = config_bytes(false, true, 0);
        assert_eq!(&cfg[0..4], &0u32.to_ne_bytes());
        assert_eq!(
            &cfg[4..8],
            &1u32.to_ne_bytes(),
            "enforce_audio must be its own field, not aliased onto the camera one"
        );

        // coalesce_ns must still land at offset 8, which is what claiming the
        // padding slot could have broken.
        let cfg = config_bytes(false, false, 0x0123_4567_89ab_cdef);
        assert_eq!(&cfg[8..16], &0x0123_4567_89ab_cdefu64.to_ne_bytes());

        // The two flags are independent in every combination.
        for (cam, aud) in [(false, false), (true, false), (false, true), (true, true)] {
            let c = config_bytes(cam, aud, 0);
            assert_eq!(u32::from_ne_bytes(c[0..4].try_into().unwrap()), cam as u32);
            assert_eq!(u32::from_ne_bytes(c[4..8].try_into().unwrap()), aud as u32);
        }
    }
}
