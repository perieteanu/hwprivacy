use anyhow::Context;
use clap::{Parser, Subcommand};
use hwprivacy_common::dbus_interface::HwPrivacyProxy;

#[derive(Parser)]
#[command(name = "hwprivacy-ctl", about = "HWPrivacy - Hardware Permission Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status
    Status,
    /// List discovered protected devices
    Devices,
    /// Manage per-app rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Show active streams
    Streams {
        /// Filter by app name
        #[arg(long)]
        app: Option<String>,
    },
    /// Show recent events
    Log {
        /// Number of events to show
        #[arg(long, default_value = "20")]
        last: u32,
    },
    /// What has touched a device, how often, and since when (survives restarts)
    History,
    /// Importable rule sets
    #[command(subcommand)]
    Preset(PresetAction),
    /// Emergency: deny everything immediately
    BlockAll,
    /// Restore to saved rules
    UnblockAll,
}

#[derive(Subcommand)]
enum PresetAction {
    /// List available presets
    List,
    /// Show what a preset contains
    Show {
        name: String,
    },
    /// Preview a preset import. Writes nothing unless --apply is given.
    Import {
        name: String,
        /// Actually write the rules. Without this, nothing is changed.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all rules
    List,
    /// Set a rule: <app> <device> <permission>
    Set {
        /// App name (e.g., "firefox")
        app: String,
        /// Device: mic, cam, monitor
        device: String,
        /// Permission: allow, while_in_use, ask, deny
        permission: String,
    },
    /// Remove all rules for an app
    Remove {
        /// App name
        app: String,
    },
    /// Binaries the KERNEL layer has denied a camera — the source for
    /// `allow-camera`.
    ///
    /// The kernel layer matches an executable by inode and never looks at an
    /// app name, so this list, not guesswork, is where a camera grant starts.
    DeniedCameras,
    /// Allow a binary the camera at BOTH layers: sets `camera = allow` and
    /// attaches the executable the kernel layer needs.
    AllowCamera {
        /// Absolute path to the real binary, from `denied-cameras`.
        /// On Debian that is /usr/lib/firefox-esr/firefox-esr, never
        /// /usr/bin/firefox — the latter is a shell script.
        path: String,
        /// Rule to attach it to. Defaults to the binary's own name.
        ///
        /// Use this to land the executable on a rule you already have: the
        /// PipeWire layer knows Firefox as `firefox`, while the binary is
        /// called `firefox-esr`. Without --as you get two rules for one app.
        #[arg(long = "as")]
        as_app: Option<String>,
    },
    /// Attach (or clear, with "") the kernel-layer executable for an app.
    SetExe {
        /// App name of an existing rule
        app: String,
        /// Absolute path, or "" to clear
        path: String,
    },
}

/// How one permission cell prints.
///
/// An empty string means the rule says nothing about that category, so it
/// follows `default_action`. It must NOT print as "deny": until 2026-08-23
/// every rule carried all three categories and a camera grant silently wrote
/// two denies, so "deny" was both what the file said and what the table
/// showed. Now the file can be honest, and so must this.
fn perm_cell(p: &String) -> String {
    if p.is_empty() {
        "—".to_string()
    } else {
        p.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::perm_cell;

    #[test]
    fn an_unset_category_renders_as_a_dash_not_as_deny() {
        assert_eq!(perm_cell(&String::new()), "—");
        assert_ne!(perm_cell(&String::new()), "deny");
    }

    #[test]
    fn a_set_category_renders_verbatim() {
        assert_eq!(perm_cell(&"ask_each".to_string()), "ask_each");
        assert_eq!(perm_cell(&"deny".to_string()), "deny");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let connection = zbus::Connection::session()
        .await
        .context("Failed to connect to session D-Bus. Is the daemon running?")?;

    let proxy = HwPrivacyProxy::new(&connection)
        .await
        .context("Failed to create D-Bus proxy. Is hwprivacy-daemon running?")?;

    match cli.command {
        Commands::Status => {
            let (running, devices, rules, blocked, streams) = proxy.get_status().await?;
            println!("HWPrivacy Daemon");
            println!("  Running:          {}", if running { "yes" } else { "no" });
            println!("  Guarded devices:  {}", devices);
            println!("  Active rules:     {}", rules);
            println!("  Blocked attempts: {}", blocked);
            println!("  Active streams:   {}", streams);

            // A rule that cannot reach the layer it names belongs on the
            // status surface, not only in the journal. Reported here as well
            // as in `rules list` because `status` is what gets checked when
            // something "isn't working".
            if let Ok(rules) = proxy.get_rules().await {
                let gaps = rules.iter().filter(|r| !r.5.is_empty()).count();
                if gaps > 0 {
                    println!(
                        "  Rules not in force: {}  <- see: hwprivacy-ctl rules list",
                        gaps
                    );
                }
            }

            // Live while_in_use sessions. Printed whenever one is open, and
            // silent otherwise — a permanent "Sessions: 0" line teaches the
            // reader to skip the row, and this row exists to be noticed.
            //
            // This is the only surface on which a session is directly visible.
            // Without it "is a session live" could only be inferred from the
            // kernel allowlist count, which also moves when a rule changes or
            // a binary is replaced — an ambiguous signal is why while_in_use
            // went months without anyone being able to falsify it.
            if let Ok(sessions) = proxy.get_sessions().await {
                if !sessions.is_empty() {
                    println!();
                    println!("Live sessions (while_in_use — access ends when the device is released)");
                    for (app, device, age) in &sessions {
                        let age = if *age >= 60 {
                            format!("{}m{:02}s", age / 60, age % 60)
                        } else {
                            format!("{}s", age)
                        };
                        println!("  {:<20} {:<12} open {}", app, device, age);
                    }
                }
            }

            // Kernel layer. Reported separately and always — "not connected"
            // is real information, not an absence worth hiding.
            match proxy.get_kernel_status().await {
                Ok((connected, enforcing, allowed, unresolved, err)) => {
                    println!();
                    println!("Kernel layer (eBPF LSM)");
                    if connected {
                        println!("  Connected:        yes");
                        println!(
                            "  Camera enforced:  {}",
                            if enforcing { "yes — non-allowlisted apps get EPERM" } else { "no (observing)" }
                        );
                        println!("  Allowed binaries: {}", allowed);
                        if unresolved > 0 {
                            println!(
                                "  UNUSABLE entries: {}  <- those apps are being denied the camera",
                                unresolved
                            );
                        }
                    } else {
                        // "unknown", NOT "no".
                        //
                        // A disconnected daemon cannot see the kernel state, and
                        // reporting its own default as fact is how this line came
                        // to say "NOT blocked" on 2026-08-19 while the camera was
                        // demonstrably blocked — 3/3 opens denied by a running
                        // hwprivacy-lsm.service that the daemon simply could not
                        // reach. Claiming protection that is absent and denying
                        // protection that is present are the same class of bug,
                        // and both destroy trust in the readout.
                        println!("  Connected:        no");
                        println!(
                            "  Camera enforced:  UNKNOWN — the daemon cannot reach the kernel helper,"
                        );
                        println!(
                            "                    so it cannot see whether the camera is enforced."
                        );
                        println!("                    Check directly with:");
                        println!("                      systemctl is-active hwprivacy-lsm");
                        println!(
                            "                    If that unit is active, the camera IS being enforced"
                        );
                        println!(
                            "                    from /var/lib/hwprivacy/policy regardless of this line."
                        );
                    }
                    if !err.is_empty() {
                        println!("  Last error:       {}", err);
                    }
                }
                Err(_) => {
                    println!();
                    println!("Kernel layer (eBPF LSM)");
                    println!("  Connected:        unknown — daemon predates this feature");
                }
            }
        }

        Commands::Devices => {
            let devices = proxy.get_devices().await?;
            let kernel = proxy.get_kernel_status().await.ok();

            if devices.is_empty() {
                println!("No protected devices discovered.");
            } else {
                println!("{:<12} {:<45} {:<30} {}", "Category", "Node", "Description", "Guard");
                println!("{}", "-".repeat(95));
                for (cat, node, desc, guarded) in &devices {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        cat,
                        node,
                        desc,
                        if *guarded { "ON" } else { "OFF" }
                    );
                }
            }

            // The kernel layer guards a device the PipeWire list cannot show.
            //
            // This row exists because of what happened on 2026-08-19: with
            // wireplumber denied the camera, PipeWire had no Video/Source node
            // at all, so this table listed three devices and NO camera —
            // while the camera was in fact the single most strongly protected
            // device on the machine. The tool was silent about it precisely
            // BECAUSE protection was working.
            //
            // Listing devices by what PipeWire happens to expose describes the
            // monitoring substrate, not the hardware. Say what is guarded.
            if let Some((connected, enforcing, allowed, unresolved, _)) = kernel {
                println!();
                println!("Kernel layer (eBPF LSM) — guards device nodes directly, not via PipeWire");
                println!("{}", "-".repeat(95));
                if connected && enforcing {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        "camera", "/dev/video* (by executable inode)",
                        format!("{allowed} executable(s) allowed"), "ON"
                    );
                    if unresolved > 0 {
                        println!(
                            "{:<12} {:<45} {:<30} {}",
                            "", "", format!("{unresolved} rule(s) UNUSABLE — those apps are denied"), ""
                        );
                    }
                } else if connected {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        "camera", "/dev/video*", "helper connected, observing only", "OFF"
                    );
                } else {
                    println!("  Not connected — this daemon cannot see the kernel layer.");
                    println!("  It may still be enforcing. Check: systemctl is-active hwprivacy-lsm");
                }
                println!();
                println!("A camera absent from the PipeWire list above is not unprotected —");
                println!("it may mean wireplumber was denied, so no PipeWire node exists at all.");
            }
        }

        Commands::Rules { action } => match action {
            RulesAction::List => {
                let rules = proxy.get_rules().await?;
                if rules.is_empty() {
                    println!("No rules configured. Default policy: deny/ask.");
                } else {
                    // One line per rule. This used to print one line per
                    // (rule, category), so a single rule looked like three
                    // separate ones and there was nowhere to show the
                    // executable — the field that decides whether a camera
                    // grant does anything.
                    println!(
                        "{:<20} {:<13} {:<13} {:<13} {}",
                        "App", "Mic", "Camera", "Monitor", "Executable"
                    );
                    println!("{}", "-".repeat(90));
                    let mut any_unset = false;
                    let mut gaps = Vec::new();
                    for (app, mic, cam, mon, exe, note) in &rules {
                        // An empty permission means the rule says nothing
                        // about that category, so it follows default_action.
                        // Rendering it as "deny" would be a lie, and was.
                        any_unset |= mic.is_empty() || cam.is_empty() || mon.is_empty();
                        let cell = perm_cell;
                        let exe_cell = if exe.is_empty() { "(none)" } else { exe.as_str() };
                        println!(
                            "{:<20} {:<13} {:<13} {:<13} {}{}",
                            app,
                            cell(mic),
                            cell(cam),
                            cell(mon),
                            exe_cell,
                            if note.is_empty() { "" } else { "   <- see below" }
                        );
                        if !note.is_empty() {
                            gaps.push((app.clone(), note.clone()));
                        }
                    }
                    if any_unset {
                        println!();
                        println!("—  no rule for that device; follows default_action.");
                    }
                    // The whole point of this change: a rule that cannot reach
                    // the layer it names must say so on the surface that shows
                    // it. On 2026-08-23 this table reported `camera allow`
                    // while the kernel denied every open.
                    for (app, note) in &gaps {
                        println!();
                        println!("!  {}: {}", app, note);
                        println!("   Fix: hwprivacy-ctl rules denied-cameras");
                    }
                }
            }
            RulesAction::DeniedCameras => {
                let rows = proxy.get_history().await?;
                let denied: Vec<_> = rows
                    .iter()
                    .filter(|(_, device, source, denied, ..)| {
                        source == "kernel" && device == "camera" && *denied > 0
                    })
                    .collect();
                if denied.is_empty() {
                    println!("The kernel layer has denied no camera opens.");
                    println!(
                        "Nothing to allow yet — a binary appears here once it has tried."
                    );
                } else {
                    println!("{:<52} {:>7}  {}", "EXECUTABLE", "DENIED", "LAST");
                    println!("{}", "-".repeat(84));
                    for (identity, _, _, denied, _, _, last) in &denied {
                        println!("{:<52} {:>7}  {}", identity, denied, last);
                    }
                    println!();
                    println!("Allow one with:");
                    println!(
                        "    hwprivacy-ctl rules allow-camera {} [--as <existing-rule>]",
                        denied[0].0
                    );
                }
            }
            RulesAction::AllowCamera { path, as_app } => {
                // Derive the same suggestion the GUI shows, so the two agree.
                let app = as_app.unwrap_or_else(|| hwprivacy_common::short_name(&path));

                // One call, not two. Setting the rule and then the binary
                // leaves a moment where the rule reads `allow` with nothing
                // behind it — which correctly raises the gap warning, for an
                // operation that is about to succeed. The daemon does both
                // under one lock and rolls the rule back if the path is bad.
                let (ok, msg) = proxy.allow_camera(&app, &path).await?;
                if !ok {
                    eprintln!("Nothing was written: {}", msg);
                    std::process::exit(2);
                }
                println!("{}", msg);
                println!("The kernel layer picks it up within exe_recheck_secs.");
            }
            RulesAction::SetExe { app, path } => {
                let (ok, msg) = proxy.set_rule_exe(&app, &path).await?;
                if ok {
                    println!("{}", msg);
                } else {
                    eprintln!("{}", msg);
                    std::process::exit(2);
                }
            }
            RulesAction::Set { app, device, permission } => {
                let ok = proxy.set_rule(&app, &device, &permission).await?;
                if ok {
                    println!("Rule set: {} → {} = {}", app, device, permission);
                } else if device.starts_with("cam") && permission == "while_in_use" {
                    // Do NOT tell the user to attach a binary and retry: that
                    // retry is now refused too, and a message that prescribes a
                    // failing command is worse than none. The old text did
                    // exactly that.
                    eprintln!(
                        "Refused: the camera cannot use while_in_use.\n\
                         \n\
                         A session has to be STARTED by answering a prompt, and an\n\
                         application that reaches the camera through V4L2 — Firefox and\n\
                         Chrome among them — never produces one. Its denial arrives from\n\
                         the kernel as an informational popup with no buttons, so there\n\
                         is nothing to answer and the camera would stay denied forever.\n\
                         Measured live on 2026-09-01.\n\
                         \n\
                         Use allow or deny instead:\n\
                         \n\
                         \x20   hwprivacy-ctl rules allow-camera <path> --as {}\n\
                         \x20   hwprivacy-ctl rules set {} cam deny\n\
                         \n\
                         The microphone and the playback monitor DO support\n\
                         while_in_use — they are gated by PipeWire, which prompts."
                        , app, app
                    );
                    std::process::exit(2);
                } else {
                    eprintln!("Failed to set rule. Check device ({}) and permission ({}) values.", device, permission);
                    std::process::exit(2);
                }
            }
            RulesAction::Remove { app } => {
                let ok = proxy.remove_rule(&app).await?;
                if ok {
                    println!("Rules removed for: {}", app);
                } else {
                    println!("No rules found for: {}", app);
                }
            }
        },

        Commands::Streams { app } => {
            let streams = proxy.get_active_streams().await?;
            let filtered: Vec<_> = if let Some(ref filter) = app {
                streams.iter().filter(|s| s.0.contains(filter.as_str())).collect()
            } else {
                streams.iter().collect()
            };

            if filtered.is_empty() {
                println!("No active streams.");
            } else {
                println!("{:<20} {:<7} {:<12} {:<25} {:<15} {:<12} {}", "App", "PID", "Device", "Node", "Media", "Permission", "Active");
                println!("{}", "-".repeat(100));
                for (app, pid, dev, node, media, perm, active) in &filtered {
                    println!(
                        "{:<20} {:<7} {:<12} {:<25} {:<15} {:<12} {}",
                        app,
                        pid,
                        dev,
                        &node[..node.len().min(25)],
                        &media[..media.len().min(15)],
                        perm,
                        if *active { "yes" } else { "no" }
                    );
                }
            }
        }

        Commands::Log { last } => {
            let events = proxy.get_events(last).await?;
            if events.is_empty() {
                println!("No recent events.");
            } else {
                // 19 wide: timestamps carry a full date now (g4), not just
                // "%H:%M:%S". A 10-wide column silently truncated them.
                println!("{:<19} {:<20} {:<12} {}", "Time", "App", "Device", "Action");
                println!("{}", "-".repeat(64));
                for (ts, app, dev, action) in &events {
                    println!("{:<19} {:<20} {:<12} {}", ts, app, dev, action);
                }
            }
        }

        Commands::History => {
            let rows = proxy.get_history().await?;
            if rows.is_empty() {
                println!("Nothing has touched a guarded device yet.");
            } else {
                println!(
                    "{:<44} {:<11} {:<9} {:>7} {:>7}  {:<19} {}",
                    "IDENTITY", "DEVICE", "SOURCE", "DENIED", "ALLOWED", "FIRST", "LAST"
                );
                println!("{}", "-".repeat(112));
                for (identity, device, source, denied, allowed, first, last) in &rows {
                    println!(
                        "{:<44} {:<11} {:<9} {:>7} {:>7}  {:<19} {}",
                        identity, device, source, denied, allowed, first, last
                    );
                }
                println!();
                // Said plainly rather than left for the reader to discover.
                // A table that looks complete but is not is worse than no
                // table: it would quietly under-report anything that happened
                // while the session was down.
                println!(
                    "Counted only while the user daemon was running. Events from before\n\
                     login are in the kernel helper's journal instead:\n\
                     \n    journalctl -u hwprivacy-lsm --since '3 days ago'\n"
                );
                println!(
                    "'kernel' rows are keyed on the executable path and are stable across\n\
                     restarts. 'pipewire' rows are keyed on a name the application declares\n\
                     about itself, which is weaker — treat them as a hint, not an identity.\n"
                );
                // Said outright, because a column headed ALLOWED next to one
                // headed DENIED reads like a scoreboard of things that went
                // wrong. It is the opposite: it is the record that was missing.
                println!(
                    "ALLOWED means the access SUCCEEDED, under a rule you set. It is not an\n\
                     alarm — it is the answer to 'did anything use my camera on Tuesday',\n\
                     which could not be answered at all before. Counts are opens, not\n\
                     sessions. 'pipewire' rows end a while_in_use session when the link
     goes away; 'kernel' rows cannot — that hook is on open() only."
                );
            }
        }

        Commands::Preset(action) => match action {
            PresetAction::List => {
                let rows = proxy.get_presets().await?;
                if rows.is_empty() {
                    println!("No presets found in ~/.config/hwprivacy/presets/ or /usr/share/hwprivacy/presets/.");
                } else {
                    println!("{:<20} {:>7}  {}", "NAME", "RULES", "DESCRIPTION");
                    println!("{}", "-".repeat(96));
                    for (name, desc, count, _path) in &rows {
                        println!("{:<20} {:>7}  {}", name, count, desc);
                    }
                    println!();
                    println!("`hwprivacy-ctl preset show <name>` to see what one contains.");
                }
            }

            PresetAction::Show { name } => {
                // Shown as a PLAN rather than as the file's contents, because
                // what matters is what would happen on THIS machine — which
                // binary resolves, and what is already ruled on.
                let rows = proxy.import_preset(&name, false).await?;
                println!("Preset '{}' on this machine:\n", name);
                for (app, outcome, _) in &rows {
                    println!("  {:<24} {}", app, outcome);
                }
            }

            PresetAction::Import { name, apply } => {
                let rows = proxy.import_preset(&name, apply).await?;
                let added = rows.iter().filter(|(_, _, a)| *a).count();

                for (app, outcome, _) in &rows {
                    println!("  {:<24} {}", app, outcome);
                }
                println!();

                if apply {
                    if added == 0 {
                        println!("Nothing was added — every entry was skipped for the reason above.");
                    } else {
                        println!("Imported {} rule(s) from '{}'.", added, name);
                    }
                } else {
                    // Said outright. A preset is a grant, and the one thing a
                    // user must never be unsure about is whether it took
                    // effect.
                    println!(
                        "PREVIEW ONLY — nothing was written.\n\
                         Re-run with --apply to add the {} rule(s) marked 'added':\n\
                         \n    hwprivacy-ctl preset import {} --apply",
                        added, name
                    );
                }
            }
        },

        Commands::BlockAll => {
            proxy.block_all().await?;
            println!("EMERGENCY: All device access blocked!");
        }

        Commands::UnblockAll => {
            proxy.unblock_all().await?;
            println!("Block-all mode disabled. Saved rules restored.");
        }
    }

    Ok(())
}
