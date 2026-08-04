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
    /// Emergency: deny everything immediately
    BlockAll,
    /// Restore to saved rules
    UnblockAll,
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
        /// Permission: allow, ask_each, while_in_use, ask, deny
        permission: String,
    },
    /// Remove all rules for an app
    Remove {
        /// App name
        app: String,
    },
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
        }

        Commands::Devices => {
            let devices = proxy.get_devices().await?;
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
        }

        Commands::Rules { action } => match action {
            RulesAction::List => {
                let rules = proxy.get_rules().await?;
                if rules.is_empty() {
                    println!("No rules configured. Default policy: deny/ask.");
                } else {
                    // Group by app
                    let mut current_app = String::new();
                    println!("{:<25} {:<12} {}", "App", "Device", "Permission");
                    println!("{}", "-".repeat(50));
                    for (app, device, perm) in &rules {
                        if *app != current_app {
                            if !current_app.is_empty() {
                                println!();
                            }
                            current_app = app.clone();
                        }
                        println!("{:<25} {:<12} {}", app, device, perm);
                    }
                }
            }
            RulesAction::Set { app, device, permission } => {
                let ok = proxy.set_rule(&app, &device, &permission).await?;
                if ok {
                    println!("Rule set: {} → {} = {}", app, device, permission);
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
                println!("{:<10} {:<20} {:<12} {}", "Time", "App", "Device", "Action");
                println!("{}", "-".repeat(55));
                for (ts, app, dev, action) in &events {
                    println!("{:<10} {:<20} {:<12} {}", ts, app, dev, action);
                }
            }
        }

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
