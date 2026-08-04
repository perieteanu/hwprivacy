mod app;
mod ui;
mod input;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "hwprivacy-tui",
    about = "HWPrivacy — Terminal interface (htop-like)\n\nReal-time view of protected devices, active streams, rules, and events.\nRequires hwprivacy-daemon to be running.",
    version
)]
struct Cli {}

#[tokio::main]
async fn main() -> Result<()> {
    let _cli = Cli::parse();
    app::run().await
}
