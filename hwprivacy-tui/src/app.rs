use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hwprivacy_common::dbus_interface::HwPrivacyProxy;
use ratatui::prelude::*;
use std::io;
use std::time::Duration;

use crate::input;
use crate::ui;

/// Which panel is focused
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Panel {
    Devices,
    Streams,
    Rules,
    Events,
}

impl Panel {
    pub fn next(self) -> Self {
        match self {
            Panel::Devices => Panel::Streams,
            Panel::Streams => Panel::Rules,
            Panel::Rules => Panel::Events,
            Panel::Events => Panel::Devices,
        }
    }
}

/// Application state for TUI
pub struct App {
    pub proxy: HwPrivacyProxy<'static>,
    pub active_panel: Panel,
    pub selected_row: usize,
    pub running: bool,

    // Cached data from daemon
    pub devices: Vec<(String, String, String, bool)>,
    pub streams: Vec<(String, u32, String, String, String, String, bool)>,
    pub rules: Vec<(String, String, String)>,
    pub events: Vec<(String, String, String, String)>,
    pub status: (bool, u32, u32, u32, u32),
}

impl App {
    pub async fn new() -> Result<Self> {
        let connection = zbus::Connection::session()
            .await
            .context("Failed to connect to D-Bus")?;

        // We need 'static lifetime for the proxy, so we leak the connection
        let connection = Box::leak(Box::new(connection));

        let proxy = HwPrivacyProxy::new(connection)
            .await
            .context("Failed to connect to hwprivacy-daemon")?;

        let mut app = Self {
            proxy,
            active_panel: Panel::Devices,
            selected_row: 0,
            running: true,
            devices: Vec::new(),
            streams: Vec::new(),
            rules: Vec::new(),
            events: Vec::new(),
            status: (false, 0, 0, 0, 0),
        };

        app.refresh().await;
        Ok(app)
    }

    pub async fn refresh(&mut self) {
        if let Ok(d) = self.proxy.get_devices().await {
            self.devices = d;
        }
        if let Ok(s) = self.proxy.get_active_streams().await {
            self.streams = s;
        }
        if let Ok(r) = self.proxy.get_rules().await {
            self.rules = r;
        }
        if let Ok(e) = self.proxy.get_events(50).await {
            self.events = e;
        }
        if let Ok(s) = self.proxy.get_status().await {
            self.status = s;
        }
    }

    pub fn max_rows(&self) -> usize {
        match self.active_panel {
            Panel::Devices => self.devices.len(),
            Panel::Streams => self.streams.len(),
            Panel::Rules => self.rules.len(),
            Panel::Events => self.events.len(),
        }
    }
}

pub async fn run() -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new().await?;
    let tick_rate = Duration::from_millis(1000); // refresh every 1s

    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    input::handle_key(&mut app, key.code).await;
                }
            }
        } else {
            // Tick: refresh data from daemon
            app.refresh().await;
        }

        if !app.running {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
