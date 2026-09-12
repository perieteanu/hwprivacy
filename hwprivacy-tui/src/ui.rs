use crate::app::{App, Panel};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title + tabs
            Constraint::Length(3),  // status bar
            Constraint::Min(10),   // main content
            Constraint::Length(2), // help bar
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);
    draw_status(f, chunks[1], app);
    draw_panel(f, chunks[2], app);
    draw_help(f, chunks[3], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let tabs = Tabs::new(vec!["Devices", "Streams", "Rules", "Events"])
        .block(Block::default().borders(Borders::ALL).title(" HWPrivacy v0.1.0 "))
        .select(match app.active_panel {
            Panel::Devices => 0,
            Panel::Streams => 1,
            Panel::Rules => 2,
            Panel::Events => 3,
        })
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Yellow).bold());

    f.render_widget(tabs, area);
}

/// The kernel-layer line, and whether it should alarm.
///
/// Pure so it can be tested — the rest of this module needs a terminal. The
/// TUI reported nothing about layer 2 until 2026-09-12, neither the camera
/// guard nor the ALSA capture backstop, so the one screen meant to be read at a
/// glance was silent about the stronger enforcement layer.
///
/// `alarm` is true only when the helper is reachable AND a guard is off. A
/// disconnected daemon is NOT an alarm: the helper may well be enforcing from
/// `/var/lib/hwprivacy/policy` and the daemon simply cannot see it — reporting
/// that as danger is the 2026-08-19 bug inverted, and a status line that cries
/// wolf on a healthy machine is one that gets ignored on a broken one.
pub fn kernel_status_line(
    kernel: &(bool, bool, u32, u32, String),
    audio: &(bool, String),
) -> (String, bool) {
    let (connected, camera_on, allowed, unresolved, _) = kernel;
    if !connected {
        return (
            " Kernel: UNREACHABLE — may still be enforcing; check hwprivacy-lsm".to_string(),
            false,
        );
    }
    // An empty reason with enforcing=false means the daemon never answered —
    // it predates GetAudioBackstop. That is "unknown", not "off".
    let audio_word = match audio {
        (true, _) => "audio backstop ON",
        (false, why) if why.is_empty() => "audio backstop UNKNOWN",
        (false, _) => "audio backstop OFF",
    };
    let mut line = format!(
        " Kernel: connected | camera {} | {} | {} binary(ies) allowed",
        if *camera_on { "ON" } else { "OFF" },
        audio_word,
        allowed,
    );
    if *unresolved > 0 {
        line.push_str(&format!(" | {} UNUSABLE", unresolved));
    }
    let alarm = !*camera_on || !audio.0 || *unresolved > 0;
    (line, alarm)
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let (running, devices, rules, blocked, streams) = app.status;
    let status_text = format!(
        " {} | Guarded: {} | Rules: {} | Blocked: {} | Active streams: {}",
        if running { "RUNNING" } else { "STOPPED" },
        devices,
        rules,
        blocked,
        streams,
    );

    // Two lines in the chunk draw() already reserves as Length(3). A second
    // row needs no layout change, no new tab, and no touch to Panel::next() or
    // App::max_rows() — which matters in the one crate with no other tests.
    let (kernel_text, alarm) = kernel_status_line(&app.kernel, &app.audio_backstop);
    let status = Paragraph::new(vec![
        Line::from(status_text).style(Style::default().fg(Color::Green)),
        Line::from(kernel_text).style(Style::default().fg(if alarm {
            Color::Red
        } else {
            Color::Green
        })),
    ])
    .style(Style::default().bg(Color::DarkGray))
    .block(Block::default());

    f.render_widget(status, area);
}

fn draw_panel(f: &mut Frame, area: Rect, app: &App) {
    match app.active_panel {
        Panel::Devices => draw_devices(f, area, app),
        Panel::Streams => draw_streams(f, area, app),
        Panel::Rules => draw_rules(f, area, app),
        Panel::Events => draw_events(f, area, app),
    }
}

fn draw_devices(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["Category", "Description", "Node", "Guard"])
        .style(Style::default().bold().fg(Color::Cyan))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .devices
        .iter()
        .enumerate()
        .map(|(i, (cat, node, desc, guarded))| {
            let style = if i == app.selected_row {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };
            let guard_style = if *guarded {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            Row::new(vec![
                Cell::from(cat.as_str()),
                Cell::from(desc.as_str()),
                Cell::from(truncate(node, 35)),
                Cell::from(if *guarded { "GUARDED" } else { "OFF" }).style(guard_style),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(30),
            Constraint::Min(35),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Protected Devices "));

    f.render_widget(table, area);
}

fn draw_streams(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["App", "PID", "Device", "Stream", "Permission", "Active"])
        .style(Style::default().bold().fg(Color::Cyan))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .streams
        .iter()
        .enumerate()
        .map(|(i, (app_name, pid, dev, node, _media, perm, active))| {
            let style = if i == app.selected_row {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let perm_style = permission_color(perm);
            Row::new(vec![
                Cell::from(app_name.as_str()),
                Cell::from(pid.to_string()),
                Cell::from(dev.as_str()),
                Cell::from(truncate(node, 20)),
                Cell::from(perm.as_str()).style(perm_style),
                Cell::from(if *active { "yes" } else { "no" }),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(14),
            Constraint::Length(7),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Active Streams "));

    f.render_widget(table, area);
}

fn draw_rules(f: &mut Frame, area: Rect, app: &App) {
    // Mark which category column the a/d/e/w keys will act on. Without this
    // the column cursor is invisible and the keys are a guess.
    let mark = |idx: usize, label: &str| {
        if app.selected_device == idx {
            format!("[{label}]")
        } else {
            format!(" {label} ")
        }
    };
    let header = Row::new(vec![
        "App".to_string(),
        mark(0, "Mic"),
        mark(1, "Camera"),
        mark(2, "Monitor"),
        "Executable".to_string(),
    ])
    .style(Style::default().bold().fg(Color::Cyan))
    .bottom_margin(1);

    let rows: Vec<Row> = app
        .rules
        .iter()
        .enumerate()
        .map(|(i, (app_name, mic, cam, mon, exe, note))| {
            let style = if i == app.selected_row {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            // "—" means the rule says nothing about that category, so it
            // follows default_action. Showing "deny" there would be a lie.
            // Owned, so the closure's return does not borrow its argument.
            let cell = |p: &String| {
                if p.is_empty() {
                    Cell::from("—").style(Style::default().fg(Color::DarkGray))
                } else {
                    Cell::from(p.clone()).style(permission_color(p))
                }
            };
            // A rule that cannot reach the layer it names is marked here as
            // well as in the CLI — this pane is where a reader looks to
            // confirm a grant took effect.
            let exe_cell = if !note.is_empty() {
                Cell::from(format!("! {}", if exe.is_empty() { "(none)" } else { exe.as_str() }))
                    .style(Style::default().fg(Color::Yellow))
            } else if exe.is_empty() {
                Cell::from("(none)").style(Style::default().fg(Color::DarkGray))
            } else {
                Cell::from(exe.as_str())
            };
            Row::new(vec![
                Cell::from(app_name.as_str()),
                cell(mic),
                cell(cam),
                cell(mon),
                exe_cell,
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" App Rules  (←/→ pick device, a/d/w set, x remove) "),
    );

    f.render_widget(table, area);
}

fn draw_events(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["Time", "App", "Device", "Action"])
        .style(Style::default().bold().fg(Color::Cyan))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .events
        .iter()
        .rev() // newest first
        .enumerate()
        .map(|(i, (ts, app_name, dev, action))| {
            let style = if i == app.selected_row {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let action_style = match action.as_str() {
                "ALLOWED" | "STREAM_ALLOWED" => Style::default().fg(Color::Green),
                "DENIED" | "STREAM_DENIED" => Style::default().fg(Color::Red),
                "ASKED" => Style::default().fg(Color::Yellow),
                "REVOKED" => Style::default().fg(Color::Magenta),
                _ => Style::default(),
            };
            Row::new(vec![
                Cell::from(ts.as_str()),
                Cell::from(app_name.as_str()),
                Cell::from(dev.as_str()),
                Cell::from(action.as_str()).style(action_style),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            // 19, not 10: event timestamps carry a full date since g4 was
            // fixed. At 10 the date rendered and the CLOCK was cut off.
            Constraint::Length(19),
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Min(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Recent Events "));

    f.render_widget(table, area);
}

fn draw_help(f: &mut Frame, area: Rect, _app: &App) {
    let help = Paragraph::new(
        " Tab:panel  ↑↓:navigate  ←→:device  a:allow  d:deny  w:while_in_use  x:delete  r:refresh  q:quit",
    )
    .style(Style::default().fg(Color::DarkGray));

    f.render_widget(help, area);
}

fn permission_color(perm: &str) -> Style {
    match perm {
        "allow" => Style::default().fg(Color::Green),
        "deny" => Style::default().fg(Color::Red),
        "while_in_use" => Style::default().fg(Color::Blue),
        "ask" => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::kernel_status_line;

    fn kernel(connected: bool, camera: bool, allowed: u32, unresolved: u32)
        -> (bool, bool, u32, u32, String)
    {
        (connected, camera, allowed, unresolved, String::new())
    }

    /// The healthy machine: both guards on, nothing to shout about.
    #[test]
    fn both_guards_on_is_not_an_alarm() {
        let (line, alarm) = kernel_status_line(&kernel(true, true, 6, 0), &(true, String::new()));
        assert!(line.contains("camera ON"));
        assert!(line.contains("audio backstop ON"));
        assert!(!alarm);
    }

    /// The state this whole change exists for. Before 2026-09-12 the TUI drew
    /// no kernel line at all, so a machine with the backstop off looked
    /// identical to one with it on.
    #[test]
    fn an_off_backstop_alarms_and_says_so() {
        let (line, alarm) = kernel_status_line(
            &kernel(true, true, 6, 0),
            &(false, "the audio server is not in the capture allowlist".to_string()),
        );
        assert!(line.contains("audio backstop OFF"), "got: {line}");
        assert!(alarm, "a guard that is off must catch the eye");
    }

    /// An old daemon has no GetAudioBackstop, so `refresh()` leaves the default
    /// `(false, "")`. That must render as UNKNOWN: printing "OFF" would assert
    /// that protection is absent when nothing was ever asked.
    #[test]
    fn a_daemon_without_the_method_reads_unknown_not_off() {
        let (line, _) = kernel_status_line(&kernel(true, true, 6, 0), &(false, String::new()));
        assert!(line.contains("audio backstop UNKNOWN"), "got: {line}");
        assert!(!line.contains("backstop OFF"));
    }

    /// A disconnected daemon must not alarm. The helper may be enforcing from
    /// its policy cache with the daemon simply unable to see it — that is the
    /// documented 2026-08-19 situation, and painting it red teaches the user to
    /// ignore the colour.
    #[test]
    fn unreachable_is_reported_without_crying_wolf() {
        let (line, alarm) = kernel_status_line(&kernel(false, false, 0, 0), &(false, String::new()));
        assert!(line.contains("UNREACHABLE"), "got: {line}");
        assert!(line.contains("may still be enforcing"));
        assert!(!alarm, "unknown is not danger");
    }

    /// Unusable entries mean apps are being denied by a rule that cannot work.
    #[test]
    fn unusable_entries_are_surfaced_and_alarm() {
        let (line, alarm) = kernel_status_line(&kernel(true, true, 6, 2), &(true, String::new()));
        assert!(line.contains("2 UNUSABLE"), "got: {line}");
        assert!(alarm);
    }
}
