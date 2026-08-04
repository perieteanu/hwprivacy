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
    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::Green).bg(Color::DarkGray))
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
    let header = Row::new(vec!["App", "Device", "Permission"])
        .style(Style::default().bold().fg(Color::Cyan))
        .bottom_margin(1);

    let rows: Vec<Row> = app
        .rules
        .iter()
        .enumerate()
        .map(|(i, (app_name, dev, perm))| {
            let style = if i == app.selected_row {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            let perm_style = permission_color(perm);
            Row::new(vec![
                Cell::from(app_name.as_str()),
                Cell::from(dev.as_str()),
                Cell::from(perm.as_str()).style(perm_style),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(25),
            Constraint::Length(12),
            Constraint::Min(15),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" App Rules "));

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
            Constraint::Length(10),
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
        " Tab:panel  ↑↓:navigate  a:allow  d:deny  e:ask_each  w:while_in_use  x:delete  r:refresh  q:quit",
    )
    .style(Style::default().fg(Color::DarkGray));

    f.render_widget(help, area);
}

fn permission_color(perm: &str) -> Style {
    match perm {
        "allow" => Style::default().fg(Color::Green),
        "deny" => Style::default().fg(Color::Red),
        "ask_each" => Style::default().fg(Color::Yellow),
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
