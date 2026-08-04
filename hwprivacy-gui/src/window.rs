use gtk::prelude::*;
use gtk::{self, glib, Align, Orientation, SelectionMode};
use hwprivacy_common::dbus_interface::HwPrivacyProxy;

#[derive(Debug)]
enum UiMessage {
    Devices(Vec<(String, String, String, bool)>),
    Rules(Vec<(String, String, String)>),
    Streams(Vec<(String, u32, String, String, String, String, bool)>),
    Events(Vec<(String, String, String, String)>),
    Status(bool, u32, u32, u32, u32),
    Error(String),
}

enum DaemonCommand {
    Refresh,
    SetRule(String, String, String),
    RemoveRule(String),
    BlockAll,
    UnblockAll,
}

pub fn build_ui(app: &gtk::Application) {
    // If window already exists (re-activate), just show it
    if let Some(win) = app.active_window() {
        win.set_visible(true);
        win.present();
        return;
    }

    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("HWPrivacy — Hardware Permission Manager")
        .default_width(700)
        .default_height(500)
        .build();

    // Close button hides to tray instead of quitting
    window.connect_close_request(|win| {
        win.set_visible(false);
        glib::Propagation::Stop // prevent default destroy
    });

    // Main layout: header + notebook
    let main_box = gtk::Box::new(Orientation::Vertical, 0);

    // Status bar at top
    let status_label = gtk::Label::new(Some("Connecting to daemon..."));
    status_label.set_halign(Align::Start);
    status_label.set_margin_start(10);
    status_label.set_margin_top(5);
    status_label.set_margin_bottom(5);
    status_label.add_css_class("caption");
    main_box.append(&status_label);
    main_box.append(&gtk::Separator::new(Orientation::Horizontal));

    // Notebook (tabs)
    let notebook = gtk::Notebook::new();

    // -- Devices tab --
    let devices_box = gtk::Box::new(Orientation::Vertical, 8);
    devices_box.set_margin_top(10);
    devices_box.set_margin_start(10);
    devices_box.set_margin_end(10);
    let devices_list = gtk::ListBox::new();
    devices_list.set_selection_mode(SelectionMode::None);
    let devices_scroll = gtk::ScrolledWindow::new();
    devices_scroll.set_child(Some(&devices_list));
    devices_scroll.set_vexpand(true);
    devices_box.append(&devices_scroll);
    notebook.append_page(&devices_box, Some(&gtk::Label::new(Some("Devices"))));

    // -- Rules tab --
    let rules_box = gtk::Box::new(Orientation::Vertical, 8);
    rules_box.set_margin_top(10);
    rules_box.set_margin_start(10);
    rules_box.set_margin_end(10);
    let rules_list = gtk::ListBox::new();
    rules_list.set_selection_mode(SelectionMode::None);
    let rules_scroll = gtk::ScrolledWindow::new();
    rules_scroll.set_child(Some(&rules_list));
    rules_scroll.set_vexpand(true);
    rules_box.append(&rules_scroll);

    // Add-rule form
    let add_row = gtk::Box::new(Orientation::Horizontal, 6);
    let app_entry = gtk::Entry::new();
    app_entry.set_placeholder_text(Some("app (e.g. obs)"));
    app_entry.set_hexpand(true);
    let dev_entry = gtk::Entry::new();
    dev_entry.set_placeholder_text(Some("device (camera/microphone/screen/...)"));
    dev_entry.set_hexpand(true);
    let perm_combo = gtk::ComboBoxText::new();
    for p in ["allow", "deny", "ask", "ask_each", "while_in_use"] {
        perm_combo.append_text(p);
    }
    perm_combo.set_active(Some(0));
    let add_btn = gtk::Button::with_label("Add / Update");
    add_row.append(&app_entry);
    add_row.append(&dev_entry);
    add_row.append(&perm_combo);
    add_row.append(&add_btn);
    rules_box.append(&add_row);

    notebook.append_page(&rules_box, Some(&gtk::Label::new(Some("Rules"))));

    // -- Streams tab --
    let streams_box = gtk::Box::new(Orientation::Vertical, 8);
    streams_box.set_margin_top(10);
    streams_box.set_margin_start(10);
    streams_box.set_margin_end(10);
    let streams_list = gtk::ListBox::new();
    streams_list.set_selection_mode(SelectionMode::None);
    let streams_scroll = gtk::ScrolledWindow::new();
    streams_scroll.set_child(Some(&streams_list));
    streams_scroll.set_vexpand(true);
    streams_box.append(&streams_scroll);
    notebook.append_page(&streams_box, Some(&gtk::Label::new(Some("Streams"))));

    // -- Events tab --
    let events_box = gtk::Box::new(Orientation::Vertical, 8);
    events_box.set_margin_top(10);
    events_box.set_margin_start(10);
    events_box.set_margin_end(10);
    let events_list = gtk::ListBox::new();
    events_list.set_selection_mode(SelectionMode::None);
    let events_scroll = gtk::ScrolledWindow::new();
    events_scroll.set_child(Some(&events_list));
    events_scroll.set_vexpand(true);
    events_box.append(&events_scroll);
    notebook.append_page(&events_box, Some(&gtk::Label::new(Some("Events"))));

    // Emergency buttons bar
    let button_bar = gtk::Box::new(Orientation::Horizontal, 8);
    button_bar.set_margin_start(10);
    button_bar.set_margin_end(10);
    button_bar.set_margin_top(5);
    button_bar.set_margin_bottom(5);

    let block_all_btn = gtk::Button::with_label("Block All");
    block_all_btn.add_css_class("destructive-action");
    let unblock_all_btn = gtk::Button::with_label("Unblock All");
    let refresh_btn = gtk::Button::with_label("Refresh");

    button_bar.append(&block_all_btn);
    button_bar.append(&unblock_all_btn);
    button_bar.append(&refresh_btn);

    main_box.append(&notebook);
    main_box.append(&gtk::Separator::new(Orientation::Horizontal));
    main_box.append(&button_bar);
    window.set_child(Some(&main_box));

    // CSS
    let css = gtk::CssProvider::new();
    css.load_from_data(
        ".perm-allow { color: #27ae60; font-weight: bold; }
         .perm-deny { color: #e74c3c; font-weight: bold; }
         .perm-ask-each { color: #f39c12; font-weight: bold; }
         .perm-while-in-use { color: #3498db; font-weight: bold; }
         .perm-ask { color: #f39c12; }",
    );
    gtk::style_context_add_provider_for_display(
        &gtk::gdk::Display::default().unwrap(),
        &css,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Communication channels
    let (ui_tx, ui_rx) = async_channel::unbounded::<UiMessage>();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<DaemonCommand>();

    // Spawn D-Bus worker
    let ui_tx_worker = ui_tx.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(dbus_worker(ui_tx_worker, cmd_rx));
    });

    // Handle D-Bus responses
    let devices_list_c = devices_list.clone();
    let rules_list_c = rules_list.clone();
    let streams_list_c = streams_list.clone();
    let events_list_c = events_list.clone();
    let status_label_c = status_label.clone();
    let cmd_tx_del = cmd_tx.clone();

    glib::spawn_future_local(async move {
        while let Ok(msg) = ui_rx.recv().await {
            match msg {
                UiMessage::Status(running, devs, rules, blocked, streams) => {
                    status_label_c.set_text(&format!(
                        "{} | Devices: {} | Rules: {} | Blocked: {} | Streams: {}",
                        if running { "Running" } else { "Stopped" },
                        devs, rules, blocked, streams,
                    ));
                }
                UiMessage::Devices(devices) => {
                    clear_listbox(&devices_list_c);
                    for (cat, _node, desc, guarded) in &devices {
                        let row = gtk::Box::new(Orientation::Horizontal, 10);
                        row.set_margin_top(4);
                        row.set_margin_bottom(4);
                        let lbl = gtk::Label::new(Some(&format!("{:<12} {}", cat, desc)));
                        lbl.set_halign(Align::Start);
                        lbl.set_hexpand(true);
                        let guard = gtk::Label::new(Some(if *guarded { "GUARDED" } else { "OFF" }));
                        guard.add_css_class(if *guarded { "perm-allow" } else { "perm-deny" });
                        row.append(&lbl);
                        row.append(&guard);
                        devices_list_c.append(&row);
                    }
                }
                UiMessage::Rules(rules) => {
                    clear_listbox(&rules_list_c);
                    for (app, dev, perm) in &rules {
                        let row = gtk::Box::new(Orientation::Horizontal, 10);
                        row.set_margin_top(2);
                        row.set_margin_bottom(2);
                        let lbl = gtk::Label::new(Some(&format!("{:<25} {:<12}", app, dev)));
                        lbl.set_halign(Align::Start);
                        lbl.set_hexpand(true);
                        let plbl = gtk::Label::new(Some(perm));
                        let css_class = match perm.as_str() {
                            "allow" => "perm-allow",
                            "deny" => "perm-deny",
                            "ask_each" => "perm-ask-each",
                            "while_in_use" => "perm-while-in-use",
                            _ => "perm-ask",
                        };
                        plbl.add_css_class(css_class);
                        let del_btn = gtk::Button::with_label("Remove");
                        let cmd_del = cmd_tx_del.clone();
                        let app_owned = app.clone();
                        del_btn.connect_clicked(move |_| {
                            let _ = cmd_del.send(DaemonCommand::RemoveRule(app_owned.clone()));
                        });
                        row.append(&lbl);
                        row.append(&plbl);
                        row.append(&del_btn);
                        rules_list_c.append(&row);
                    }
                }
                UiMessage::Streams(streams) => {
                    clear_listbox(&streams_list_c);
                    for (app, pid, dev, node, _media, perm, active) in &streams {
                        let row = gtk::Box::new(Orientation::Horizontal, 8);
                        row.set_margin_top(2);
                        row.set_margin_bottom(2);
                        let text = format!(
                            "{} (pid:{}) → {} [{}] {}",
                            app,
                            pid,
                            dev,
                            if node.len() > 20 { &node[..20] } else { node },
                            perm,
                        );
                        let lbl = gtk::Label::new(Some(&text));
                        lbl.set_halign(Align::Start);
                        lbl.set_hexpand(true);
                        let status = gtk::Label::new(Some(if *active { "active" } else { "ended" }));
                        status.add_css_class(if *active { "perm-allow" } else { "perm-deny" });
                        row.append(&lbl);
                        row.append(&status);
                        streams_list_c.append(&row);
                    }
                }
                UiMessage::Events(events) => {
                    clear_listbox(&events_list_c);
                    for (ts, app, dev, action) in events.iter().rev() {
                        let text = format!("{} {} → {} → {}", ts, app, dev, action);
                        let lbl = gtk::Label::new(Some(&text));
                        lbl.set_halign(Align::Start);
                        let css_class = match action.as_str() {
                            "ALLOWED" | "STREAM_ALLOWED" => "perm-allow",
                            "DENIED" | "STREAM_DENIED" => "perm-deny",
                            "ASKED" => "perm-ask",
                            _ => "",
                        };
                        if !css_class.is_empty() {
                            lbl.add_css_class(css_class);
                        }
                        events_list_c.append(&lbl);
                    }
                }
                UiMessage::Error(msg) => {
                    status_label_c.set_text(&format!("Error: {}", msg));
                }
            }
        }
    });

    // Button handlers
    let cmd_block = cmd_tx.clone();
    block_all_btn.connect_clicked(move |_| { let _ = cmd_block.send(DaemonCommand::BlockAll); });

    let cmd_unblock = cmd_tx.clone();
    unblock_all_btn.connect_clicked(move |_| { let _ = cmd_unblock.send(DaemonCommand::UnblockAll); });

    let cmd_refresh = cmd_tx.clone();
    refresh_btn.connect_clicked(move |_| { let _ = cmd_refresh.send(DaemonCommand::Refresh); });

    // Add-rule button handler
    let cmd_add = cmd_tx.clone();
    let app_entry_c = app_entry.clone();
    let dev_entry_c = dev_entry.clone();
    let perm_combo_c = perm_combo.clone();
    add_btn.connect_clicked(move |_| {
        let app = app_entry_c.text().to_string();
        let dev = dev_entry_c.text().to_string();
        let perm = perm_combo_c.active_text().map(|s| s.to_string()).unwrap_or_default();
        if app.is_empty() || dev.is_empty() || perm.is_empty() {
            return;
        }
        let _ = cmd_add.send(DaemonCommand::SetRule(app, dev, perm));
        app_entry_c.set_text("");
        dev_entry_c.set_text("");
    });

    // Initial refresh
    let _ = cmd_tx.send(DaemonCommand::Refresh);

    // Auto-refresh every 2 seconds
    let cmd_auto = cmd_tx.clone();
    glib::timeout_add_seconds_local(2, move || {
        let _ = cmd_auto.send(DaemonCommand::Refresh);
        glib::ControlFlow::Continue
    });

    window.present();
}

fn clear_listbox(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

async fn dbus_worker(
    ui_tx: async_channel::Sender<UiMessage>,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<DaemonCommand>,
) {
    let connection = match zbus::Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            let _ = ui_tx.send(UiMessage::Error(format!("D-Bus: {}", e))).await;
            return;
        }
    };

    let proxy = match HwPrivacyProxy::new(&connection).await {
        Ok(p) => p,
        Err(e) => {
            let _ = ui_tx.send(UiMessage::Error(format!("Daemon: {}", e))).await;
            return;
        }
    };

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            DaemonCommand::Refresh => {
                if let Ok(s) = proxy.get_status().await {
                    let _ = ui_tx.send(UiMessage::Status(s.0, s.1, s.2, s.3, s.4)).await;
                }
                if let Ok(d) = proxy.get_devices().await {
                    let _ = ui_tx.send(UiMessage::Devices(d)).await;
                }
                if let Ok(r) = proxy.get_rules().await {
                    let _ = ui_tx.send(UiMessage::Rules(r)).await;
                }
                if let Ok(s) = proxy.get_active_streams().await {
                    let _ = ui_tx.send(UiMessage::Streams(s)).await;
                }
                if let Ok(e) = proxy.get_events(50).await {
                    let _ = ui_tx.send(UiMessage::Events(e)).await;
                }
            }
            DaemonCommand::SetRule(app, dev, perm) => {
                let _ = proxy.set_rule(&app, &dev, &perm).await;
                let _ = ui_tx.send(UiMessage::Status(true, 0, 0, 0, 0)).await; // trigger refresh
            }
            DaemonCommand::RemoveRule(app) => {
                let _ = proxy.remove_rule(&app).await;
            }
            DaemonCommand::BlockAll => {
                let _ = proxy.block_all().await;
            }
            DaemonCommand::UnblockAll => {
                let _ = proxy.unblock_all().await;
            }
        }
    }
}
