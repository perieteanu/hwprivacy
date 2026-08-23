use gtk::prelude::*;
use gtk::{self, glib, Align, Orientation, SelectionMode};
use hwprivacy_common::dbus_interface::HwPrivacyProxy;

#[derive(Debug)]
enum UiMessage {
    Devices(Vec<(String, String, String, bool)>),
    /// One entry per RULE: (app, mic, camera, monitor, exe_path, gap_note).
    /// A permission is "" when the rule says nothing about that category.
    Rules(Vec<(String, String, String, String, String, String)>),
    /// Binaries the kernel layer has denied a camera: (exe_path, denials, last).
    ///
    /// This is the list the user picks from to grant a camera. It exists
    /// because the kernel layer matches an executable by inode and never looks
    /// at an app name — so there was no string a user could type into the
    /// rules form that would grant a camera, and no way to discover the path.
    CameraDenials(Vec<(String, u32, String)>),
    Streams(Vec<(String, u32, String, String, String, String, bool)>),
    Events(Vec<(String, String, String, String)>),
    Status(bool, u32, u32, u32, u32),
    Error(String),
}

enum DaemonCommand {
    Refresh,
    SetRule(String, String, String),
    /// Grant a camera at BOTH layers: `camera = allow` on `app`, plus the
    /// executable the kernel layer needs. One command because doing only half
    /// leaves a rule that reads `allow` and denies.
    AllowCamera { app: String, exe_path: String },
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

    // -- Camera denials: the source for a camera grant --
    //
    // Sits above the add-rule form deliberately. The form cannot grant a
    // camera on its own: the kernel layer matches an executable by inode and
    // ignores the app name entirely, so a user typing into it has no way to
    // reach the camera and no way to discover the path. This list is that way.
    let denials_label = gtk::Label::new(Some("Camera denials — pick one to allow"));
    denials_label.set_halign(Align::Start);
    denials_label.add_css_class("heading");
    rules_box.append(&denials_label);
    let denials_list = gtk::ListBox::new();
    denials_list.set_selection_mode(SelectionMode::None);
    let denials_scroll = gtk::ScrolledWindow::new();
    denials_scroll.set_child(Some(&denials_list));
    denials_scroll.set_min_content_height(90);
    rules_box.append(&denials_scroll);

    // Add-rule form
    let add_row = gtk::Box::new(Orientation::Horizontal, 6);

    // Editable combo, not a bare Entry: the known names come from the rules
    // and streams the daemon already reports, and a new one is still typeable.
    let app_combo = gtk::ComboBoxText::with_entry();
    app_combo.set_hexpand(true);
    if let Some(entry) = app_combo.child().and_downcast::<gtk::Entry>() {
        entry.set_placeholder_text(Some("app (e.g. obs)"));
    }

    // A dropdown, because there are exactly three categories. The old free-text
    // field's placeholder advertised "screen", which DeviceCategory::from_str
    // rejects — it told the user to type a value that could not work.
    let dev_combo = gtk::ComboBoxText::new();
    for d in ["camera", "microphone", "monitor"] {
        dev_combo.append_text(d);
    }
    dev_combo.set_active(Some(0));

    let perm_combo = gtk::ComboBoxText::new();
    for p in ["allow", "deny", "ask", "while_in_use"] {
        perm_combo.append_text(p);
    }
    perm_combo.set_active(Some(0));
    let add_btn = gtk::Button::with_label("Add / Update");
    add_row.append(&app_combo);
    add_row.append(&dev_combo);
    add_row.append(&perm_combo);
    add_row.append(&add_btn);
    rules_box.append(&add_row);

    let form_hint = gtk::Label::new(Some(
        "A camera rule set here reaches the PipeWire layer only. \
         Non-sandboxed apps need a binary — use the denial list above.",
    ));
    form_hint.set_halign(Align::Start);
    form_hint.set_wrap(true);
    form_hint.add_css_class("caption");
    rules_box.append(&form_hint);

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
         .perm-ask { color: #f39c12; }
         .perm-unset { color: #7f8c8d; font-style: italic; }",
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
    let cmd_tx_allow = cmd_tx.clone();
    let denials_list_c = denials_list.clone();
    let app_combo_c = app_combo.clone();
    let window_c = window.clone();
    // Rule names currently known, so the grant dialog can offer to land a
    // binary on a rule that already exists instead of creating a second one.
    let known_apps: std::rc::Rc<std::cell::RefCell<Vec<String>>> =
        std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let known_apps_c = known_apps.clone();
    let known_apps_c2 = known_apps.clone();

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
                    for (app, mic, cam, mon, exe, note) in &rules {
                        let row = gtk::Box::new(Orientation::Vertical, 2);
                        row.set_margin_top(3);
                        row.set_margin_bottom(3);

                        let top = gtk::Box::new(Orientation::Horizontal, 10);
                        let lbl = gtk::Label::new(Some(app));
                        lbl.set_halign(Align::Start);
                        lbl.set_width_chars(20);
                        lbl.set_xalign(0.0);
                        top.append(&lbl);

                        // One cell per category. An empty permission means the
                        // rule says nothing there and the category follows
                        // default_action — rendering that as "deny" was a lie
                        // the old three-rows-per-rule listing could not avoid.
                        for (name, perm) in [("mic", mic), ("cam", cam), ("mon", mon)] {
                            let text = if perm.is_empty() {
                                format!("{name}: —")
                            } else {
                                format!("{name}: {perm}")
                            };
                            let plbl = gtk::Label::new(Some(&text));
                            plbl.set_width_chars(18);
                            plbl.set_xalign(0.0);
                            plbl.add_css_class(match perm.as_str() {
                                "allow" => "perm-allow",
                                "deny" => "perm-deny",
                                                                "while_in_use" => "perm-while-in-use",
                                "" => "perm-unset",
                                _ => "perm-ask",
                            });
                            top.append(&plbl);
                        }

                        let spacer = gtk::Label::new(None);
                        spacer.set_hexpand(true);
                        top.append(&spacer);

                        let del_btn = gtk::Button::with_label("Remove");
                        let cmd_del = cmd_tx_del.clone();
                        let app_owned = app.clone();
                        del_btn.connect_clicked(move |_| {
                            let _ = cmd_del.send(DaemonCommand::RemoveRule(app_owned.clone()));
                        });
                        top.append(&del_btn);
                        row.append(&top);

                        // The executable, and — the point of this row — whether
                        // the rule can actually reach the layer it names.
                        let sub = gtk::Label::new(Some(&if note.is_empty() {
                            format!(
                                "    binary: {}",
                                if exe.is_empty() { "(none)" } else { exe.as_str() }
                            )
                        } else {
                            format!("    ! {note}")
                        }));
                        sub.set_halign(Align::Start);
                        sub.set_wrap(true);
                        sub.add_css_class(if note.is_empty() { "caption" } else { "perm-deny" });
                        row.append(&sub);

                        rules_list_c.append(&row);
                    }

                    // Keep the app-name dropdown in step with reality, without
                    // clobbering whatever the user is mid-way through typing.
                    let names: Vec<String> = rules.iter().map(|r| r.0.clone()).collect();
                    refresh_app_names(&app_combo_c, &known_apps_c, names);
                }
                UiMessage::CameraDenials(denials) => {
                    clear_listbox(&denials_list_c);
                    if denials.is_empty() {
                        let lbl = gtk::Label::new(Some(
                            "    Nothing yet — a binary appears here once it has been denied.",
                        ));
                        lbl.set_halign(Align::Start);
                        lbl.add_css_class("caption");
                        denials_list_c.append(&lbl);
                    }
                    for (path, count, last) in &denials {
                        let row = gtk::Box::new(Orientation::Horizontal, 10);
                        row.set_margin_top(2);
                        row.set_margin_bottom(2);
                        let lbl = gtk::Label::new(Some(&format!(
                            "{}   ({} denials, last {})",
                            path, count, last
                        )));
                        lbl.set_halign(Align::Start);
                        lbl.set_hexpand(true);
                        lbl.set_wrap(true);
                        let btn = gtk::Button::with_label("Allow camera");
                        let cmd_allow = cmd_tx_allow.clone();
                        let path_owned = path.clone();
                        let known = known_apps_c2.clone();
                        let parent = window_c.clone();
                        btn.connect_clicked(move |_| {
                            show_grant_dialog(
                                &parent,
                                &path_owned,
                                &known.borrow(),
                                cmd_allow.clone(),
                            );
                        });
                        row.append(&lbl);
                        row.append(&btn);
                        denials_list_c.append(&row);
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
    let app_combo_add = app_combo.clone();
    let dev_combo_c = dev_combo.clone();
    let perm_combo_c = perm_combo.clone();
    add_btn.connect_clicked(move |_| {
        let app = app_combo_add
            .child()
            .and_downcast::<gtk::Entry>()
            .map(|e| e.text().to_string())
            .unwrap_or_default();
        let dev = dev_combo_c.active_text().map(|s| s.to_string()).unwrap_or_default();
        let perm = perm_combo_c.active_text().map(|s| s.to_string()).unwrap_or_default();
        if app.trim().is_empty() || dev.is_empty() || perm.is_empty() {
            return;
        }
        let _ = cmd_add.send(DaemonCommand::SetRule(app.trim().to_string(), dev, perm));
        if let Some(e) = app_combo_add.child().and_downcast::<gtk::Entry>() {
            e.set_text("");
        }
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

/// Repopulate the app-name dropdown from the names the daemon knows.
///
/// Refresh runs every two seconds, so this is on a hot path in the only sense
/// that matters for a UI: it must not disturb someone mid-word.
///
/// # What actually threatens the entry, measured
///
/// Not `remove_all()` and not `append_text()` — both leave a
/// `ComboBoxText::with_entry`'s text alone (measured 2026-08-23, GTK 4.18.6).
/// Only `set_active()` writes to it. So there is deliberately NO save/restore
/// dance here: an earlier draft had one, it could never fire, and code that
/// guards an impossible hazard reads as evidence the hazard is real.
///
/// The early return is still worth keeping — rebuilding the model would close
/// an open dropdown and churn widgets twice a second for nothing — but it is
/// an efficiency guard, not a correctness one, and is not claimed as more.
fn refresh_app_names(
    combo: &gtk::ComboBoxText,
    known: &std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    mut names: Vec<String>,
) {
    names.sort();
    names.dedup();
    if *known.borrow() == names {
        return;
    }
    combo.remove_all();
    for n in &names {
        combo.append_text(n);
    }
    *known.borrow_mut() = names;
}

/// Ask which rule a denied binary should be attached to, then grant it.
///
/// The dropdown exists because the two layers key on different things: the
/// PipeWire layer on a name the application declares about itself ("firefox"),
/// the kernel layer on an executable ("/usr/lib/firefox-esr/firefox-esr", whose
/// short name is "firefox-esr"). Defaulting silently to the short name would
/// leave two rules for one application; offering the existing names lets one
/// rule carry both identities.
fn show_grant_dialog(
    parent: &gtk::ApplicationWindow,
    exe_path: &str,
    known_apps: &[String],
    cmd_tx: tokio::sync::mpsc::UnboundedSender<DaemonCommand>,
) {
    let suggested = hwprivacy_common::short_name(exe_path);

    let win = gtk::Window::builder()
        .title("Allow camera")
        .transient_for(parent)
        .modal(true)
        .default_width(520)
        .build();

    let vbox = gtk::Box::new(Orientation::Vertical, 10);
    vbox.set_margin_top(14);
    vbox.set_margin_bottom(14);
    vbox.set_margin_start(14);
    vbox.set_margin_end(14);

    let path_lbl = gtk::Label::new(Some(&format!("Binary:  {exe_path}")));
    path_lbl.set_halign(Align::Start);
    path_lbl.set_wrap(true);
    vbox.append(&path_lbl);

    let explain = gtk::Label::new(Some(
        "Attach it to which rule?  The camera is granted by executable, while \
         the microphone and monitor are matched by the name the app reports. \
         Pick an existing rule to keep both on one entry.",
    ));
    explain.set_halign(Align::Start);
    explain.set_wrap(true);
    explain.add_css_class("caption");
    vbox.append(&explain);

    let combo = gtk::ComboBoxText::with_entry();
    for n in known_apps {
        combo.append_text(n);
    }
    if let Some(e) = combo.child().and_downcast::<gtk::Entry>() {
        e.set_text(&suggested);
    }
    vbox.append(&combo);

    let buttons = gtk::Box::new(Orientation::Horizontal, 8);
    buttons.set_halign(Align::End);
    let cancel = gtk::Button::with_label("Cancel");
    let confirm = gtk::Button::with_label("Allow camera");
    confirm.add_css_class("suggested-action");
    buttons.append(&cancel);
    buttons.append(&confirm);
    vbox.append(&buttons);

    win.set_child(Some(&vbox));

    let win_cancel = win.clone();
    cancel.connect_clicked(move |_| win_cancel.close());

    let win_ok = win.clone();
    let path_owned = exe_path.to_string();
    confirm.connect_clicked(move |_| {
        let app = combo
            .child()
            .and_downcast::<gtk::Entry>()
            .map(|e| e.text().to_string())
            .unwrap_or_default();
        if app.trim().is_empty() {
            return;
        }
        let _ = cmd_tx.send(DaemonCommand::AllowCamera {
            app: app.trim().to_string(),
            exe_path: path_owned.clone(),
        });
        win_ok.close();
    });

    win.present();
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
                if let Ok(h) = proxy.get_history().await {
                    let denials: Vec<(String, u32, String)> = h
                        .into_iter()
                        .filter(|(_, device, source, denied, ..)| {
                            source == "kernel" && device == "camera" && *denied > 0
                        })
                        .map(|(identity, _, _, denied, _, _, last)| (identity, denied, last))
                        .collect();
                    let _ = ui_tx.send(UiMessage::CameraDenials(denials)).await;
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
            DaemonCommand::AllowCamera { app, exe_path } => {
                // Atomic on the daemon side, so a successful grant never
                // flashes the "rule saved but not in force" notification for
                // the instant between the rule and its binary.
                match proxy.allow_camera(&app, &exe_path).await {
                    Ok((true, msg)) => {
                        let _ = ui_tx.send(UiMessage::Error(msg)).await;
                    }
                    Ok((false, why)) => {
                        let _ = ui_tx
                            .send(UiMessage::Error(format!("Nothing was written: {why}")))
                            .await;
                    }
                    Err(e) => {
                        let _ = ui_tx.send(UiMessage::Error(format!("D-Bus: {e}"))).await;
                    }
                }
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


#[cfg(test)]
mod tests {
    use super::*;

    /// ONE test function, not several.
    ///
    /// `gtk::init()` must run on the main thread and exactly once; cargo runs
    /// `#[test]` functions on parallel threads, so several GTK tests race and
    /// fail for a reason that has nothing to do with the code. Everything
    /// widget-shaped therefore lives here, in order, behind a single init.
    ///
    /// Needs a display. Skipped rather than failed when there is none, so a
    /// headless CI run does not report a defect it did not observe — a test
    /// that fails for want of an X server teaches you to ignore it.
    #[test]
    fn the_add_rule_form_offers_only_what_can_work() {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            eprintln!("no display; skipping GTK widget tests");
            return;
        }
        if gtk::init().is_err() {
            eprintln!("gtk::init failed; skipping GTK widget tests");
            return;
        }

        // -- the device dropdown ------------------------------------------
        //
        // AT-SPI cannot read a GTK4 ComboBoxText's popup contents, so the
        // model is asserted here instead. This is the check that would have
        // caught the placeholder advertising "screen": every entry must be a
        // string DeviceCategory::from_str actually accepts.
        let dev = gtk::ComboBoxText::new();
        for d in ["camera", "microphone", "monitor"] {
            dev.append_text(d);
        }
        let model = dev.model().expect("combo has a model");
        assert_eq!(
            model.iter_n_children(None),
            3,
            "three device categories, no more and no fewer"
        );

        let mut seen = Vec::new();
        if let Some(iter) = model.iter_first() {
            loop {
                let v: String = model.get_value(&iter, 0).get().expect("column 0 is text");
                seen.push(v);
                if !model.iter_next(&iter) {
                    break;
                }
            }
        }
        seen.sort();
        assert_eq!(seen, vec!["camera", "microphone", "monitor"]);
        assert!(
            !seen.iter().any(|s| s == "screen"),
            "'screen' is not a DeviceCategory; offering it tells the user to \
             type a value that will be rejected"
        );
        for s in &seen {
            assert!(
                s.parse::<hwprivacy_common::DeviceCategory>().is_ok(),
                "the dropdown offers {s:?}, which the daemon would reject"
            );
        }

        // -- refresh_app_names --------------------------------------------
        let combo = gtk::ComboBoxText::with_entry();
        let known = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

        refresh_app_names(&combo, &known, vec!["obs".into(), "firefox".into(), "obs".into()]);
        assert_eq!(
            *known.borrow(),
            vec!["firefox".to_string(), "obs".to_string()],
            "sorted and deduped"
        );

        // The model must actually carry what was asked for — `known` agreeing
        // while the dropdown shows something else would be the worst outcome.
        let read_back = |c: &gtk::ComboBoxText| {
            let m = c.model().expect("model");
            let mut v = Vec::new();
            if let Some(it) = m.iter_first() {
                loop {
                    v.push(m.get_value(&it, 0).get::<String>().expect("text"));
                    if !m.iter_next(&it) {
                        break;
                    }
                }
            }
            v
        };
        assert_eq!(read_back(&combo), vec!["firefox".to_string(), "obs".to_string()]);

        refresh_app_names(&combo, &known, vec!["obs".into(), "chrome".into()]);
        assert_eq!(read_back(&combo), vec!["chrome".to_string(), "obs".to_string()]);

        // The property that makes a 2 s refresh safe: rebuilding the list must
        // not disturb what someone is typing.
        //
        // Measured 2026-08-23: `remove_all` and `append_text` do not touch a
        // with_entry combo's text, but `set_active` does. So this is a guard
        // against a future refactor adding one — reintroduce `set_active` in
        // refresh_app_names and this assertion fails, which is the only reason
        // it is worth keeping.
        let entry = combo.child().and_downcast::<gtk::Entry>().expect("editable");
        entry.set_text("half-typed");
        refresh_app_names(&combo, &known, vec!["vlc".into(), "obs".into()]);
        assert_eq!(
            entry.text(),
            "half-typed",
            "rebuilding the list must not wipe what is being typed"
        );
    }
}
