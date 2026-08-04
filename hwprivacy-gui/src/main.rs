mod tray;
mod window;

use gtk::prelude::*;
use gtk::glib;
use std::sync::mpsc;

const APP_ID: &str = "org.hwprivacy.Gui";

/// Suppressed warning substrings (harmless GTK 4.18 / config noise)
const SUPPRESSED: &[&str] = &[
    "reported min height",
    "reported min width",
    "Unknown key gtk-modules",
];

/// Raw GLib log writer — installed before ANY glib/gtk initialization.
/// This is the only way to catch warnings emitted during gtk_init itself.
unsafe extern "C" fn log_writer(
    level: glib::ffi::GLogLevelFlags,
    fields: *const glib::ffi::GLogField,
    n_fields: usize,
    _user_data: glib::ffi::gpointer,
) -> glib::ffi::GLogWriterOutput {
    // Only filter warnings; let everything else through
    if (level & glib::ffi::G_LOG_LEVEL_WARNING) != 0
        || (level & glib::ffi::G_LOG_LEVEL_DEBUG) != 0
    {
        // Search for MESSAGE field
        for i in 0..n_fields {
            let field = &*fields.add(i);
            let key = std::ffi::CStr::from_ptr(field.key);
            if key.to_bytes() == b"MESSAGE" {
                let msg = std::ffi::CStr::from_ptr(field.value as *const i8);
                if let Ok(msg_str) = msg.to_str() {
                    for pat in SUPPRESSED {
                        if msg_str.contains(pat) {
                            return glib::ffi::G_LOG_WRITER_HANDLED;
                        }
                    }
                }
            }
        }
    }

    // Pass everything else to the default writer
    glib::ffi::g_log_writer_default(level, fields, n_fields, std::ptr::null_mut())
}

/// Commands from tray icon to GTK main loop
#[derive(Debug)]
pub enum TrayCommand {
    ShowWindow,
    HideWindow,
    ToggleWindow,
    Quit,
}

fn main() -> glib::ExitCode {
    // Install log writer FIRST — before any glib/gtk calls
    unsafe {
        glib::ffi::g_log_set_writer_func(
            Some(log_writer),
            std::ptr::null_mut(),
            None,
        );
    }

    // Channel: tray thread → GTK main loop
    let (tray_tx, tray_rx) = mpsc::channel::<TrayCommand>();

    let app = gtk::Application::builder()
        .application_id(APP_ID)
        .build();

    // Start tray icon in background thread
    std::thread::spawn(move || {
        tray::run_tray(tray_tx);
    });

    // Process tray commands on GTK main loop
    let app_for_tray = app.clone();
    let tray_rx = std::sync::Mutex::new(tray_rx);
    glib::timeout_add_local(std::time::Duration::from_millis(100), move || {
        if let Ok(rx) = tray_rx.lock() {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    TrayCommand::ShowWindow => {
                        if let Some(win) = app_for_tray.active_window() {
                            win.set_visible(true);
                            win.present();
                        }
                    }
                    TrayCommand::HideWindow => {
                        if let Some(win) = app_for_tray.active_window() {
                            win.set_visible(false);
                        }
                    }
                    TrayCommand::ToggleWindow => {
                        if let Some(win) = app_for_tray.active_window() {
                            if win.is_visible() {
                                win.set_visible(false);
                            } else {
                                win.set_visible(true);
                                win.present();
                            }
                        }
                    }
                    TrayCommand::Quit => {
                        app_for_tray.quit();
                    }
                }
            }
        }
        glib::ControlFlow::Continue
    });

    // Ctrl+Q to really quit
    app.set_accels_for_action("app.quit", &["<Ctrl>Q"]);
    let quit_action = gtk::gio::SimpleAction::new("quit", None);
    let app_quit = app.clone();
    quit_action.connect_activate(move |_, _| {
        app_quit.quit();
    });
    app.add_action(&quit_action);

    app.connect_activate(window::build_ui);
    app.run()
}
