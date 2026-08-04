use crate::app::{App, Panel};
use crossterm::event::KeyCode;

pub async fn handle_key(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char('q') | KeyCode::Esc => {
            app.running = false;
        }
        KeyCode::Tab => {
            app.active_panel = app.active_panel.next();
            app.selected_row = 0;
        }
        KeyCode::Up => {
            if app.selected_row > 0 {
                app.selected_row -= 1;
            }
        }
        KeyCode::Down => {
            let max = app.max_rows().saturating_sub(1);
            if app.selected_row < max {
                app.selected_row += 1;
            }
        }
        KeyCode::Char('r') => {
            app.refresh().await;
        }

        // Rule modifications (only work in Rules panel)
        KeyCode::Char('a') if app.active_panel == Panel::Rules => {
            set_selected_rule_permission(app, "allow").await;
        }
        KeyCode::Char('d') if app.active_panel == Panel::Rules => {
            set_selected_rule_permission(app, "deny").await;
        }
        KeyCode::Char('e') if app.active_panel == Panel::Rules => {
            set_selected_rule_permission(app, "ask_each").await;
        }
        KeyCode::Char('w') if app.active_panel == Panel::Rules => {
            set_selected_rule_permission(app, "while_in_use").await;
        }
        KeyCode::Char('x') if app.active_panel == Panel::Rules => {
            delete_selected_rule(app).await;
        }

        _ => {}
    }
}

async fn set_selected_rule_permission(app: &mut App, permission: &str) {
    if let Some((app_name, device, _)) = app.rules.get(app.selected_row) {
        let _ = app
            .proxy
            .set_rule(app_name, device, permission)
            .await;
        app.refresh().await;
    }
}

async fn delete_selected_rule(app: &mut App) {
    if let Some((app_name, _, _)) = app.rules.get(app.selected_row) {
        let _ = app.proxy.remove_rule(app_name).await;
        app.refresh().await;
        if app.selected_row > 0 {
            app.selected_row -= 1;
        }
    }
}
