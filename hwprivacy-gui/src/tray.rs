use crate::TrayCommand;
use ksni::{self, menu::StandardItem, Tray, TrayService};
use std::sync::mpsc::Sender;

struct HwPrivacyTray {
    tx: Sender<TrayCommand>,
}

impl Tray for HwPrivacyTray {
    fn icon_name(&self) -> String {
        "preferences-system-privacy".to_string()
    }

    fn title(&self) -> String {
        "HWPrivacy".to_string()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "HWPrivacy — Hardware Permission Manager".to_string(),
            description: "Click to show/hide. Right-click for menu.".to_string(),
            icon_name: "preferences-system-privacy".to_string(),
            icon_pixmap: Vec::new(),
        }
    }

    fn id(&self) -> String {
        "hwprivacy".to_string()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(TrayCommand::ToggleWindow);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Show HWPrivacy".to_string(),
                icon_name: "preferences-system-privacy".to_string(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(TrayCommand::ShowWindow);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Hide to Tray".to_string(),
                icon_name: "window-close".to_string(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(TrayCommand::HideWindow);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Exit".to_string(),
                icon_name: "application-exit".to_string(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(TrayCommand::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn run_tray(tx: Sender<TrayCommand>) {
    let service = TrayService::new(HwPrivacyTray { tx });
    let _handle = service.handle();
    let _ = service.run(); // blocks forever (tray event loop)
}
