# HWPrivacy — Hardware Permission Manager for Linux

An Android-style hardware permission manager for the Linux desktop.
Applications must be granted explicit permission to access microphones, cameras,
and playback monitor sources. Default policy: **deny all**.

Built for Debian 13 (Trixie) with PipeWire/WirePlumber. Works on KDE Plasma and GNOME.

---

## Table of Contents

- [Motivation](#motivation)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Permission Model](#permission-model)
- [Components](#components)
- [Technology Choices](#technology-choices)
- [Building](#building)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [What Has Been Implemented](#what-has-been-implemented)
- [What Remains To Be Done](#what-remains-to-be-done)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Motivation

On Android, every app must request permission to use the microphone, camera, or
other hardware. The user explicitly grants or denies access. On traditional Linux
desktops, **no such permission system exists for native applications**. Any process
running as your user can freely connect to PipeWire and grab the microphone, camera,
or even record what you're listening to — all without your knowledge or consent.

Flatpak/Snap apps have sandboxed permissions via XDG Portals, but native .deb-installed
applications (Firefox, Telegram, Chromium, etc.) bypass all of this.

HWPrivacy fills this gap by operating at the **PipeWire graph level**, intercepting
and enforcing access policies for all applications regardless of packaging format.

---

## How It Works

Every audio/video device on a modern Linux desktop flows through **PipeWire**.
PipeWire represents everything as a directed graph:

- **Device nodes**: microphone sources, camera sources, speaker sinks
- **Application nodes**: Firefox audio streams, Telegram voice calls, etc.
- **Links**: connections between nodes (e.g., microphone → Firefox capture)

HWPrivacy monitors this graph by polling `pw-dump` every 500ms. When a new link
appears connecting an application to a protected device, the daemon:

1. **Identifies** the application (name, PID, stream properties) and device category
2. **Checks** the rules database for a matching policy
3. **Enforces** the decision: allow the link, destroy it, or prompt the user

For **playback monitor protection**, the daemon detects a specific PipeWire pattern:
when an `Audio/Sink` node appears as the **output** side of a link to a
`Stream/Input/Audio` node, that means an application is tapping the monitor source
(recording what's playing through the speakers). Normal playback flows in the
opposite direction (`Stream/Output/Audio → Audio/Sink`) and is never blocked.

---

## Architecture

```
                    PipeWire Graph
                    (nodes + links)
                         |
                         | pw-dump (JSON polling every 500ms)
                         v
    +--------------------------------------------+
    |          hwprivacy-daemon (Rust)            |
    |                                            |
    |  Device Discovery   Policy Engine          |
    |  (mic, cam, monitor) (rules + per-stream)  |
    |                                            |
    |  Link Manager        Stream Tracker        |
    |  (pw-link destroy)   (active, cooldowns)   |
    |                                            |
    |  Notification Manager (2-stage)            |
    |  1. Instant BLOCKED alert (5s auto-dismiss)|
    |  2. Action prompt (Allow/Deny/AskEach/Use) |
    |                                            |
    |  D-Bus Service (org.hwprivacy.Daemon)      |
    +--------------------------------------------+
         |           |           |           |
         v           v           v           v
    hwprivacy-  hwprivacy-  hwprivacy-  Desktop
       ctl         tui         gui      Notifications
    (CLI)      (htop-like)  (GTK4 +     (freedesktop)
                             tray icon)
```

---

## Permission Model

### Permission Levels

| Permission | Behavior | Best for |
|------------|----------|----------|
| `allow` | All streams from this app auto-allowed | Trusted apps (OBS, dedicated voice app) |
| `ask_each` | Every new stream triggers a prompt | Browsers (per-tab gating) |
| `while_in_use` | Allowed while app's PipeWire client is active | Messaging apps (Telegram, Signal) |
| `ask` | Prompt once, save permanent rule | Unknown apps (default) |
| `deny` | Always blocked, instant notification shown | Untrusted apps |

### Two-Layer Model (The Browser Solution)

Browsers are mini operating systems — one "Firefox" PipeWire client serves dozens
of tabs. At the PipeWire level, all tabs share one client name. However, each tab
that requests mic/camera access creates a **separate PipeWire node** with unique
properties (`object.serial`, `node.name`, `media.name`).

HWPrivacy uses two layers:

- **Layer 1 (App rule)**: "Firefox may use the mic" — baseline permission
- **Layer 2 (Per-stream gating)**: With `ask_each`, every NEW capture node from
  Firefox triggers a notification. Shady JavaScript in a background tab gets caught.

### Notification Behavior

**2-stage notifications:**

1. **Stage 1 — Instant BLOCKED** (fire-and-forget, auto-dismisses in 5s):
   Tells the user immediately that an access attempt was caught and blocked.

2. **Stage 2 — Action prompt** (persistent, waits for user response):
   Presents buttons to set a rule. For `ask`: [Always Allow] [Ask Each Time]
   [While in Use] [Always Deny]. For `ask_each`: [Allow Stream] [Deny Stream].

**Dismiss behavior:**

- Dismissing (closing without clicking a button) = **no rule saved**
- Access stays blocked for this attempt
- A **60-second cooldown** prevents notification spam (the monitoring loop runs
  every 500ms, so without cooldown, a dismissed prompt would reappear instantly)
- After cooldown expires, the next attempt prompts again

### Protected Device Categories

| Category | What it protects | How detected |
|----------|-----------------|--------------|
| Microphone | Audio capture sources | PipeWire nodes with `media.class = "Audio/Source"` (excluding `.monitor` names) |
| Camera | Video capture sources | PipeWire nodes with `media.class = "Video/Source"` |
| Monitor | Playback eavesdrop | PipeWire `Audio/Sink` nodes acting as source in a link (sink → app pattern) |

**Playback is never blocked.** You hear your music/videos normally. Only apps
trying to tap the monitor source (record what you hear) are intercepted.

---

## Components

### hwprivacy-daemon

The core service. Runs as a systemd user unit or via D-Bus activation.

- Discovers protected devices from PipeWire graph
- Polls graph every 500ms for new links
- Enforces policy (allow/deny/ask)
- Manages 2-stage desktop notifications
- Exposes D-Bus API for all other components
- Persists rules to TOML config file

**Subcommands:**

```
hwprivacy-daemon              # start daemon (foreground)
hwprivacy-daemon run          # same as above
hwprivacy-daemon install      # install as systemd user service + D-Bus activation
hwprivacy-daemon uninstall    # remove service files
hwprivacy-daemon service-status  # show systemd status
```

### hwprivacy-ctl

Command-line interface for all operations.

```
hwprivacy-ctl status                          # daemon status summary
hwprivacy-ctl devices                         # list discovered devices
hwprivacy-ctl rules list                      # show all rules
hwprivacy-ctl rules set firefox mic ask_each  # set a rule
hwprivacy-ctl rules remove firefox            # remove all rules for app
hwprivacy-ctl streams                         # show active streams
hwprivacy-ctl streams --app firefox           # filter by app
hwprivacy-ctl log --last 20                   # recent events
hwprivacy-ctl block-all                       # emergency: deny everything
hwprivacy-ctl unblock-all                     # restore saved rules
```

### hwprivacy-tui

htop-like terminal interface built with ratatui. Four panels:

- **Devices**: discovered protected devices with guard status
- **Streams**: active connections with app name, PID, device, permission
- **Rules**: per-app permission matrix, editable with keyboard shortcuts
- **Events**: real-time log of access attempts and decisions

Keyboard: `Tab` switch panels, `↑↓` navigate, `a` allow, `d` deny,
`e` ask_each, `w` while_in_use, `x` delete rule, `r` refresh, `q` quit.

### hwprivacy-gui

GTK4 graphical interface with system tray integration.

- **Tabs**: Devices, Rules, Streams, Events
- **Buttons**: Block All, Unblock All, Refresh
- **Auto-refresh**: every 2 seconds via D-Bus
- **System tray** (StatusNotifierItem via ksni):
  - Left-click: toggle window show/hide
  - Right-click menu: Show / Hide to Tray / Exit
- **Close button (X)**: hides to tray (app keeps running)
- **Ctrl+Q** or tray "Exit": actually quits
- Works on KDE Plasma and GNOME (with AppIndicator extension)

---

## Technology Choices

| Choice | What | Why |
|--------|------|-----|
| **Rust** | All components | Memory-safe, async (tokio), no GC pauses, close to hardware, single-binary deployment |
| **PipeWire CLI tools** (`pw-dump`, `pw-link`) | Graph monitoring and link management | Works with Debian's Rust 1.85 (avoids pipewire-rs C binding issues). Upgrade path to native pipewire-rs in v2 |
| **zbus v4** | D-Bus IPC | Standard Linux IPC, enables D-Bus activation. v4 chosen over v5 for Rust 1.85 MSRV compatibility |
| **TOML** | Config/rules storage | Human-readable, easy to hand-edit, standard in Rust ecosystem |
| **notify-rust v4.11** | Desktop notifications | Freedesktop notifications with action buttons. Pinned to 4.11 (last version using zbus v4) |
| **ratatui 0.28** | Terminal UI | Modern htop-like TUI framework. Pinned to 0.28 for Rust 1.85 compatibility |
| **GTK4 (gtk4-rs 0.9)** | GUI | Native look on GNOME, good KDE integration via theme. Maps to GTK 4.18 on Debian 13 |
| **ksni** | System tray | Pure Rust StatusNotifierItem implementation. Works on KDE natively, GNOME with AppIndicator extension |
| **systemd user unit** | Service management | Auto-start at login, restart on crash, standard Linux service lifecycle |
| **D-Bus activation** | Auto-start daemon | CLI/TUI/GUI can start the daemon automatically on first connection |
| **GPL-3.0-or-later** | License | Debian-compatible, copyleft |

### Dependency pinning notes

Debian 13 ships Rust 1.85.0. Several crates require newer Rust:

- `zbus` v5 requires Rust 1.87 → pinned to `zbus` v4
- `notify-rust` v4.12 pulls `zbus` v5 → pinned to `notify-rust` v4.11.3
- `ratatui` v0.29 pulls `instability` v0.3.12 (needs Rust 1.88) → pinned to `ratatui` v0.28 + `instability` v0.3.7 via `cargo update --precise`

---

## Building

### Prerequisites

```bash
sudo apt install -y rustc cargo libgtk-4-dev pkg-config libdbus-1-dev
```

### Build

```bash
cd ~/hwprivacy
cargo build --release --workspace
```

### Binaries

```
target/release/hwprivacy-daemon   # 6.9 MB
target/release/hwprivacy-ctl      # 5.0 MB
target/release/hwprivacy-tui      # 4.9 MB
target/release/hwprivacy-gui      # 4.5 MB
```

---

## Installation

### Quick install (as systemd user service)

```bash
# Build
cargo build --release --workspace

# Install service (creates systemd unit, D-Bus activation, default config)
./target/release/hwprivacy-daemon install
```

This installs:

| File | Location |
|------|----------|
| systemd service | `~/.config/systemd/user/hwprivacy.service` |
| D-Bus activation | `~/.local/share/dbus-1/services/org.hwprivacy.Daemon.service` |
| Config | `~/.config/hwprivacy/config.toml` |

The daemon starts immediately and will auto-start on every login.

### Uninstall

```bash
./target/release/hwprivacy-daemon uninstall
```

Stops and disables the service, removes service files. Config is preserved.

### Debian package (future)

Full `debian/` packaging is included for building `.deb` packages:

```bash
sudo apt install -y debhelper
dpkg-buildpackage -us -uc -b
```

Produces 4 packages: `hwprivacy-daemon`, `hwprivacy-ctl`, `hwprivacy-tui`, `hwprivacy-gui`.

---

## Usage

### Check status

```bash
hwprivacy-ctl status
```

### Set rules for common apps

```bash
# Browsers: ask for every new stream (per-tab security)
hwprivacy-ctl rules set firefox mic ask_each
hwprivacy-ctl rules set firefox cam ask_each
hwprivacy-ctl rules set "Firefox Developer Edition" mic ask_each
hwprivacy-ctl rules set chromium mic ask_each

# Messaging: allow while app is running
hwprivacy-ctl rules set telegram-desktop mic while_in_use
hwprivacy-ctl rules set telegram-desktop cam while_in_use
hwprivacy-ctl rules set signal mic while_in_use

# Trusted recording apps: always allow
hwprivacy-ctl rules set obs mic allow
hwprivacy-ctl rules set obs cam allow
hwprivacy-ctl rules set obs monitor allow

# Block everything for an app
hwprivacy-ctl rules set suspicious-app mic deny
```

### Monitor in real-time

```bash
# Terminal UI (htop-like)
hwprivacy-tui

# Or GUI with tray icon
hwprivacy-gui

# Or watch the event log
hwprivacy-ctl log --last 50
```

### Emergency

```bash
hwprivacy-ctl block-all     # instantly deny everything
hwprivacy-ctl unblock-all   # restore to saved rules
```

---

## Configuration

Config file: `~/.config/hwprivacy/config.toml`

```toml
[policy]
default_action = "ask"       # what to do for unknown apps: "ask" or "deny"
poll_interval_ms = 500       # how often to check PipeWire graph

[devices]
microphone = true            # guard microphones
camera = true                # guard cameras
monitor = true               # guard playback monitor (eavesdrop protection)

[[rules]]
app_name = "firefox"
microphone = "ask_each"
camera = "ask_each"
monitor = "deny"

[[rules]]
app_name = "telegram-desktop"
microphone = "while_in_use"
camera = "while_in_use"
monitor = "deny"

[[rules]]
app_name = "obs"
microphone = "allow"
camera = "allow"
monitor = "allow"
```

Rules are automatically saved when set via CLI, TUI, GUI, or notification actions.

---

## What Has Been Implemented

### Phase 1: Foundation (complete)

- [x] Cargo workspace with 5 crates (common, daemon, ctl, tui, gui)
- [x] Config system (TOML, user/system paths, load/save)
- [x] Device auto-discovery from PipeWire graph via `pw-dump`
- [x] PipeWire graph monitoring with link diff detection
- [x] Policy engine with 5 permission levels + per-stream gating
- [x] Link manager (destroy unauthorized links via `pw-link`/`pw-cli`)
- [x] Stream tracker (active connections, events, cooldowns)
- [x] D-Bus service with full API (methods + signals)
- [x] CLI tool with all commands (status, devices, rules, streams, log, block-all)
- [x] **Tested live**: monitor tap blocked (parecord captured 0 bytes of audio),
      Firefox playback unaffected

### Phase 2: Notifications (complete)

- [x] 2-stage notification system (instant BLOCKED + action prompt)
- [x] Notification actions: Always Allow, Ask Each Time, While in Use, Always Deny
- [x] Per-stream actions: Allow Stream, Deny Stream
- [x] Dismiss = no rule saved + 60s cooldown (prevents notification spam)
- [x] **Tested live**: notifications appear immediately when access is blocked

### Phase 3: TUI (complete)

- [x] htop-like terminal interface with ratatui
- [x] Four panels: Devices, Streams, Rules, Events
- [x] Keyboard navigation and rule editing
- [x] Real-time refresh (1s polling via D-Bus)
- [x] Color coding for permission levels

### Phase 4: GUI (complete)

- [x] GTK4 window with tabbed interface (Devices, Rules, Streams, Events)
- [x] Emergency buttons (Block All, Unblock All, Refresh)
- [x] Auto-refresh every 2 seconds
- [x] System tray icon (StatusNotifierItem via ksni)
- [x] Close to tray / show from tray / Exit
- [x] Ctrl+Q to quit
- [x] GTK warning suppression (raw GLib log writer)
- [x] Works on KDE Plasma and GNOME

### Phase 5: Packaging (complete)

- [x] `hwprivacy-daemon install/uninstall` commands
- [x] systemd user service with auto-start
- [x] D-Bus activation (daemon auto-starts on first client connection)
- [x] Full `debian/` packaging (control, rules, changelog, copyright, .service,
      .desktop, .install files)
- [x] Makefile with build/install/clean/deb targets
- [x] `--help` and `--version` on all binaries

---

## What Remains To Be Done

### Short-term improvements

- [ ] **While-in-use lifecycle tracking**: currently `while_in_use` allows the
      stream but doesn't actively revoke when the PipeWire client disconnects.
      Needs monitoring of client disconnect events to revoke permissions.
- [ ] **GUI rule editing**: the GUI displays rules but doesn't yet have inline
      editing (dropdowns to change permissions). Currently rules must be changed
      via CLI or TUI.
- [ ] **GUI stream actions**: allow/deny buttons on active streams in the GUI
      streams tab.
- [ ] **TUI streams panel actions**: allow/deny on individual streams from TUI.
- [ ] **Device guard toggling**: TUI/GUI can display guard status but don't yet
      toggle it (enable/disable guarding per device category).
- [ ] **Per-device rules**: different rules for built-in mic vs USB mic
      (currently rules apply per device *category*, not per individual device).

### Medium-term features

- [ ] **WirePlumber Lua policy hook** (v2): Zero-latency link interception by
      hooking into WirePlumber's linking policy. Blocks links BEFORE they are
      created, eliminating the ~500ms race window. Architecture already supports
      this — the policy engine is decoupled from the monitoring approach.
- [ ] **pipewire-rs native bindings** (v2): Replace `pw-dump`/`pw-link` subprocess
      calls with direct PipeWire library integration for better performance and
      event-driven (not polling) monitoring.
- [ ] **Process path identity**: Match apps by executable path (`/usr/bin/firefox`)
      in addition to PipeWire client name, for stronger identification.
- [ ] **XDG Portal integration**: Coordinate with the Flatpak/portal permission
      system so sandboxed and native apps have a unified permission experience.
- [ ] **Profiles**: "Meeting mode" (allow Zoom/Teams), "Privacy mode" (deny all),
      "Recording mode" (allow OBS everything). Quick-switch via tray menu.
- [ ] **System tray status indicator**: Show mic/camera icons in tray when actively
      in use (like Android's green dot).
- [ ] **Persistent audit log**: Write access events to a log file for later review,
      not just the in-memory 500-event ring buffer.
- [ ] **Automatic rule suggestions**: After N blocked attempts from the same app,
      suggest setting a permanent rule.

### Packaging

- [ ] **Test .deb build**: Run `dpkg-buildpackage` end-to-end, test install/uninstall
      cycle on clean Debian 13.
- [ ] **Post-install scripts**: Automatically enable systemd service after
      `apt install hwprivacy-daemon`.
- [ ] **Man pages**: Write man pages for all four binaries.
- [ ] **Upstream submission**: Prepare for Debian ITP (Intent To Package).

---

## Known Limitations

1. **~500ms race window**: Between a link being created and the daemon destroying it,
   there is a brief window where audio could flow. In practice this means a few
   hundred milliseconds of audio might be captured before being cut. This is
   acceptable for v1. The v2 WirePlumber hook approach eliminates this entirely.

2. **PipeWire node names as identity**: Apps are identified by their PipeWire
   `application.name` property. A malicious app could spoof this name. Process
   path identity (v2 feature) would mitigate this.

3. **No browser tab URL visibility**: PipeWire cannot see which website triggered
   a mic/camera request inside a browser. The `ask_each` mode mitigates this by
   prompting for every new stream, but the user cannot see "site xyz.com wants mic"
   — only "Firefox wants mic (new stream)".

4. **Debian Rust 1.85 constraints**: Several crate versions are pinned to older
   releases for MSRV compatibility. This will resolve as Debian ships newer Rust.

5. **GTK4 on KDE**: GTK4 apps work on KDE but use GTK theming, not native Qt/KDE
   look. For a fully native KDE experience, a Qt frontend would be needed.

---

## Project Structure

```
hwprivacy/
├── Cargo.toml                          # workspace root
├── Cargo.lock
├── PLAN.md                             # detailed design document
├── README.md                           # this file
├── LICENSE                             # GPL-3.0-or-later
├── Makefile
│
├── hwprivacy-common/                   # shared types + D-Bus interface
│   └── src/
│       ├── lib.rs
│       ├── config.rs                   # Config, AppRule, Permission types + TOML
│       ├── device.rs                   # DeviceCategory, ProtectedDevice
│       ├── stream.rs                   # StreamInfo, ActiveConnection, AccessEvent
│       └── dbus_interface.rs           # D-Bus proxy trait (zbus)
│
├── hwprivacy-daemon/                   # core daemon
│   └── src/
│       ├── main.rs                     # entry point, CLI, monitoring loop, service install
│       ├── device_discovery.rs         # pw-dump JSON → ProtectedDevice list
│       ├── pipewire_monitor.rs         # graph snapshot, link diff detection
│       ├── policy_engine.rs            # rule matching, link classification, decisions
│       ├── link_manager.rs             # pw-link/pw-cli link destruction
│       ├── stream_tracker.rs           # active connections, events, cooldowns
│       ├── notification.rs             # 2-stage freedesktop notifications
│       ├── dbus_service.rs             # D-Bus server (zbus interface impl)
│       └── state.rs                    # DaemonState (config + devices + tracker)
│
├── hwprivacy-ctl/                      # CLI tool
│   └── src/main.rs
│
├── hwprivacy-tui/                      # terminal UI
│   └── src/
│       ├── main.rs
│       ├── app.rs                      # ratatui app loop + D-Bus
│       ├── ui.rs                       # 4-panel layout + rendering
│       └── input.rs                    # keyboard handling
│
├── hwprivacy-gui/                      # GTK4 GUI
│   └── src/
│       ├── main.rs                     # GTK app + tray command loop + log filter
│       ├── window.rs                   # main window, tabs, D-Bus worker
│       └── tray.rs                     # StatusNotifierItem (ksni) tray icon
│
├── dbus/
│   └── org.hwprivacy.Daemon.service    # D-Bus activation file
│
└── debian/                             # Debian packaging
    ├── control                         # 4 binary packages
    ├── rules                           # build rules (cargo)
    ├── changelog
    ├── copyright                       # GPL-3
    ├── compat                          # debhelper 13
    ├── hwprivacy-daemon.service        # systemd user unit
    ├── hwprivacy-gui.desktop           # .desktop entry
    ├── hwprivacy-daemon.install
    ├── hwprivacy-ctl.install
    ├── hwprivacy-tui.install
    └── hwprivacy-gui.install
```

---

## D-Bus API Reference

Service: `org.hwprivacy.Daemon`
Path: `/org/hwprivacy/Daemon`

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `GetDevices()` | `Array<(String, String, String, Bool)>` | (category, node_name, description, guarded) |
| `GetRules()` | `Array<(String, String, String)>` | (app_name, device, permission) |
| `SetRule(app, device, permission)` | `Bool` | Set/update a rule |
| `RemoveRule(app)` | `Bool` | Remove all rules for an app |
| `GetActiveStreams()` | `Array<(String, u32, String, String, String, String, Bool)>` | (app, pid, device, node, media, perm, active) |
| `GetStatus()` | `(Bool, u32, u32, u32, u32)` | (running, devices, rules, blocked, streams) |
| `GetEvents(last_n)` | `Array<(String, String, String, String)>` | (timestamp, app, device, action) |
| `BlockAll()` | `Bool` | Emergency deny-all |
| `UnblockAll()` | `Bool` | Restore saved rules |
| `AllowStream(serial)` | `Bool` | One-shot allow pending stream |
| `DenyStream(serial)` | `Bool` | One-shot deny pending stream |

### Signals

| Signal | Args | When |
|--------|------|------|
| `AccessAttempt` | (app, pid, device, node, action) | New access attempt processed |
| `RuleChanged` | (app, device, permission) | Rule created/updated/removed |
| `StreamEvent` | (app, device, serial, event_type) | Stream connected/disconnected |

---

## Testing Summary

Tests performed on Lenovo Legion Slim 5 16IRH8, Debian 13, KDE Plasma,
PipeWire 1.4.2, ALC257 codec (2 internal mics as stereo), Integrated Camera.

| Test | Result |
|------|--------|
| Device discovery (mic, camera, monitor sinks) | 4 devices found correctly |
| Rule CRUD via CLI | Create, read, update, delete all working |
| Config persistence to TOML | Survives daemon restart |
| Firefox video playback (normal) | Not intercepted, plays normally |
| Monitor tap via `parecord` | **Blocked**: 0 bytes audio captured (44-byte empty WAV) |
| Firefox playback during monitor block | Unaffected, kept playing |
| Instant BLOCKED notification | Appears immediately on access attempt |
| Action notification with buttons | Shows Allow/Deny/AskEach/WhileInUse options |
| Notification dismiss → cooldown | No spam for 60s, then re-prompts |
| systemd service install | Enabled, running, survives reboot |
| D-Bus activation | Daemon auto-starts on first CLI/TUI/GUI connection |
| GUI tray icon | Shows in KDE system tray, left-click toggles window |
| GUI close to tray | X hides window, tray "Exit" actually quits |

---

## Credits

Developed by Perieteanu Costin in collaboration with Claude (Anthropic's Claude Code).

---

## License

GPL-3.0-or-later

Copyright 2026 perieteanu
