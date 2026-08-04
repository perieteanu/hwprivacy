# HWPrivacy — Hardware Permission Manager for Linux

## What is this?

An Android-style hardware permission manager for the Linux desktop.
Apps must be granted explicit permission to access microphones, cameras,
playback monitors, and any other PipeWire-managed device.

**Default policy: DENY ALL.** Nothing gets access unless the user says so.

---

## Core Concept

Every audio/video device on a modern Linux desktop flows through PipeWire.
PipeWire represents everything as a graph: device nodes (mic, camera, speakers)
and app nodes (Firefox, Telegram, Zoom) connected by links.

HWPrivacy monitors this graph in real-time. When an app tries to connect
to a protected device, HWPrivacy intercepts the link and enforces policy.

### Permission Levels

- **ALLOW** — all streams from this app are auto-allowed (trusted app)
- **ASK_EACH** — each new stream triggers a prompt (ideal for browsers)
- **WHILE_IN_USE** — access granted while the app's PipeWire client is active
  (revoked when app disconnects)
- **ASK** — prompt once, remember for session
- **DENY** — always blocked (default for unknown apps)

---

## The Browser Problem (and solution)

Browsers are mini operating systems. One "Firefox" PipeWire client can have
dozens of tabs, each potentially wanting mic/camera access. At the PipeWire
level, client name alone cannot distinguish tabs.

**However**: each tab that touches audio creates a **separate PipeWire node**
with a unique `object.serial`, `node.name`, and sometimes `media.name`.
This means we CAN gate access per-stream, not just per-app.

### Two-layer permission model

**Layer 1 — App baseline rule**
"Firefox may use the mic" — the Android-style per-app permission.

**Layer 2 — Per-stream gating**
Even with app-level permission, every NEW capture/record node from that
app is checked individually:

- `"allow"` → all streams auto-allowed (trusted apps like Telegram)
- `"ask_each"` → every new stream triggers notification (browsers, untrusted)
- `"deny"` → no streams ever

For browsers, `ask_each` is the recommended default. Each time a new tab
calls getUserMedia(), the user gets prompted. Shady JS in a background tab
gets caught.

### What we CAN see per stream (PipeWire node properties)

| Property | What it tells us |
|----------|-----------------|
| `application.name` | App name ("Firefox", "Chromium") |
| `application.process.id` | PID — Chromium uses separate PIDs per tab |
| `node.name` | Unique stream identifier |
| `media.name` | Sometimes stream purpose / media title |
| `media.class` | "Audio/Source", "Video/Source", "Stream/Input/Audio" |
| `object.serial` | Unique PipeWire object ID |

### What we CANNOT see

- Tab URL / website name (browser-internal, not exposed to PipeWire)
- Which JS triggered the request

### Protection against browser-internal capture

A tab CANNOT listen to another tab's audio without going through PipeWire:
- `getUserMedia()` → creates a capture node → **we intercept it**
- `getDisplayMedia()` → goes through xdg-desktop-portal → if it reaches
  PipeWire → **we intercept it**

Both paths create new PipeWire nodes that HWPrivacy catches.

---

## What Gets Protected

The daemon auto-discovers all devices from the PipeWire graph:

| Category | What it protects | Example devices |
|----------|-----------------|-----------------|
| Microphone | Audio capture sources | Built-in mic (L+R), USB mics, headset mic |
| Camera | Video capture sources | Integrated webcam, USB cameras |
| Monitor | Playback monitor taps | Apps trying to record what you hear |
| (Future) | Screen capture, MIDI, etc. | Extensible by category |

**Playback itself is NOT blocked** — you hear your music/videos normally.
Only apps trying to TAP the monitor source (eavesdrop on playback) are blocked.

---

## Permission Flow

```
New PipeWire link detected (app node → protected device node)
        │
        ▼
Identify: app_name, PID, node properties, device category
        │
        ▼
Check rules database for this app + device category
        │
        ├─── Rule: ALLOW ──────────► Link stays, log access
        │
        ├─── Rule: DENY ──────────► Link destroyed immediately, log
        │
        ├─── Rule: ASK_EACH ──────► Link destroyed + notification:
        │                            "Firefox (new stream) wants Microphone"
        │                            [Allow Stream] [Deny Stream]
        │                            (does NOT save permanent rule)
        │
        ├─── Rule: WHILE_IN_USE ──► Link stays, track client lifecycle,
        │                            revoke when client disconnects
        │
        ├─── Rule: ASK ───────────► Link destroyed + notification:
        │                            "Unknown App wants Microphone"
        │                            [Always Allow] [Ask Each] [While in Use] [Deny]
        │                            (saves permanent rule)
        │
        └─── No rule ─────────────► Same as ASK (default for unknown apps)
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    PipeWire Graph                             │
│  (mic nodes, camera nodes, app nodes, links between them)    │
│  Each stream = separate node with unique properties           │
└──────────────┬───────────────────────────────────────────────┘
               │ monitors graph via pw-dump JSON + polling
               ▼
┌──────────────────────────────────────────────────────────────┐
│                  hwprivacy-daemon (Rust)                      │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │ PipeWire    │  │ Policy       │  │ Notification       │  │
│  │ Monitor     │  │ Engine       │  │ Manager            │  │
│  │             │  │              │  │                    │  │
│  │ - graph     │  │ - rules db   │  │ - freedesktop      │  │
│  │   polling   │──│ - per-app    │──│   notifications    │  │
│  │ - new link  │  │ - per-stream │  │ - action callbacks │  │
│  │   detection │  │ - per-device │  │ - Allow/Deny/      │  │
│  │ - link      │  │ - node prop  │  │   AskEach/Use      │  │
│  │   destroy   │  │   matching   │  │                    │  │
│  └─────────────┘  └──────────────┘  └────────────────────┘  │
│                                                              │
│  ┌──────────────────┐  ┌───────────────────────────────────┐ │
│  │ Device Discovery  │  │ D-Bus Interface                   │ │
│  │                   │  │ (org.hwprivacy.Daemon)            │ │
│  │ - mic sources     │  │                                   │ │
│  │ - camera sources  │  │ Methods: GetDevices, GetRules,    │ │
│  │ - monitor sources │  │   SetRule, GetActiveConnections,  │ │
│  │ - hotplug detect  │  │   GetStreamInfo, BlockAll         │ │
│  │                   │  │ Signals: AccessAttempt,           │ │
│  │                   │  │   RuleChanged, StreamEvent        │ │
│  └──────────────────┘  └───────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
        │ D-Bus            │ D-Bus          │ D-Bus       │ D-Bus
        ▼                  ▼                ▼             ▼
┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐
│ hwprivacy-tui│  │ hwprivacy-gui│  │hwprivacy-  │  │ Desktop  │
│              │  │              │  │    ctl      │  │ Notific. │
│ htop-like    │  │ GTK4 window  │  │             │  │          │
│ terminal UI  │  │ (GNOME+KDE)  │  │ CLI tool    │  │ Allow/   │
│ real-time    │  │ permission   │  │ one-shot    │  │ Deny     │
│ navigation   │  │ matrix       │  │ commands    │  │ prompts  │
│ stream view  │  │ stream view  │  │             │  │          │
└──────────────┘  └──────────────┘  └────────────┘  └──────────┘
```

---

## Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Daemon core | Rust + tokio | Async, fast, memory-safe, close to hardware |
| PipeWire interaction | `pw-dump`, `pw-link`, `pw-cli` (subprocess) | Works with Debian Rust 1.85, no C binding issues. Upgrade to pipewire-rs in v2 |
| Policy storage | TOML config file | Human-readable, easy to edit manually |
| IPC | D-Bus via `zbus` v4 | Standard Linux IPC, enables D-Bus activation |
| Notifications | `notify-rust` | Freedesktop notifications with action buttons, works on KDE + GNOME |
| TUI | `ratatui` + `crossterm` | Modern htop-like terminal UI |
| GUI | GTK4 via `gtk4-rs` | Native look on GNOME, good integration on KDE via GTK theme |
| CLI | `clap` | Standard Rust CLI framework |
| Service | systemd user unit | Auto-start at login, restart on crash |

---

## Workspace Structure

```
hwprivacy/
├── Cargo.toml                      workspace root
├── PLAN.md                         this file
├── LICENSE                         GPL-3.0-or-later
│
├── hwprivacy-common/               shared types + D-Bus interface
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── config.rs               policy config structures
│       ├── device.rs               device categories + types
│       ├── stream.rs               stream identification types
│       └── dbus_interface.rs       D-Bus proxy trait
│
├── hwprivacy-daemon/               core daemon
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                 entry point, signal handling
│       ├── pipewire_monitor.rs     PipeWire graph monitoring (pw-dump polling)
│       ├── policy_engine.rs        rule matching + enforcement (app + stream level)
│       ├── link_manager.rs         destroy/allow PipeWire links (pw-link)
│       ├── device_discovery.rs     find all protected devices
│       ├── stream_tracker.rs       track per-stream state and client lifecycle
│       ├── notification.rs         desktop notification with actions
│       ├── dbus_service.rs         D-Bus server implementation
│       └── state.rs                runtime state (active connections, pending, events)
│
├── hwprivacy-tui/                  terminal UI (htop-like)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── app.rs                  ratatui app loop + D-Bus connection
│       ├── ui.rs                   layout + rendering (4 panels)
│       └── input.rs                keyboard handling
│
├── hwprivacy-gui/                  GTK4 graphical UI
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── window.rs               main window
│       ├── devices_view.rs         device list with guard toggles
│       ├── rules_view.rs           per-app permission matrix
│       ├── streams_view.rs         active streams with node properties
│       └── events_view.rs          recent events log
│
├── hwprivacy-ctl/                  CLI tool
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
│
├── dbus/
│   ├── org.hwprivacy.Daemon.service    D-Bus activation
│   └── org.hwprivacy.Daemon.xml        introspection XML
│
└── debian/
    ├── control                     4 binary packages
    ├── rules
    ├── changelog
    ├── copyright
    ├── compat
    ├── hwprivacy-daemon.service    systemd user unit
    ├── hwprivacy-gui.desktop       desktop entry
    ├── hwprivacy-daemon.install
    ├── hwprivacy-ctl.install
    ├── hwprivacy-tui.install
    └── hwprivacy-gui.install
```

---

## Config File Format

Location: `~/.config/hwprivacy/config.toml`
(System defaults: `/etc/hwprivacy/config.toml`)

```toml
[policy]
# What to do when no rule matches an app
# "deny" = block silently (most secure)
# "ask"  = block and prompt user (recommended)
default_action = "ask"

# How often to poll PipeWire graph (milliseconds)
poll_interval_ms = 500

# Enable/disable protection per device category
[devices]
microphone = true
camera = true
monitor = true      # playback monitor tapping

# Per-app rules
# Permission values:
#   "allow"        - all streams auto-allowed (trusted app)
#   "ask_each"     - prompt for every new stream (ideal for browsers)
#   "while_in_use" - allowed while app's PipeWire client is active
#   "ask"          - prompt once per session
#   "deny"         - always blocked

[[rules]]
app_name = "firefox"
microphone = "ask_each"
camera = "ask_each"
monitor = "deny"

[[rules]]
app_name = "Firefox Developer Edition"
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

[[rules]]
app_name = "chromium"
microphone = "ask_each"
camera = "ask_each"
monitor = "deny"

[[rules]]
app_name = "signal"
microphone = "while_in_use"
camera = "while_in_use"
monitor = "deny"
```

---

## TUI Layout (htop-like, ratatui)

```
╔══ HWPrivacy v0.1.0 ═══════════════════════════════════════════════╗
║                                                                    ║
║  PROTECTED DEVICES                                                 ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │ ● Microphone  Built-in Audio Analog Stereo     [GUARDED]   │   ║
║  │ ● Camera      Integrated Camera                [GUARDED]   │   ║
║  │ ● Monitor     Built-in Audio Analog Stereo     [GUARDED]   │   ║
║  └─────────────────────────────────────────────────────────────┘   ║
║                                                                    ║
║  ACTIVE STREAMS                                                    ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  App                  Device     Stream          Status     │   ║
║  │  firefox (pid:2977)   Mic        AudioStream     ALLOWED   │   ║
║  │  telegram (pid:741892) Mic       VoiceCall       IN USE    │   ║
║  │  chromium (pid:8823)  Cam        WebRTC          PENDING   │   ║
║  └─────────────────────────────────────────────────────────────┘   ║
║                                                                    ║
║  APP RULES                                                         ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  App                  Mic        Cam        Monitor         │   ║
║  │▸ firefox              ASK_EACH   ASK_EACH   DENY           │   ║
║  │  telegram-desktop     IN USE     IN USE     DENY           │   ║
║  │  obs                  ALLOW      ALLOW      ALLOW          │   ║
║  │  chromium             ASK_EACH   ASK_EACH   DENY           │   ║
║  └─────────────────────────────────────────────────────────────┘   ║
║                                                                    ║
║  RECENT EVENTS                                                     ║
║  ┌─────────────────────────────────────────────────────────────┐   ║
║  │  15:42:01  firefox new stream → Mic → asked user            │   ║
║  │  15:42:03  firefox stream #74 → Mic → user ALLOWED          │   ║
║  │  15:41:58  unknown-app → Camera → DENIED (no rule)          │   ║
║  │  15:40:22  telegram → Mic → ALLOWED (while_in_use)          │   ║
║  └─────────────────────────────────────────────────────────────┘   ║
║                                                                    ║
╠════════════════════════════════════════════════════════════════════╣
║ Tab:panel ↑↓:nav  a:allow d:deny e:ask_each w:in_use x:del q:quit║
╚════════════════════════════════════════════════════════════════════╝
```

---

## CLI Commands

```bash
# Status
hwprivacy-ctl status                              # daemon status + device summary
hwprivacy-ctl devices                             # list all discovered devices

# Rules
hwprivacy-ctl rules list                          # show all rules
hwprivacy-ctl rules set firefox mic ask_each      # set rule
hwprivacy-ctl rules set firefox cam deny
hwprivacy-ctl rules set telegram mic while_in_use
hwprivacy-ctl rules remove firefox                # remove all rules for app

# Streams (live)
hwprivacy-ctl streams                             # show active streams with node props
hwprivacy-ctl streams --app firefox               # filter by app

# Events
hwprivacy-ctl log                                 # stream recent events (follow mode)
hwprivacy-ctl log --last 50                       # last 50 events

# Emergency
hwprivacy-ctl block-all                           # deny everything NOW
hwprivacy-ctl unblock-all                         # restore to saved rules
```

---

## D-Bus Interface

Service: `org.hwprivacy.Daemon`
Path: `/org/hwprivacy/Daemon`

### Methods
- `GetDevices() → Array<(String category, String name, Bool guarded)>`
- `GetRules() → Array<(String app, String device, String permission)>`
- `SetRule(String app, String device, String permission) → Bool`
- `RemoveRule(String app) → Bool`
- `GetActiveStreams() → Array<(String app, u32 pid, String device, String node_name, String media_name, String permission, Bool active)>`
- `GetStreamInfo(u32 object_serial) → Dict<String, String>` (all node properties)
- `GetStatus() → (Bool running, u32 guarded_devices, u32 active_rules, u32 blocked_count, u32 active_streams)`
- `GetEvents(u32 last_n) → Array<(String timestamp, String app, String device, String action)>`
- `BlockAll() → Bool`
- `UnblockAll() → Bool`
- `AllowStream(u32 object_serial) → Bool` (one-shot allow for pending stream)
- `DenyStream(u32 object_serial) → Bool` (one-shot deny for pending stream)

### Signals
- `AccessAttempt(String app, u32 pid, String device, String node_name, String action_taken)`
- `RuleChanged(String app, String device, String new_permission)`
- `StreamEvent(String app, String device, u32 object_serial, String event_type)`

---

## Debian Packaging

4 binary packages from one source:

| Package | Contains | Depends on |
|---------|----------|------------|
| `hwprivacy-daemon` | daemon binary, systemd service, D-Bus activation, default config | pipewire, wireplumber |
| `hwprivacy-ctl` | CLI tool | hwprivacy-daemon |
| `hwprivacy-tui` | terminal UI | hwprivacy-daemon |
| `hwprivacy-gui` | GTK4 app + .desktop file | hwprivacy-daemon, libgtk-4-1 |

### Post-install (hwprivacy-daemon)
- Installs systemd user service (auto-start at login)
- Installs D-Bus activation file (auto-start on first client connection)
- Installs default config to `/etc/hwprivacy/config.toml`
- User config: `~/.config/hwprivacy/config.toml` (overrides system)

---

## Implementation Phases

### Phase 1: Foundation (daemon + CLI)
1. Create project structure as `hwprivacy` workspace
2. Common crate: types (Permission, DeviceCategory, StreamInfo, AppRule),
   config parsing (TOML), D-Bus proxy trait
3. Daemon: PipeWire graph monitor via `pw-dump` JSON parsing
4. Daemon: device auto-discovery (mic sources, camera sources, monitor sources)
5. Daemon: stream tracker — identify new capture/record nodes, extract
   app_name, PID, node properties
6. Daemon: policy engine — match app+device+stream against rules,
   decide action (allow/deny/ask/ask_each)
7. Daemon: link manager — destroy unauthorized links via `pw-link -d`,
   track allowed links
8. Daemon: D-Bus service — expose all methods and signals
9. CLI: all commands working against live daemon
10. Test: Firefox mic access blocked/allowed, per-stream gating works

### Phase 2: Notifications
11. Desktop notifications with action buttons
    - For ASK: [Always Allow] [Ask Each Time] [While in Use] [Deny]
    - For ASK_EACH: [Allow This Stream] [Deny This Stream]
12. Notification callback → save rule or one-shot allow → enforce
13. "While in use" tracking — monitor PipeWire client lifecycle,
    revoke permission when client disconnects
14. Pending stream queue — hold denied streams, re-allow if user permits

### Phase 3: TUI
15. ratatui app scaffolding with D-Bus connection
16. Four panels: devices, active streams, app rules, recent events
17. Tab switching between panels, arrow key navigation
18. Keyboard shortcuts: a=allow, d=deny, e=ask_each, w=while_in_use, x=delete
19. Real-time updates via D-Bus signals
20. Color coding: green=allowed, red=denied, yellow=pending, blue=in_use

### Phase 4: GUI
21. GTK4 window with notebook/tabs or sidebar navigation
22. Devices view: discovered devices with guard on/off toggle
23. Rules view: per-app permission matrix (table with dropdowns)
24. Streams view: active streams with node properties, allow/deny buttons
25. Events view: scrolling log of recent events
26. Real-time sync via D-Bus signals

### Phase 5: Packaging
27. debian/ control, rules, changelog, copyright
28. systemd user service file
29. D-Bus activation service file
30. Default config file
31. .desktop file for GUI
32. Build and test .deb install/uninstall cycle
33. Post-install/post-remove scripts

---

## Questions Resolved

- **Name**: `hwprivacy` (Hardware Privacy)
- **Default policy**: DENY — unknown apps are blocked and user is prompted
- **Devices**: ALL PipeWire-managed devices discovered automatically (mic, cam, monitor, future)
- **Browser problem**: Solved via per-stream gating (`ask_each` permission level)
- **Playback**: NOT blocked — only monitor source tapping is blocked
- **Root/sudo**: NOT needed at runtime. Root only for `apt install`
- **KDE + GNOME**: GTK4 works on both. Notifications use freedesktop standard
- **Service**: systemd user unit + D-Bus activation
- **Persistence**: Rules saved to TOML config, survive reboot
- **Race condition**: ~500ms in v1 (acceptable), v2 adds WirePlumber hooks for zero-latency

---

## v2 Roadmap (future)

- **WirePlumber Lua policy hook**: Zero-latency link interception (block BEFORE link created)
- **pipewire-rs native bindings**: Replace subprocess calls for better performance
- **Process path identity**: Match apps by `/usr/bin/firefox` not just client name
- **XDG Portal integration**: Coordinate with Flatpak/portal permission system
- **Per-device rules**: Different rules for built-in mic vs USB mic
- **Profiles**: "Meeting mode" (allow Zoom/Teams), "Privacy mode" (deny all), etc.
- **System tray indicator**: Show active mic/camera access in panel
- **Audit log**: Persistent log of all access attempts for review
