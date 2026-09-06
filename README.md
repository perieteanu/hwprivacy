# HWPrivacy — Hardware Permission Manager for Linux

An Android-style hardware permission manager for the Linux desktop.
Applications must be granted explicit permission to access microphones, cameras,
and playback monitor sources.

Enforcement happens in **two layers**: the PipeWire graph, and an **eBPF LSM in
the kernel**. Neither is sufficient alone — see [How It Works](#how-it-works).

Built for Debian 13 (Trixie) with PipeWire/WirePlumber. Works on KDE Plasma and GNOME.

> **The default policy is `deny`.** An application with no rule is denied and
> gets a notification saying so. `ask` still exists and is opt-in per rule.
> Settled 2026-08-21 — see `docs-yaml/DECISIONS.yaml > d-deny-by-default`.
> A config written before that date may set `default_action = "ask"`
> explicitly, and is left alone; the default only applies when the key is
> absent.

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
- [Project Structure](#project-structure)
- [D-Bus API Reference](#d-bus-api-reference)
- [Testing Summary](#testing-summary)
- [Credits](#credits)
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

HWPrivacy fills this gap with two enforcement layers: the **PipeWire graph**,
which knows *which application* is asking, and an **eBPF LSM in the kernel**,
which sees an `open()` of a device node whatever the application talks to.

**Read the coverage honestly before relying on it.** The camera is enforced in
the kernel and holds against a browser using V4L2 directly. The microphone is
enforced at both layers — per application in PipeWire, and as a coarse
binary-level backstop in the kernel that closes the direct-ALSA bypass
(limitation 1 explains what that backstop can and cannot express). The playback
monitor is guarded at the PipeWire layer, which is the correct layer for it.

---

## How It Works

### The premise this project started from — and where it broke

The original design rested on: *every audio/video device on a modern Linux
desktop flows through PipeWire*. **That premise is false**, and it was never
tested until 2026-08-04, when it was measured on the live system:

```
ffmpeg -f v4l2 -i /dev/video0 -frames:v 90   → 90 frames captured, 0 events logged
ffmpeg -f alsa -i hw:0,0      -t 3           → 3s of mic audio,     0 events logged
```

Firefox and Chrome take the camera through **V4L2 directly**. No PipeWire node,
no link, nothing to observe — not "allowed", not "missed", but structurally
invisible. This is why a second, lower layer exists.

### Layer 1 — the PipeWire graph

PipeWire represents everything as a directed graph:

- **Device nodes**: microphone sources, camera sources, speaker sinks
- **Application nodes**: Firefox audio streams, Telegram voice calls, etc.
- **Links**: connections between nodes (e.g., microphone → Firefox capture)

HWPrivacy monitors this graph with `pw-dump --monitor`: one long-lived process
that streams changes, rather than a spawn twice a second. A new link is seen in
**~11 ms**, and layer 1 costs **0.033% of a core at idle** (both measured
2026-09-01; the previous polling design cost 2.70-2.82%). When a new link
appears connecting an application to a protected device, the daemon:

1. **Identifies** the application (name, PID, stream properties) and device category
4. **Checks** the rules database for a matching policy
5. **Enforces** the decision: allow the link, destroy it, or prompt the user

For **playback monitor protection**, the daemon detects a specific PipeWire pattern:
when an `Audio/Sink` node appears as the **output** side of a link to a
`Stream/Input/Audio` node, that means an application is tapping the monitor source
(recording what's playing through the speakers). Normal playback flows in the
opposite direction (`Stream/Output/Audio → Audio/Sink`) and is never blocked.

### Layer 2 — the kernel (eBPF LSM)

`hwprivacy-lsm` attaches an eBPF program to the `security_file_open` LSM hook.
Every `open()` of a video4linux (major 81) or ALSA (major 116) device node is
seen, keyed by the **inode of the calling executable** — not by a name the
application asserts about itself.

- **Camera (major 81)** is enforced under `--enforce`: an executable not on the
  allowlist gets `-EPERM` from the kernel. Unbypassable from userspace.
- **Audio (major 116)** is **observe-only** and never denied here. Denying
  major 116 outright would deny `/usr/bin/pipewire`, which is every
  application's microphone path. A proper audio backstop is future work.

Measured cost: **+13.75 ns per `open()`** (95% CI [+7.3, +20.2]), 1.88% of a
733 ns `open()`, and **0% at idle**.

### Why both layers stay

| | sees | blind to |
|---|---|---|
| **PipeWire layer** | *which app* wants the mic; the playback monitor | the camera entirely |
| **Kernel layer** | any `open()` of a camera/ALSA node, by inode | *which app* wants the mic — `/dev/snd` is held by `/usr/bin/pipewire` on everyone's behalf |

The **playback-monitor feature has no kernel equivalent** — there is no
straightforward way to tap a sink monitor below PipeWire. That is why layer 1
is not merely legacy.

> **The kernel layer runs at boot.** `hwprivacy-lsm.service` is installed and
> enabled, starts before the user daemon, and enforces from
> `/var/lib/hwprivacy/policy`. The BPF program is **never pinned**, so stopping
> the service detaches it and restores normal access — that is deliberate, and
> it is also the honest limit of the protection: anything that can stop a root
> service can turn the camera back on.

---

## Architecture

```
    Application open("/dev/video0")
                         |
                         v
    +--------------------------------------------+
    |   hwprivacy-lsm (root)  —  eBPF LSM         |
    |   security_file_open, major 81 / 116        |
    |   allowlist keyed by executable (dev, ino)  |
    |   camera: -EPERM      audio: observe only   |
    +--------------------------------------------+
                         | AccessEvent, NDJSON over
                         | /run/hwprivacy/lsm.sock (0660)
                         v
                    PipeWire Graph
                    (nodes + links)
                         |
                         | pw-dump --monitor (one long-lived process,
                         | streaming changes; a new link is seen in ~11ms)
                         v
    +--------------------------------------------+
    |          hwprivacy-daemon (Rust)            |
    |                                            |
    |  Device Discovery   Policy Engine          |
    |  (mic, cam, monitor) (rules per category)  |
    |                                            |
    |  Link Manager        Stream Tracker        |
    |  (pw-link destroy)   (active, cooldowns)   |
    |                                            |
    |  Notification Manager (2-stage)            |
    |  1. Instant BLOCKED alert (5s auto-dismiss)|
    |  2. Action prompt, stays until answered:   |
    |     Always Allow / While in Use / Deny     |
    |     (no While in Use on the camera)        |
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
| `allow` | All access from this app auto-allowed | Trusted apps (OBS, dedicated voice app) |
| `while_in_use` | A **session**: allowed from your answer until the device is released | Messaging apps (Telegram, Signal) |
| `ask` | Prompt once, save a permanent rule | Unknown apps |
| `deny` | Always blocked, notification shown | Untrusted apps |

`while_in_use` is **microphone and playback monitor only**. The camera takes
`allow` or `deny` — see [The camera has no sessions](#the-camera-has-no-sessions).

`ask_each` was removed in 2026-08. The string still parses, as `ask`, so an
older config keeps loading.

### The camera has no sessions

`camera = while_in_use` was built, worked end to end against a live kernel, and
was withdrawn the same day. A camera session ended **111 ms after it started**,
while the call was still running:

```
20:02:33.712  ALLOWED (first open)
20:02:33.823  session ended: released the camera (kernel)     [111 ms]
20:02:35.914  12 further allowed open(s)   <- the actual capture
20:02:38.317  executable removed from the allowlist, MID-CALL
```

Firefox *probes* the camera before capturing — open, close, then open the
handles it records with. The probe close takes the open count to zero, so the
release fires before capture begins. An open count is a **transient**: zero
means "no handle held right now", not "finished with the camera".

The microphone and monitor are unaffected, because PipeWire gives them a link
whose lifetime genuinely is the use. Details: `d-camera-is-allow-or-deny`.

### Browsers: one client, many tabs

Browsers are mini operating systems — one "Firefox" PipeWire client serves
dozens of tabs, and at the PipeWire level they share one client name.

**hwprivacy does not gate per tab.** Per-stream grants were removed in 2026-08
(`d-no-per-stream-grants`): the deny path destroys a link that the allow path
cannot recreate, so a grant could never actually be used. The executable is the
principal — allowing `firefox` allows every site Firefox has a grant for.

### Notification Behavior

**2-stage notifications:**

1. **Stage 1 — Instant BLOCKED** (fire-and-forget, auto-dismisses in 5s):
   Tells the user immediately that an access attempt was caught and blocked.

2. **Stage 2 — Action prompt** (persistent, waits for user response):
   Presents buttons to set a rule: [Always Allow] [While in Use] [Always Deny].
   A **camera** prompt from the kernel layer offers [Always Allow] [Always Deny]
   only, and says that the answer applies to your NEXT attempt — the open() that
   raised it was already refused, because the LSM hook must answer in
   nanoseconds.

**Dismiss behavior — DEFECT, this section describes the intent, not the code:**

The design below is what `main.rs` implements and what should happen:

- Dismissing (closing without clicking a button) = no rule saved
- Access stays blocked for this attempt
- A 60-second cooldown prevents notification spam
- After cooldown expires, the next attempt prompts again

**What actually happens:** `notification.rs` converts the dismiss into
`Some(Permission::Deny)` before it ever reaches that logic, so **dismissing a
prompt writes a permanent `deny` rule** and the cooldown path is dead code.
Months of ignored popups became policy the user never chose. Tracked as
blocker **b1** in `docs-yaml/ROADMAP.yaml`; **not yet fixed**.

Because of b1, **kernel-layer denials deliberately use an informational
notification with no buttons** — routing a new event source through the action
path would inherit this bug on day one.

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
- Watches the graph via `pw-dump --monitor` (streamed, ~11 ms to see a new link)
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

### hwprivacy-lsm

The kernel layer. **Runs as root**, as the system service
`hwprivacy-lsm.service` (enabled, started at boot, before the user daemon).

- Attaches two eBPF programs: `lsm/file_open` (the verdict) and
  `lsm/file_release` (observes a device being released)
- Matches the **executable's inode**, which an application cannot spoof
- Denies a non-allowlisted camera `open()` with `EPERM`
- Enforces from `/var/lib/hwprivacy/policy` before any user logs in, and takes
  live policy from the daemon over `/run/hwprivacy/lsm.sock` (0660,
  group `hwprivacy`)
- Audio is **observe-only** — see limitation 1

```
hwprivacy-lsm --summarize            # observe only, per-consumer table
hwprivacy-lsm --enforce              # deny non-allowlisted camera opens
hwprivacy-lsm --dump-policy          # read the policy map back OUT of the
                                     # kernel, beside what userspace intended
hwprivacy-lsm --json                 # NDJSON, one object per event
```

Measured cost: **+13.75 ns per `open()`** (95% CI `[+7.3, +20.2]`, 1.88% of a
733 ns `open()`) and **0% at idle** — the hook bills per syscall, not per second.

### hwprivacy-ctl

Command-line interface for all operations.

```
hwprivacy-ctl status                          # daemon status summary
hwprivacy-ctl devices                         # list discovered devices
hwprivacy-ctl rules list                      # show all rules
hwprivacy-ctl rules set firefox mic while_in_use   # set a rule
hwprivacy-ctl rules allow-camera <path> --as <rule>  # camera needs the BINARY
hwprivacy-ctl rules denied-cameras            # what the kernel has denied,
                                              # with the path to allow
hwprivacy-ctl rules remove firefox            # remove all rules for app
hwprivacy-ctl streams                         # show active streams
hwprivacy-ctl streams --app firefox           # filter by app
hwprivacy-ctl log --last 20                   # recent events (in-memory ring)
hwprivacy-ctl history                         # survives restarts
hwprivacy-ctl preset list                     # importable rule sets
hwprivacy-ctl preset import <name> --apply    # preview is the default
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
`w` while_in_use, `x` delete rule, `r` refresh, `q` quit.

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
| **PipeWire CLI tools** (`pw-dump --monitor`, `pw-link`) | Graph monitoring and link management | `--monitor` streams changes from one long-lived process. Its wire format is already the shape the daemon wants — block 0 is a full snapshot, later blocks carry only changes, a removal is the object with `"info": null` — so the existing parsers are reused unchanged. **Not** an MSRV workaround: `librust-pipewire-dev 0.8.0-7` *is* in Debian 13, and that objection (recorded for months) was obsolete |
| **eBPF LSM** (`libbpf-rs` 0.27, C programs via clang) | Kernel enforcement | The only layer that sees an application taking the camera through V4L2 directly, which is how Firefox and Chrome do it. Costs +13.75 ns per `open()` and nothing at idle |
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
# userspace
sudo apt install -y rustc cargo libgtk-4-dev pkg-config libdbus-1-dev

# the kernel layer additionally needs the eBPF toolchain
sudo apt install -y clang libbpf-dev bpftool
```

`hwprivacy-lsm` is a workspace member, so **`cargo build --workspace` fails
without the eBPF toolchain** — including for the daemon. It also needs a
generated `src/bpf/vmlinux.h`; `build.rs` says so explicitly if it is missing.

Runtime requirements for the kernel layer: a kernel with BPF LSM enabled
(`CONFIG_BPF_LSM=y` and `bpf` present in `/sys/kernel/security/lsm`) and root
to attach. Developed against Debian 13's 6.12 kernel.

### Build

```bash
cd hwprivacy
cargo build --release --workspace     # or: make build
```

### Binaries

Five, sizes as built on Debian 13 (2026-09-06):

```
target/release/hwprivacy-daemon   # 8.8 MB   layer 1 enforcer + policy owner
target/release/hwprivacy-lsm      # 2.3 MB   layer 2, runs as root
target/release/hwprivacy-ctl      # 5.5 MB   CLI
target/release/hwprivacy-tui      # 5.6 MB   ratatui TUI
target/release/hwprivacy-gui      # 6.2 MB   GTK4 + tray
```

The three frontends are pure D-Bus viewers with no authority of their own.

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

**This installs layer 1 only.** The camera is not protected against a V4L2
application until the kernel helper is installed too — see below.

### The kernel layer (layer 2)

Deliberately a separate, opt-in step: `hwprivacy-lsm` runs as **root** and
denies the camera by default, so pulling it in silently would change the
machine's behaviour in a way nobody asked for. It is also the only component
with a kernel requirement (`CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`, and
`bpf` present in `/sys/kernel/security/lsm`).

```bash
sudo make install-lsm
```

Then the steps it cannot do for you:

```bash
sudo addgroup --system hwprivacy
sudo adduser $USER hwprivacy          # to push policy to the kernel
sudo adduser $USER systemd-journal    # to READ the audit trail
sudo install -d -m 0755 /var/lib/hwprivacy
sudo systemctl daemon-reload && sudo systemctl enable --now hwprivacy-lsm
```

Log out and back in for the group changes to take effect. Stopping the service
restores camera access immediately — the BPF program is never pinned.

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

Produces 5 packages: `hwprivacy-daemon`, `hwprivacy-lsm`, `hwprivacy-ctl`,
`hwprivacy-tui`, `hwprivacy-gui`.

**Never exercised.** `dpkg-buildpackage` has never been run against this tree
and no `.deb` has ever been produced, so treat this as untested. The `control`
descriptions are also boilerplate that never mention PipeWire.

---

## Usage

### Check status

```bash
hwprivacy-ctl status
```

### Set rules for common apps

```bash
# Browsers. Note the executable is the principal: this grants every site
# that ever obtains a grant inside Firefox, not one tab.
hwprivacy-ctl rules set firefox mic while_in_use
# The camera needs the BINARY, because the kernel matches by inode:
hwprivacy-ctl rules allow-camera /usr/lib/firefox-esr/firefox-esr --as firefox
# Find the path for anything the kernel has denied:
hwprivacy-ctl rules denied-cameras

# Messaging: allow while app is running
hwprivacy-ctl rules set telegram-desktop mic while_in_use
# The camera takes allow or deny only — `cam while_in_use` is REFUSED.
hwprivacy-ctl rules allow-camera /usr/bin/telegram-desktop --as telegram-desktop
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

# What has touched a device over DAYS — this one survives restarts,
# unlike the 500-entry in-memory event ring that `log` reads:
hwprivacy-ctl history

# Importable rule sets. Preview is the default, because a preset is a grant:
hwprivacy-ctl preset list
hwprivacy-ctl preset import desktop-baseline --apply
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
default_action = "deny"          # unknown apps: "deny" (default) or "ask"
                                 # (poll_interval_ms was retired on 2026-09-02:
                                 #  the graph is streamed, not polled. An old
                                 #  config still loads; the key is ignored and
                                 #  dropped on the next rule write.)
dismiss_cooldown_secs = 60       # after a dismissed prompt, before asking again
while_in_use_settle_secs = 10    # a released device stays granted this long,
                                 # covering the gap while an app reconnects
exe_recheck_secs = 30            # re-resolve allowlisted binaries (catches a
                                 # package upgrade changing an inode)
awaiting_open_secs = 60          # a granted session that is never opened
                                 # expires after this
notify_on_allow = true           # announce ALLOWED access, not only denials
notify_allow_grace_secs = 60     # stay quiet for this long after startup
notify_allow_cooldown_secs = 300 # per (app, device), between allow notices

[devices]
microphone = true                # guard microphones
camera = true                    # guard cameras
monitor = true                   # guard playback monitor (eavesdrop protection)

# The audio/video servers. Without these the camera has no PipeWire node at
# all — import them with: hwprivacy-ctl preset import desktop-baseline --apply
[[rules]]
app_name = "pipewire"
camera = "allow"
exe_path = "/usr/bin/pipewire"

[[rules]]
app_name = "wireplumber"
camera = "allow"
exe_path = "/usr/bin/wireplumber"

# exe_path is what the KERNEL layer matches, by inode. Without it a camera
# rule does nothing for an app that uses V4L2 directly — which is how Firefox
# and Chrome take the camera.
[[rules]]
app_name = "firefox"
microphone = "while_in_use"
camera = "allow"
exe_path = "/usr/lib/firefox-esr/firefox-esr"

[[rules]]
app_name = "obs"
microphone = "allow"
monitor = "allow"
```

A category the rule says nothing about is **unset**, not denied: it falls
through to `default_action` and prints as `—`. Setting one category writes one
category.

Rules are saved automatically when set via CLI, TUI, GUI, or a notification
action. **The daemon rewrites the whole file on any rule change**, so comments
and hand-formatting are lost — stop the daemon before editing by hand.

---

## What Has Been Implemented

These five phases are **layer 1** (the PipeWire graph). The kernel layer has
its own phase numbering, described under *Layer 2* above — "Phase 5" here is
packaging; "Phase 5" there is the ALSA backstop, which has **not** started.

### Phase 1: Foundation (complete)

- [x] Cargo workspace with 7 crates (common, proto, daemon, lsm, ctl, tui, gui)
- [x] Config system (TOML, user/system paths, load/save)
- [x] Device auto-discovery from PipeWire graph via `pw-dump`
- [x] PipeWire graph monitoring with link diff detection
- [x] Policy engine, rules per category (microphone / camera / monitor)
- [x] Link manager (destroy unauthorized links via `pw-link`/`pw-cli`)
- [x] Stream tracker (active connections, events, cooldowns)
- [x] D-Bus service with full API (methods + signals)
- [x] CLI tool with all commands (status, devices, rules, streams, log, block-all)
- [x] **Tested live**: monitor tap blocked (parecord captured 0 bytes of audio),
      Firefox playback unaffected

### Phase 2: Notifications (complete)

- [x] 2-stage notification system (instant BLOCKED + action prompt)
- [x] Notification actions: Always Allow, While in Use, Always Deny.
      `Ask Each Time` was removed on 2026-08-23 — the per-stream grant behind
      it could never take effect. The camera offers no *While in Use*.
- [x] Dismiss = no rule saved + a cooldown (`policy.dismiss_cooldown_secs`).
      The prompt itself **stays until answered** — a permission question is a
      to-do item, not a nag.
- [x] An allowed access notifies too, not only a blocked one (`notify_allow`)
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
- [ ] **Never exercised**: `make install` has never been run and no `.deb` has
      ever been built. The `debian/` tree is complete but untested, and its
      control descriptions are boilerplate that never mention PipeWire.

---

## What Remains To Be Done

### Short-term improvements

- [x] **While-in-use lifecycle tracking** — done 2026-08-23. `while_in_use` is
      a SESSION: no session means ask, answering opens it, and the session ends
      when the device is released. Keyed on (app, device). **Microphone and
      playback monitor only** — the camera takes `allow` or `deny`, because a
      camera session ended itself 111 ms in on a browser's probe close
      (`d-camera-is-allow-or-deny`).
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
      created, closing the remaining race window entirely. Architecture already
      supports this — the policy engine is decoupled from the monitoring
      approach.
- [ ] **pipewire-rs native bindings** (v2): replace the `pw-dump`/`pw-link`
      subprocesses with the library. Note this is **no longer about CPU or
      polling** — `pw-dump --monitor` already removed both. What remains is
      registry enumeration on connect, which would also close limitation 6
      (links that already exist at daemon start).
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

1. **The microphone backstop is coarse: it gates binaries, not applications.**
   Direct ALSA capture used to bypass hwprivacy completely — measured
   2026-08-04, `ffmpeg -f alsa -i hw:0,0 -t 3` captured three seconds of real
   audio with zero events logged. Since 2026-09-06 the kernel denies it:
   a non-allowlisted `open()` of `/dev/snd/pcmC*D*c` returns **EPERM**,
   verified live.

   What remains limited is *what it can express*. `/dev/snd` is opened by the
   audio server on every application's behalf, so the kernel sees
   `/usr/bin/pipewire`, never the app behind it. The backstop therefore answers
   only "may this binary take the microphone without going through PipeWire" —
   in practice, the audio stack and anything that genuinely bypasses it.
   **Per-application microphone policy exists only in layer 1**, and an
   application that routes through PipeWire is gated there, by name, exactly as
   before.

   It gates on the capture **minor**, never on ALSA's major number: denying
   major 116 would deny `/usr/bin/pipewire` and stop every application's
   microphone. Playback, control, sequencer and timer nodes are never touched.

   **Enabling it requires allowlisting your audio server**, or the first thing
   denied is the server itself:

   ```bash
   hwprivacy-ctl preset import audio-backstop --apply
   ```

   hwprivacy refuses to enforce until it sees a recognised audio server in that
   allowlist, and logs the reason — see limitation 2.

2. **The audio backstop only recognises a PipeWire stack.** Before enforcing,
   hwprivacy checks that an audio server is actually in the capture allowlist —
   a safety interlock, because enforcing without one denies every microphone on
   the machine at once. That check recognises exactly three names: `pipewire`,
   `wireplumber` and `pipewire-pulse`.

   On a machine running JACK, PulseAudio, or bare ALSA with no server, adding
   your own server to the allowlist is **not** enough: the interlock still
   refuses and the backstop stays off. The failure is safe and it is logged,
   but it is a real limitation, not a misconfiguration. Widening it is a
   one-line change in `audio_backstop_blocker()`
   (`hwprivacy-common/src/config.rs`), deliberately left undone until it can be
   measured against a real non-PipeWire stack — guessing which binaries look
   like an audio server is the kind of fuzzy matching this project has already
   been bitten by.

3. **~11 ms race window**: between a link being created and the daemon
   destroying it, there is a brief window where audio could flow. Measured at
   ~11 ms since the graph became a stream (2026-09-01); it was 0-500 ms under
   the old polling design. It is not zero, and only the v2 WirePlumber hook —
   which blocks links before they are created — eliminates it entirely.

4. **Two identities, and only one is spoof-proof.** At the PipeWire layer an
   app is its self-declared `application.name`, which any app can lie about. At
   the kernel layer it is the executable's inode, which it cannot. A rule
   carries both: `app_name` for layer 1, `exe_path` for layer 2. A camera rule
   with no `exe_path` grants nothing to a V4L2 application, whatever name you
   typed.

5. **The executable is the principal.** Allowing `firefox` allows every website
   that has ever obtained a grant inside Firefox. hwprivacy cannot see which
   site asked, and does not gate per tab — per-stream grants were removed in
   2026-08 because the deny path destroys a link the allow path cannot recreate
   (`d-no-per-stream-grants`).

6. **Debian Rust 1.85 constraints**: Several crate versions are pinned to older
   releases for MSRV compatibility. This will resolve as Debian ships newer Rust.

7. **GTK4 on KDE**: GTK4 apps work on KDE but use GTK theming, not native Qt/KDE
   look. For a fully native KDE experience, a Qt frontend would be needed.

8. **Kernel enforcement cannot revoke an already-open fd.** The LSM hook fires
   on `open()`, not on `read()`. An application that opened the camera *before*
   a deny rule took effect keeps its descriptor and keeps receiving video. This
   was observed live. Closing it would mean hooking `security_file_permission`
   (intercepting every read) or revoking on policy change — a design step, not
   a patch.

9. **Links that already exist when the daemon starts are never evaluated.**
   They are seeded into `known_link_ids` and grandfathered in. Starting the
   daemon does not stop an in-progress capture.

10. **`BlockAll()` does not stop anything already recording.** It blocks *new*
   links. An active stream survives it.

11. **The BPF program is never pinned.** `hwprivacy-lsm` *is* a boot-time
   systemd service (`hwprivacy-lsm.service`, enabled, started before the user
   daemon, enforcing from `/var/lib/hwprivacy/policy`), so the kernel layer is
   active at rest. But the program is not pinned to `/sys/fs/bpf`, so stopping
   the service detaches it and restores normal access.

12. **A process running as your user can just stop the daemon.** `systemctl
    --user stop hwprivacy` needs no privileges you do not already have. The
    honest framing is "prevents accidental capture and gives visibility", not
    "enforces permissions against an adversary".

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
│       ├── preset.rs                   # importable rule sets (data, not code)
│       └── dbus_interface.rs           # D-Bus proxy trait (zbus)
│
├── hwprivacy-proto/                    # wire protocol: root helper <-> user daemon
│   └── src/lib.rs                      # NDJSON, serde ONLY (no D-Bus stack in root)
│
├── hwprivacy-lsm/                      # LAYER 2 — the root helper (eBPF LSM)
│   ├── build.rs
│   └── src/
│       ├── main.rs                     # CLI, BPF load/attach, event loop, coalescing
│       ├── device_index.rs             # (major,minor) -> name; glibc_to_kernel_dev()
│       ├── policy.rs                   # in-kernel allowlist, keyed by exe (dev, ino)
│       ├── socket.rs                   # unix socket — the helper's ONLY interface
│       ├── event.rs                    # AccessEvent, coalescing, burst accounting
│       └── bpf/
│           ├── devices.bpf.c           # the LSM program on security_file_open
│           └── vmlinux.h               # generated from /sys/kernel/btf/vmlinux
│
├── hwprivacy-daemon/                   # LAYER 1 — core daemon + layer 2 client
│   └── src/
│       ├── main.rs                     # entry point, CLI, monitoring loop, service install
│       ├── device_discovery.rs         # pw-dump JSON → ProtectedDevice list
│       ├── pipewire_monitor.rs         # graph snapshot, link diff detection
│       ├── policy_engine.rs            # rule matching, link classification, decisions
│       ├── link_manager.rs             # pw-link/pw-cli link destruction
│       ├── stream_tracker.rs           # active connections, events, cooldowns
│       ├── notification.rs             # freedesktop notifications (2-stage + kernel)
│       ├── dbus_service.rs             # D-Bus server (zbus interface impl)
│       ├── lsm_client.rs               # connects to hwprivacy-lsm, pushes policy
│       ├── pipewire_monitor.rs         # `pw-dump --monitor` supervisor + graph state
│       ├── notify_allow.rs             # gate for announcing ALLOWED access
│       ├── history.rs                  # persistent per-identity counters
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

Verified against `hwprivacy-daemon/src/dbus_service.rs` on 2026-09-06.

| Method | Returns | Description |
|--------|---------|-------------|
| `GetDevices()` | `Array<(s, s, s, b)>` | (category, node_name, description, guarded) |
| `GetRules()` | `Array<(s, s, s, s, s, s)>` | (app_name, microphone, camera, monitor, exe_path, gap) — one row per app, not per rule. An unset category is the empty string, which is **not** the same as `deny`: it falls through to `default_action`. |
| `SetRule(app, device, permission)` | `b` | Set one category. Returns `false` if the name cannot become a key. |
| `SetRuleExe(app, exe_path)` | `(b, s)` | Set the executable the kernel matches by inode. Returns (ok, message). |
| `AllowCamera(app, exe_path)` | `(b, s)` | Atomic camera grant: writes the rule and the exe together, rolls back on a bad path. |
| `RemoveRule(app)` | `b` | Remove all categories for an app |
| `GetActiveStreams()` | `Array<(s, u32, s, s, s, s, b)>` | (app, pid, device, node, media, perm, active) |
| `GetStatus()` | `(b, u32, u32, u32, u32)` | (running, devices, rules, blocked, streams) |
| `GetKernelStatus()` | `(b, b, u32, u32, s)` | (connected, enforcing_camera, allowed_exes, unresolved, last_error) |
| `GetSessions()` | `Array<(s, s, u32)>` | Live `while_in_use` sessions: (app, device, age_secs) |
| `GetEvents(last_n)` | `Array<(s, s, s, s)>` | (timestamp, app, device, action) — a 500-entry in-memory ring, lost on restart |
| `GetHistory()` | `Array<(s, s, s, u32, u32, s, s)>` | (identity, device, source, denied, allowed, first_seen, last_seen) — **survives restarts**, unlike `GetEvents` |
| `GetPresets()` | `Array<(s, s, u32, s)>` | (name, description, entry_count, source_path) |
| `ImportPreset(name, apply)` | `Array<(s, s, b)>` | (entry, outcome, changed). `apply = false` previews and writes nothing — a preset is a grant, so the safe outcome is the one you get by forgetting the flag. |
| `BlockAll()` | `b` | Emergency deny-all. **Gates new access only** — see Known Limitations. |
| `UnblockAll()` | `b` | Restore saved rules |

`AllowStream` / `DenyStream` were removed on 2026-08-23 with the per-stream
`ask_each` concept. Any older document listing them is out of date.

### Signals

| Signal | Args | When | Emitted? |
|--------|------|------|----------|
| `AccessAttempt` | (app, pid, device, node, action) | New access attempt processed | **NO — dead declaration** |
| `RuleChanged` | (app, device, permission) | Rule created/updated/removed | yes |
| `StreamEvent` | (app, device, serial, event_type) | Stream connected/disconnected | **NO — dead declaration** |

`AccessAttempt` and `StreamEvent` are declared on the interface but nothing
ever emits them. **The TUI and GUI therefore poll** (1s and 2s respectively)
rather than subscribing. Any claim elsewhere that clients are signal-driven is
false.

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
| Direct ALSA capture, non-allowlisted binary | **Blocked**: `open()` returns EPERM; kernel logs the binary and device |
| Direct ALSA capture, allowlisted binary | Allowed — it is a policy, not a blanket denial |
| Firefox playback during monitor block | Unaffected, kept playing |
| Instant BLOCKED notification | Appears immediately on access attempt |
| Action notification with buttons | Shows Always Allow / While in Use / Always Deny |
| Notification dismiss → cooldown | Nothing saved, cooldown, then re-prompts |
| Kernel camera denial vs Firefox/WhatsApp | **Blocked**: "Camera or microphone not found" |
| `while_in_use` session lifecycle (microphone) | ask → grant → use → release → SESSION_ENDED |
| systemd service install | Enabled, running, survives reboot |
| D-Bus activation | Daemon auto-starts on first CLI/TUI/GUI connection |
| GUI tray icon | Shows in KDE system tray, left-click toggles window |
| GUI close to tray | X hides window, tray "Exit" actually quits |

### Automated tests

`cargo test --workspace` → **226 tests, all passing** (measured 2026-09-06).
Note the distribution:

| crate | LOC | tests |
|---|---|---|
| hwprivacy-daemon | 6749 | 112 |
| hwprivacy-common | 2272 | 56 |
| hwprivacy-lsm | 3146 | 49 |
| hwprivacy-proto | 283 | 6 |
| hwprivacy-ctl | 633 | 2 |
| hwprivacy-gui | 1013 | 1 (widget-level; needs a display) |
| hwprivacy-tui | 567 | **0** |

`classify_link()` — the pure function that makes the entire layer-1 security
decision — was covered on 2026-08-21 with 14 tests, including the one that had
never existed: that ordinary playback into a sink is **not** a monitor tap.

Still uncovered: `parse_node()`/`parse_link()` against real `pw-dump` JSON, and
the TUI entirely. `tools/tui-screen` can now render the TUI, but nothing
asserts on what it renders.

**A test is kept only after it has been seen failing.** Every test added since
2026-08-21 was run against the deliberately reintroduced defect and observed to
fail first — eleven tests have passed with their bug present in this project's
history, which is why this is a rule and not an aspiration.

> `cargo test` does **not** refresh `target/debug/hwprivacy-lsm`; it builds a
> separate `cfg(test)` harness. Passing tests once said nothing about the
> binary actually being executed. Test scripts must `cargo build` themselves.

### Kernel layer acceptance

| Phase | Result |
|---|---|
| 1 — observe-only LSM | validated live, attached first try |
| 2 — camera enforcement | **5/5**, denied live against Firefox and WhatsApp, access restored on detach |
| 3 — daemon integration | **13/13**. C5 (burst counting) and D1 both closed 2026-08-19 |
| 4 — systemd unit for the helper | installed, enabled, boot-verified |
| 5 — ALSA audio backstop | **PASSED** 2026-09-06 — non-allowlisted `open()` gets EPERM, allowlisted succeeds, audio stack unaffected |
| 5 — audio backstop | not started |

---

## Credits

Developed by Perieteanu Costin in collaboration with Claude (Anthropic's Claude Code).

---

## License

GPL-3.0-or-later

Copyright 2026 perieteanu
