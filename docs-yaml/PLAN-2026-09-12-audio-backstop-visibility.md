<!-- Copied from ~/.claude/plans/flickering-crunching-glacier.md on 2026-09-12.
     Manual copy: rite_copy.py hardcodes DOCS="docs" and this project uses
     docs-yaml/, so it no-ops silently. Can drift; the plan is the source. -->

# Surface the audio backstop, and give the doc rot a check that fails

## Context

Two problems, both of the same class: **something true about this machine that no
surface reports.**

**1. The ALSA capture backstop is invisible.** Since 2026-09-06 the kernel denies
`/dev/snd/pcmC*D*c` to any binary not on the allowlist — g6, the project's largest
hole for a month, closed and reboot-verified. The daemon knows it:

```rust
// hwprivacy-daemon/src/lsm_client.rs:36-49
pub enforcing_camera: bool,
/// The ALSA capture backstop. Separate from `enforcing_camera` because the
/// two follow different device guards and can differ.
pub enforcing_audio: bool,
```

It is set from the helper's `Hello` (`lsm_client.rs:432-443`) and on every push
(`:465-466`), cleared on disconnect (`:74-75`) — and then it stops. `GetKernelStatus`
returns `(connected, enforcing_camera, allowed, unresolved, err)` and reads
`k.enforcing_camera` only (`dbus_service.rs:300-310`). So:

| surface | reports |
|---|---|
| `hwprivacy-ctl status` | `Camera enforced:` only (`main.rs:212`) |
| `hwprivacy-ctl devices` | a kernel row for the camera; nothing for the mic (`main.rs:291+`) |
| TUI | no kernel line at all — `refresh()` never calls `get_kernel_status()` |
| GUI | kernel state inferred from `get_history()` rows only (`window.rs:648`) |

Worse than cosmetic: `audio_backstop_blocker()` ([config.rs:797](../../projects/hwprivacy/hwprivacy-common/src/config.rs#L797))
is a hard interlock that switches enforcement **off** and only `warn!`s to the
journal. On a JACK/PulseAudio machine, or any config where the audio server is not
allowlisted, the microphone is unprotected at layer 2 and **every status surface
still looks healthy**. That is the defect class this project has spent a month
deleting, sitting on its headline feature.

**2. The docs rotted again, and the gate could not see it.** `doc-check` is GREEN
while four claims are stale or flatly false. It already reads `CLAUDE.md` and
`HANDOFF.md` — they are in the hardcoded `DOCS` list (`tools/doc-check:70-74`), and
gitignore is irrelevant because discovery is a literal list plus `os.walk`, never
`git ls-files`. The gate missed them for two different reasons:

```
LOC_TOLERANCE = 0.10            # tools/doc-check:52
CLAUDE.md claims  14042
tree measures     15592
drift              1550         tolerance 1559.2  ->  passes by 9 lines
```

and the two *false* claims are prose, for which no check exists — even though both
are mechanically verifiable against files the gate already opens.

Intended outcome: every surface tells the truth about layer 2, and the four stale
claims become a test that fails rather than a discipline to remember.

---

## Part A — expose the audio backstop

### A1. A new D-Bus method, not a widened tuple

The in-tree convention is stated three times and must be followed:

- `dbus_interface.rs:70-71` — *"Additive, like GetKernelStatus and GetHistory — GetKernelStatus keeps its tuple so the TUI and GUI stay working untouched."*
- `dbus_service.rs:296-299` — *"A NEW method rather than a change to GetStatus, whose signature three frontends already depend on."*
- `DECISIONS.yaml` `d-a-session-must-be-visible` says the same.

Add to **`hwprivacy-common/src/dbus_interface.rs`**, after `get_kernel_status`:

```rust
/// The ALSA capture backstop: `(enforcing, why_not)`.
///
/// `why_not` is empty iff `enforcing`. When it is not, it is a complete
/// sentence a frontend prints verbatim — including the disconnected case.
///
/// The honesty doctrine lives HERE rather than in three frontends. ctl already
/// carries a long comment (main.rs:223-232) explaining why a disconnected
/// daemon must say "unknown" instead of reporting its own default as fact;
/// duplicating that reasoning into the TUI and GUI is how the three copies
/// drift. One producer, three verbatim consumers.
///
/// Additive, like GetKernelStatus and GetSessions.
fn get_audio_backstop(&self) -> zbus::Result<(bool, String)>;
```

### A2. The daemon side, as a pure function

In **`hwprivacy-daemon/src/lsm_client.rs`**, beside `gap_delta()` — which exists for
exactly this reason (*"the only part of this that a test can reach"*):

```rust
/// What to report about the audio backstop, from the four things that decide it.
///
/// Pure, and separate from the D-Bus method, so every branch is reachable by a
/// test without a daemon, a helper, or a kernel. Same shape as
/// `camera_already_denied_by_rule()` and `notification::decide()`.
pub fn audio_backstop_report(
    connected: bool,
    enforcing: bool,
    mic_guarded: bool,
    blocker: Option<String>,
) -> (bool, String)
```

Branch order — the first true wins:

1. `!connected` → `(false, "unknown — the daemon cannot reach the kernel helper, so it cannot see whether the backstop is enforcing. Check: systemctl is-active hwprivacy-lsm")`
2. `enforcing` → `(true, String::new())`
3. `Some(why)` → `(false, why)` — the interlock's own sentence, which already names the fix (`preset import audio-backstop --apply`)
4. `!mic_guarded` → `(false, "the microphone is not guarded ([devices] microphone = false), so layer 2 does not enforce capture nodes")`
5. otherwise → `(false, "the helper is connected but reports the backstop off — it is running without --enforce-audio")`

Branch 5 is the one that matters operationally and has no other surface today: the
unit can be running the flag-less binary after a partial upgrade, which is exactly
the `cp`-onto-a-running-binary trap from 2026-09-06.

Then in **`hwprivacy-daemon/src/dbus_service.rs`**, next to `get_kernel_status`:

```rust
async fn get_audio_backstop(&self) -> (bool, String) {
    let s = self.state.read().await;
    audio_backstop_report(
        s.kernel.connected,
        s.kernel.enforcing_audio,
        s.config.devices.is_guarded(&DeviceCategory::Microphone),
        s.config.audio_backstop_blocker(),
    )
}
```

No new daemon state: `audio_backstop_blocker()` is a pure function of the config,
which `dbus_service` already holds.

### A3. `hwprivacy-ctl status`

Inside the `connected` branch of `main.rs:205-252`, after `Camera enforced:`:

```
Kernel layer (eBPF LSM)
  Connected:        yes
  Camera enforced:  yes — non-allowlisted apps get EPERM
  Audio backstop:   yes — non-allowlisted apps get EPERM on capture nodes
  Allowed binaries: 6
```

and when off, the reason on its own indented continuation lines, matching the
existing `Camera enforced: UNKNOWN` block's shape. `Err(_)` arm gains
`Audio backstop:   unknown — daemon predates this feature`, the pattern already at
`main.rs:253-257`.

### A4. `hwprivacy-ctl devices` — the microphone row

The block's own comment argues for this: *"Listing devices by what PipeWire happens
to expose describes the monitoring substrate, not the hardware. Say what is
guarded."* The mic is guarded at layer 2 and the table is silent.

```
Kernel layer (eBPF LSM) — guards device nodes directly, not via PipeWire
-----------------------------------------------------------------------
camera      /dev/video* (by executable inode)   6 executable(s) allowed   ON
microphone  /dev/snd/pcmC*D*c (capture nodes)   6 executable(s) allowed   ON

  note: the backstop cannot name the APPLICATION behind the audio server.
        Per-application microphone policy is layer 1's job.
```

That note is not decoration — it is the one thing `project-g6-closed-audio-backstop`
insists must never be mis-stated, and a bare `microphone ... ON` row invites exactly
the misreading.

### A5. TUI — second line in the existing status bar

`draw_status` (`ui.rs:39-54`) already owns a `Constraint::Length(3)` chunk holding
one line, so a second row needs no layout change, no new tab, no touch to
`Panel::next()` or `App::max_rows()`.

- `app.rs`: add `pub kernel: (bool, bool, u32, u32, String)` and
  `pub audio_backstop: (bool, String)`, defaulted so a daemon without the method
  renders as unknown rather than as off.
- `App::refresh()` (`app.rs:90-106`): two more `if let Ok(..)` calls, same shape as
  the existing five.
- `ui.rs`: `Paragraph::new(vec![Line::from(..), Line::from(..)])`:

```
 RUNNING | Guarded: 4 | Rules: 8 | Blocked: 0 | Active streams: 0
 Kernel: connected | camera ON | audio backstop ON
```

Colour the second line red when either guard is off while connected — the only
state that needs to catch the eye.

### A6. GUI — a second label, never the existing one

**Do not put this in `status_label`.** It is the error sink: `UiMessage::Error`
overwrites it (`window.rs:433-435`) and `AllowCamera` success toasts are routed
through `Error` too (`:670-672`), so a kernel indicator there would be wiped by the
next toast and silently read as stale-but-fine.

- new `kernel_label` appended after `status_label`, before the `Separator`
  (`window.rs:61-68`), same `caption` CSS class;
- new `UiMessage::Kernel(bool, bool, String)` variant;
- the existing `Refresh` arm (`window.rs:634-659`) gains `get_kernel_status()` and
  `get_audio_backstop()` calls beside its six, and sends the new message;
- rendered in a new match arm beside `UiMessage::Status` (`:256-262`).

### A7. README

`README.md`'s D-Bus table (~line 977-993) is headed *"Verified against
`hwprivacy-daemon/src/dbus_service.rs` on 2026-09-06"*. Add `GetAudioBackstop()` to
it, or that header becomes false the moment this lands.

### A8. Tests, each proven to fail first

House rule: *prove a new test fails against the bug it catches.* Reintroduce
"report camera only" and watch each fail before keeping it.

- `audio_backstop_report`: one test per branch, five total, plus the ordering test
  that matters — **disconnected-and-blocked must report unknown, not the blocker
  reason**, because a stale config reason presented as current fact is the same bug
  as the 2026-08-19 "NOT blocked" readout.
- the "enforcing wins over a blocker" case: the helper's actual state is
  authoritative over what the config would decide now.

### A9. `REQUIRED`, not a sentinel

The defect is an **absence**, which is `REQUIRED`'s shape, not `SENTINELS`' — the
script says so itself (`tools/doc-check:337-340`). Add two entries:

```python
("hwprivacy-daemon/src/dbus_service.rs", "get_audio_backstop",
 "the audio backstop became invisible again. It has enforced since "
 "2026-09-06 and no surface reported it for six days..."),
("hwprivacy-ctl/src/main.rs", "Audio backstop:",
 "ctl is reporting the camera guard and not the audio one..."),
```

---

## Part B — the doc gate, and the four stale claims

### B1. Tighten the tolerance

`tools/doc-check:52`: `LOC_TOLERANCE = 0.10` → `0.03`, with a comment recording
that 10% let a 1550-line drift pass by nine lines.

### B2. `DOC_CLAIMS` — the mirror of `SENTINELS`, for docs

`SENTINELS` catches a defect returning to **source**; `REQUIRED` catches a fix
leaving source. Neither can express *"this doc asserts something about another file
that the file contradicts"* — which is both of today's false claims. New list, same
shape as `REQUIRED` (file named, not tree-wide):

```python
# A claim in a doc that another FILE refutes. Not prose review — each entry is
# mechanical: forbidden string in `doc`, contradicted by `token` in `other`.
# Add one only after a doc has actually misled someone.
DOC_CLAIMS = [
    ("CLAUDE.md", 'zero occurrences of', "README.md", "eBPF",
     "README was realigned 2026-08-19 and swept end-to-end 2026-09-06. "
     "CLAUDE.md contradicted itself 40 lines later in the same file."),
    ("CLAUDE.md", "Frozen 2026-08-04 22:37", "docs-yaml/MISSION.yaml", "2026-09-06",
     "MISSION.yaml documents the backstop as enforcing. It is not frozen "
     "pre-pivot, and reading it as conditional inverts what ships."),
]
```

Report under a new check tag `doc-claim`.

### B3. Fix the `REQUIRED` hole

`tools/doc-check:355-361` does `if body is None: continue` — so **deleting** a file
passes the gate silently, while removing one token from it fails. Make a missing
`REQUIRED` file a failure, as the `ANCHORS` loop at `:206` already does. This
matters more once A9 adds two entries.

### B4. Correct the stale facts

Measured this session against the tree and the running host:

| file | claim | truth |
|---|---|---|
| `CLAUDE.md` | `7 crates, 14042 LOC` | 15592 |
| `CLAUDE.md` | `19 warnings` | 21 |
| `CLAUDE.md` | test table: lsm 49, daemon 72, common 43 | 56, 116, 60 (total 241) |
| `CLAUDE.md` | MISSION "frozen 2026-08-04, files the kernel layer under *what would fix it*" | false — MISSION covers the 2026-09-06 backstop |
| `CLAUDE.md` | README has "zero occurrences of kernel/eBPF/LSM" | false, and self-contradicted later in the same file |
| `CLAUDE.md` | "Verified ... on 2026-09-01" | 2026-09-12 |
| `HANDOFF.md` | "A release tag ... No `.deb` has ever been built" | section 3 of the same file says it builds — 5 packages, lintian 0 errors |
| `ROADMAP.yaml` | `phase_5_audio_backstop.status: "enforcement OFF pending live acceptance"` | enforcing since 2026-09-06; the same entry carries `accepted_live` and `reboot_verified` |
| `ROADMAP.yaml` | `known_policy_keys.firefox_esr: ino=30287776` | 30292989 (third upgrade) |
| `ROADMAP.yaml` | `debt.compiler_warnings: 6` | 21 |

For the inode, replace the hardcoded number with the method to obtain it — a
hardcoded inode has a half-life of one upgrade, which the roadmap itself predicts.

### B5. Two live findings worth recording as they are measured, not inferred

- **`/usr/bin/pipewire-pulse` is a symlink to `pipewire`** (both ino 30017535), so
  7 `exe_path` rules collapse to 6 kernel keys — which is why `Allowed binaries: 6`
  is correct rather than an off-by-one. Perms are OR'd per key
  (`lsm_client.rs:237-240`, `replace_policy:804`), so the live config's
  `pipewire-pulse camera = "deny"` is silently defeated by `pipewire camera =
  "allow"`. `d-executable-is-the-principal` does not cover inode aliasing. Record
  it in `DECISIONS.yaml` or `CONVENTIONS.yaml`; **do not** change behaviour in this
  change — the OR is right in spirit (the allowlist is allow-only) and the fix is a
  warning, which is its own decision.
- **The s1 fingerprint mechanism has now survived a third Firefox upgrade**, proven
  live: `sep 12 10:49:36 ... exe_ino:30292989 denied:false`. Worth stating in
  `ROADMAP > policy_staleness_2026_08_21` as a measurement rather than a prediction.

---

## Verification

```bash
make doc-check                 # must stay GREEN with B1-B4 applied, and must FAIL
                               #   when any corrected claim is reverted (check each)
cargo test --workspace         # 241 + the new audio_backstop_report tests
cargo build --release --workspace
install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/
systemctl --user restart hwprivacy
hwprivacy-ctl status           # Audio backstop: yes
hwprivacy-ctl devices          # microphone row present, with the note
make gui-test                  # 14 checks against the RUNNING window
```

Then prove the surface is not merely printing a constant — the step that separates
"reports enforcement" from "prints yes":

```bash
# with the daemon stopped, set [devices] microphone = false, restart
hwprivacy-ctl status           # must read: no — the microphone is not guarded
# restore, then stop the helper
sudo systemctl stop hwprivacy-lsm
hwprivacy-ctl status           # must read: unknown, NOT "no"
sudo systemctl start hwprivacy-lsm
```

The third command is the one that matters: reporting `no` there is the 2026-08-19
bug — *"Claiming protection that is absent and denying protection that is present
are the same class of bug"* — and a check that only ever sees the healthy state
cannot tell the two apart. The two `systemctl` lines need `sudo`, so they come to
Costin as a script with a banner; everything above it I run and report.

**Not covered:** whether the GUI label is legible or correctly placed — that needs
eyes, and `tools/gui-test` asserts presence, not layout.

---

## Deliberately not in this change

- **Retiring `while_in_use`** — decision pending. No overlap: the audio lines go in
  the kernel block, sessions are a separate block in `ctl status`.
- **Block All (g2)** — awaiting the semantics answer.
- **Widening `audio_backstop_blocker()` beyond PipeWire** — needs a real JACK or
  PulseAudio machine to measure.
- **Warning the user about inode aliasing** (B5) — recorded, not implemented.
- **A `--host` tier for doc-check** — the ROADMAP item stands; B1-B3 are the
  file-tier gaps, and the host tier is a separate piece of work.
- **The 21 compiler warnings** — counted and recorded, not fixed.
