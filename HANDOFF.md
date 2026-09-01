# HANDOFF — 2026-09-02 (00:15, one long session)

Read this first, then `CLAUDE.md`, then `docs-yaml/ROADMAP.yaml`.

**Run `make doc-check` before trusting any number here.** Green as of this
commit: 7 crates, **14636 LOC**, 5 binaries, **225 tests**, 0 failures.

---

## The one-line version

Camera sessions were built, proved end to end against a live kernel, and
**withdrawn the same evening**. The camera now takes `allow` or `deny`. What
survived is worth more than what went: an **answerable camera prompt**, and the
first `lsm/file_release` hook this project has ever loaded.

Do not reconstruct today from the commit titles alone — parts 1 and 2 land a
feature that 9a0085b then removes. The sequence is the point.

**Then the second half of the session replaced the monitoring substrate.**
Layer 1's idle cost went from 2.70-2.82% of a core to **0.033%** — 82x — and a
new link is now seen in 11 ms instead of somewhere in a 0-500 ms poll window.
Both frontends were verified afterwards; both are fine.

---

## What happened, in order

### 1. The verifier accepted the second BPF program

`hwprivacy-lsm` carrying both `lsm/file_open` and `lsm/file_release` was
installed to `/usr/bin` and the service came up **active**. That had been the
largest open unknown since 2026-08-23. `d-camera-sessions-via-file-release`'s
"not verified yet" is retired.

### 2. The PipeWire camera route came back

`pipewire` and `wireplumber` had been deleted from the config on 2026-08-23
while clearing rules for an unrelated test — **not** a decision, despite what
HANDOFF and CLAUDE.md claimed for a week. `preset import desktop-baseline
--apply` restored them, and a PipeWire restart made the camera node appear for
the first time in this project's history:

```
camera  v4l2_input.pci-0000_00_14.0-usb-0_7_1.0  Integrated Camera (V4L2)  ON
```

PipeWire probes for cameras at **startup only**. The preset alone was not
enough; the stack had to be restarted.

### 3. `while_in_use` became real — on the microphone

First complete session lifecycle the project has ever recorded, from a real
video call:

```
19:06:46  Firefox [pipewire-pulse] -> microphone -> ASKED
19:06:50  User set rule: Firefox -> Microphone = while_in_use
19:07:00  while_in_use session ended: firefox released Microphone
19:07:00  Event: firefox (pid:0) -> microphone -> SESSION_ENDED
```

Ask, grant, use, release, end. **This works and is unaffected by anything
below.**

### 4. Camera sessions: built, proved, withdrawn

The full arc ran on real hardware — allowlist **2 -> 3 -> 2**, live session in
`status`, `SESSION_ENDED` from the kernel. Then:

```
20:02:33.712  ALLOWED (first open, count 1)
20:02:33.823  session ended: released the camera (kernel)      [111 ms]
20:02:35.914  12 further allowed open(s)   <- the ACTUAL capture
20:02:38.317  2 executable(s) allowed      <- executable removed MID-CALL
```

Reproduced identically 22 seconds later. **Firefox probes the camera before
capturing** — open, close, then open the handles it records with. The probe
close takes the open count to zero, so the release fires before capture starts.
The call survived only because the capture opens beat the allowlist removal by
~2.5 s. **The video worked by race, not by policy.**

The model was wrong, not the code. "A camera session is 13 opens" was measured
as a BURST on 2026-08-05 and quietly became the design. An open count is a
TRANSIENT: zero means "no handle held right now", not "finished with the
camera".

Costin's ruling: **allow or deny only.** `d-camera-is-allow-or-deny`.

### 5. The graph streams instead of being polled

`pw-dump --monitor` replaced spawning `pw-dump` twice a second. Measured on the
live service:

```
layer 1 idle CPU   2.70-2.82%  ->  0.033%     (82x)
link latency       0-500 ms    ->  11 ms
```

**`pipewire-rs` was considered and lost** — and not on the numbers. Its recorded
objection in `d-event-driven-substrate` (MSRV, a new dependency) is obsolete:
`librust-pipewire-dev 0.8.0-7` **is** packaged in Debian 13. It lost because the
`--monitor` wire format is already what the daemon wants — block 0 is a complete
snapshot in `GraphSnapshot`'s exact shape, later blocks carry only changes, and
a removal is the object with `"info": null`. The existing parsers are reused
unchanged.

**The hazard that shaped the design**, measured before any code was written:
`pw-dump --monitor` **dies when PipeWire restarts, and exits 0**. A clean exit
is indistinguishable from success, so a bare child would leave the daemon
permanently blind while every status surface reported healthy — b5's exact
shape. The polling design was immune because it respawned every tick.

Hence: any exit is an anomaly including 0; a respawn **re-seeds, never merges**
(PipeWire ids are not stable across a server restart, so a merged graph carries
dead ids a new object can reuse — b2); and a watchdog covers silence, because a
wedged reader and a quiet system look identical. Verified live — see
`d-monitor-stream-not-polling`.

`poll_interval_ms` is retired: kept with `skip_serializing` so an existing
config still loads, ignored, and dropped on the next rule write.

### 6. Both frontends verified

They had not been checked since the rules surface changed on 2026-08-23.

- **`make gui-test` 16/16**, after one FALSE failure: the unset-category check
  read `rule_rows[0]`, which is `pipewire` — a rule that legitimately sets all
  three categories and so has no dash to find. It had only ever passed because
  row 0 happened to have a gap.
- **`tools/tui-screen` is new** and is the first thing that can look at the TUI
  at all. All four panels verified.

---

## What is running right now

| | |
|---|---|
| `hwprivacy.service` (user) | active, `~/.local/bin/hwprivacy-daemon` |
| `hwprivacy-lsm.service` (system) | active, **both BPF programs attached**, enforcing |
| live rules | `pipewire`, `wireplumber` camera=allow; `firefox` mic=while_in_use camera=allow; `parecord` mic=while_in_use |
| allowlist | 3 executables |

`firefox` is on `camera = allow` and calls work. The BPF program is still
**never pinned** — stopping the service restores normal access.

---

## Pick up here

### 1. README's unread sections — the last publication item

**Start here. Highest value, lowest effort, and the only thing blocking a
stated goal.**

README and MISSION were corrected on 2026-09-01 and are no longer the blocker:
the posture note, the hand-started-helper claim, the `ask_each` permission
table, the config example and Known Limitations are all fixed, and MISSION no
longer files the kernel layer under "what would fix it" in the conditional.

**What was never re-read**: README's Architecture section, the D-Bus API, and
the phase history. `doc-check` checks counts, anchors and sentinels — it
structurally cannot see a stale prose claim, which is exactly how the posture
note survived eleven days while the gate ran green every time.

~40 minutes. Also: the config example and CPU figures in README may now
disagree with the substrate change — check them against
`d-monitor-stream-not-polling`.

### 2. The probe-close problem, if camera sessions are ever wanted back

Needs a way to tell "the open count reached zero" from "the application released
the device". Options in `ROADMAP > camera-session-ends-on-the-probe-close`, none
chosen. A release grace period is the likely answer, and **the value is a guess
until the probe-to-capture gap is measured across more than one application** —
so this is an instrumentation task before it is a coding task. Nothing is broken
while it waits: the permission is withdrawn.

Do NOT reach for `awaiting_open_secs` — it bounds a session that was never
opened, and using it here would mask the defect exactly as a 60 s fallback hid a
broken release path for an hour.

### 3. Phase 5 — the ALSA backstop

The largest remaining hole: g6 means any process can still take the microphone
via ALSA directly, which undercuts the project's own description. Also the
largest blast radius in the project — **you cannot deny major 116**, because
that denies `/usr/bin/pipewire`, which is everyone's microphone. Needs an
observe-only pass first to find what actually opens capture devices on this
machine. Book it as its own session.

### 4. Still open from before

- **g2**: Block All does not stop anything already recording.
- **g3**: the event log is a 500-entry in-memory ring buffer. (The `history`
  table does survive restarts.)
- **The TUI has no tests.** `tools/tui-screen` can now RENDER it, which is new,
  but nothing asserts on what it renders.

---

## Traps that bit today

- **A fallback can hide a broken primary.** The kernel release path was keyed on
  the executable while the session was opened under the rule name, so
  `file_release` removed nothing — and `awaiting_open_secs` reaped the session
  60 s later, so the feature LOOKED like it worked, slowly. Cost an hour.
- **Three tests passed with their bug present**, all the same shape: asserting
  through something that has its own reason to hold, instead of pinning the
  decision under test. The fix each time was to extract that decision into its
  own function (`rule_key_for`, `session_key_for_release`,
  `camera_already_denied_by_rule`) and assert on it.
- **A doc-check SENTINEL cannot express an absence.** Sentinels catch a defect
  coming BACK; a fix going AWAY needed a new `REQUIRED` check.
- **Journal timestamps are UTC; the journal clock is EEST.** Three "unexplained"
  denials at 19:41 were the 22:41 events. Compare against
  `systemctl show -p ActiveEnterTimestamp`, never the inline stamp.
- **Under Plasma a `Timeout::Never` critical notification can go to the
  notification tray rather than staying on screen.** A prompt sat there
  unanswered for 2m44s while the camera was denied three times, and it read as
  "no prompt appeared". Both b6 skip sites now log at `info!` for this reason.
- **The daemon rewrites `config.toml` from memory on shutdown.** Editing the
  file while it holds state does nothing. Use the CLI.
- **A pty from `pty.fork()` is 0x0, and ratatui draws NOTHING into it.** It
  emits the alternate-screen and cursor-hide sequences and then paints empty
  frames forever, which reads exactly like a hung TUI. `TIOCSWINSZ` on the
  master fd first. And ratatui **redraws in place**, so concatenating raw
  output gives every frame smeared together, not a screen — `tools/tui-screen`
  replays the escape sequences onto a grid for this reason.
- **`pw-dump --monitor` exits 0 when PipeWire restarts.** Any supervisor over
  it must treat a clean exit as an anomaly.
- **A test that names an invariant but reads a fixed row is not testing it.**
  gui-test's unset-category check read row 0 and passed only because row 0
  happened to have a gap; it failed against a correct UI the moment the rule
  order changed.

---

## Deliberately NOT done

- **The probe-close fix.** Options recorded, no number measured, nothing built.
- **README's unread sections.** Architecture, D-Bus API, phase history.
- **Camera sessions.** Withdrawn, and `lsm/file_release` deliberately left
  attached — it is the working half, and detaching it would mean re-earning a
  verifier acceptance already paid for.
- **A gui-test flake was observed, not chased**: "clicking a denial opens the
  grant dialog" failed on one run and passed on a slower re-run. Back-to-back
  invocations race the dialog.
- **Nothing asserts on the TUI's rendering.** `tools/tui-screen` prints it; no
  test compares it to anything.
- **No `.deb` has ever been built**, and `make install` has never been run.
