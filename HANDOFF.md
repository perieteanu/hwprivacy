# HANDOFF — 2026-09-01

Read this first, then `CLAUDE.md`, then `docs-yaml/ROADMAP.yaml`.

**Run `make doc-check` before trusting any number here.** Green as of this
commit: 7 crates, **14042 LOC**, 5 binaries, **210 tests**, 0 failures.

---

## The one-line version

Camera sessions were built, proved end to end against a live kernel, and
**withdrawn the same evening**. The camera now takes `allow` or `deny`. What
survived is worth more than what went: an **answerable camera prompt**, and the
first `lsm/file_release` hook this project has ever loaded.

Do not reconstruct today from the commit titles alone — parts 1 and 2 land a
feature that 9a0085b then removes. The sequence is the point.

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

### 1. README and MISSION are done — check, do not redo

Both were rewritten today and are no longer the publication blocker. README's
posture note, the hand-started-helper claim, the `ask_each` permission table,
the config example and Known Limitations are corrected; MISSION no longer files
the kernel layer under "what would fix it" in the conditional.

**What to verify before publishing**: the README sections nobody re-read today —
Architecture, the D-Bus API, the phase history. `doc-check` cannot see a stale
prose claim.

### 2. The CPU regression — diagnosed, with a measured fix waiting

**Not a regression in hwprivacy's code.**

```
layer 1 steady state         2.70-2.82% of one core
pw-dump alone at 2 Hz        1.74%   <- 62% of the total, before our code runs
daemon's own work           ~1.0%
kernel helper                0.041%
```

Ruled out: the graph did not grow (210 KB / 87 objects now, vs 272 KB in the
docs), and the startup device-rescan DOES stop after 120 s — verified by
counting rescans in a clean 60 s window (zero). The 1.24% reading from
2026-08-04 is the outlier, not today's 2.8%.

**The fix is measured and not built**: `pw-dump --monitor`, one long-lived
process streaming changes instead of a spawn twice a second.

```
pw-dump --monitor, idle   0.031% of one core
spawning pw-dump at 2 Hz  1.74%              <- 56x
```

That puts layer 1 near **1.0%**, below the figure Costin already called "very
generous". Not trivial: `capture_graph()` returns a full snapshot and every
caller assumes that shape, while `--monitor` emits increments, so the daemon
must maintain the graph itself. Decide between this and
`d-event-driven-substrate` (pipewire-rs) before writing code — see
`ROADMAP > cpu-regression`.

### 3. The probe-close problem, if camera sessions are ever wanted back

Needs a way to tell "the open count reached zero" from "the application released
the device". Options in `ROADMAP > camera-session-ends-on-the-probe-close`, none
chosen. A release grace period is the likely answer, and **the value is a guess
until the probe-to-capture gap is measured across more than one application.**

Do NOT reach for `awaiting_open_secs` — it bounds a session that was never
opened, and using it here would mask the defect exactly as a 60 s fallback hid a
broken release path for an hour today.

### 4. Still open from before

- **g2**: Block All does not stop anything already recording.
- **g3**: the event log is a 500-entry in-memory ring buffer. (The `history`
  table does survive restarts.)
- **Phase 5**, the ALSA backstop: not started. You cannot simply deny major 116
  — that denies `/usr/bin/pipewire`, which is everyone's microphone.
- **The TUI has no tests.** `tools/gui-test` is GTK-only.

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

---

## Deliberately NOT done

- **The probe-close fix.** Options recorded, no number measured, nothing built.
- **`pw-dump --monitor`.** Measured, not implemented.
- **Camera sessions.** Withdrawn, and `lsm/file_release` deliberately left
  attached — it is the working half, and detaching it would mean re-earning a
  verifier acceptance already paid for.
- **`make gui-test` was not run today.** The GUI was rebuilt and reinstalled,
  but its AT-SPI checks have not been re-run against the new rules surface.
- **The TUI and GUI were not re-verified** after the rule-shape changes.
  `hwprivacy-ctl` was exercised heavily; the other two were not.
- **No `.deb` has ever been built**, and `make install` has never been run.
