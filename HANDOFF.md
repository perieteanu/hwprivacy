# HANDOFF — 2026-08-05 21:00

Read this first, then `CLAUDE.md`, then `docs-yaml/ROADMAP.yaml`.

---

## Where things stand

hwprivacy polices the PipeWire graph, and that was **measured** to be
structurally blind: camera and microphone can both be taken by going straight
to `/dev/video0` / `/dev/snd/*`, which is exactly what Firefox does for the
camera. So the project is now **two layers**, and both stay — neither is
sufficient alone.

| | Phase | State |
|---|---|---|
| 1 | observe-only eBPF LSM | **validated live** |
| 2 | camera enforcement | **PROVEN** — acceptance 5/5, denied live against Firefox/WhatsApp |
| 3 | daemon integration | **substantially proven** — 11/13 checks pass. Two gaps, both listed below |
| 4 | systemd unit for the helper | not started |
| 5 | audio backstop | agreed in principle, not started |

`git`: 24 commits, clean tree. **63 tests** — there were zero on 2026-08-04.

---

## What is running right now

| | |
|---|---|
| `hwprivacy.service` (user) | **active**, `NRestarts=0`, from `~/.local/bin/hwprivacy-daemon` |
| `hwprivacy-ctl/-tui/-gui` | in `~/.local/bin`, on `PATH` — call them by name |
| `hwprivacy-lsm` | **not running, no systemd unit.** Started by hand as root, per test. |

**Nothing is being enforced at the kernel layer right now.** The helper only
runs when a test starts it, and the eBPF program is never pinned — killing the
process detaches it and restores normal access.

After rebuilding, re-install or the service keeps the old binary:

```bash
cargo build --release --workspace
install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/
systemctl --user restart hwprivacy
```

---

## Pick up here — two open items, in this order

Test script: `~/projects/claude-run/hwprivacy-phase3-test-20260805.sh`
Criteria and full result: `docs-yaml/ROADMAP.yaml > kernel_layer >
phase_3_acceptance_criteria` and `> phase_3_result_2026_08_05`.

**1. C5 — burst counting is still UNVERIFIED, and the test cannot verify it.**
Part 2 asks for a call that "should fail", but the daemon pushes the allowlist
on connect, so Firefox is *allowed* and its 13-open burst is not a denial. The
only denied app, ffmpeg, opens once and never bursts. **Fix the test**:
temporarily set `firefox camera = "deny"` in config.toml for the deny phase and
restore afterwards — the same pattern Part 4 already uses safely.

**2. D1 — unresolved.** The call did not work even though `firefox-esr` was
allowlisted and the kernel shows it opening the camera 13 times without denial.
Two untested hypotheses, both plausible:
  - the helper is restarted between the deny and allow steps, and for up to 10 s
    until the daemon reconnects it enforces an EMPTY allowlist
  - the open-fd gap (below) leaving Firefox in a stale state

Do not guess between them. Test one at a time.

**What is already proven:** connection, reconnect without restarting the
daemon, policy push, gap reporting, unresolved-entry reporting, enforcement,
kernel events reaching `hwprivacy-ctl`/TUI/GUI, notifications with the right
wording, restore on detach, and no interference with the PipeWire layer.

---

## The measurements that decided the architecture

```
ffmpeg -f v4l2 -i /dev/video0   → 90 frames captured, 0 events logged
ffmpeg -f alsa -i hw:0,0        → 3s of mic audio,    0 events logged
```

Both layers watching the same 7 seconds:

```
KERNEL   firefox-esr → /dev/video0 ×10, /dev/video1 ×3
         pipewire    → pcmC0D0c    ×1      ← cannot tell WHO wants the mic
PIPEWIRE Firefox     → microphone  ASKED   ← knows the app, blind to the camera
         camera events: 0
```

Hook cost: **+13.75 ns/open**, 95 % CI `[+7.3, +20.2]`, 1.88 % of a 733 ns
`open()`, **0 % at idle**. The PipeWire poll burns 1.2 % constantly.

---

## Two decisions Costin has NOT made

1. **deny-by-default vs ask-by-default** for the PipeWire layer. README says
   deny-all; the live config says `ask`. See `DECISIONS.yaml
   d-posture-unsettled`. Deliberately untouched — one variable at a time.
2. Whether the PipeWire layer's four defects (b1–b4) get fixed before or after
   the kernel layer is finished.

---

## Traps that already bit

- **Two `dev_t` encodings.** `stat()`'s (glibc) and the kernel's are different
  layouts. Decoding one with the other's rules yields major 0 and silently
  matches *nothing* — while unit tests pass. This bit twice: once for `i_rdev`,
  then again for `s_dev` in the allowlist, where it looked exactly like
  "enforcement works, allowlist doesn't". All conversion now lives in
  `device_index::glibc_to_kernel_dev()`.
- **`cargo test` does not refresh `target/debug/hwprivacy-lsm`.** It builds a
  separate `cfg(test)` harness. 30 passing tests once said nothing about the
  binary being executed. Test scripts now run `cargo build` themselves.
- **D-Bus activation vs systemd.** Pointing the activation file at a real
  binary let `hwprivacy-ctl` fork a *second* daemon that grabbed the bus name;
  the unit crash-looped 32 times with `name already taken on the bus`. Now
  delegates via `SystemdService=`. Check `MainPID`, not `is-active` — the
  latter says "active" mid-restart.
- **`/usr/bin/firefox` is a shell script.** Real binaries:
  `/usr/lib/firefox-esr/firefox-esr` and `~/firefox-developer/firefox-bin` —
  different inodes, so different policy keys. That is the feature.
- **A camera session is 13 `open()` calls.** Coalescing collapses them to one
  event; the count is flushed separately or 12 denials vanish from the log.
- **`bpftool` lives in `/usr/sbin`**, off a non-root `PATH`.
- **`libelf.h: No such file`** means the Phase 0 toolchain script has not run.

---

## Deliberately NOT done

- **C5 (burst counting) and D1** — see "Pick up here". Everything else in
  Phase 3 is proven.
- **Phases 4 and 5** — no code.
- **PipeWire-layer defects b1–b4** — untouched. Dismissing a prompt on the
  plain `ask` path still writes a permanent `deny` rule. This is why kernel
  denials use an *informational* notification with no action buttons: routing
  them through the action path would inherit b1 on day one.
- **README.md is uncorrected** — still presents camera as protected and
  documents D-Bus signals that are never emitted. `CLAUDE.md` lists which of
  its claims to distrust.
- **Per-event cost unmeasured** — what one camera/mic event costs the observer
  (`/proc` resolution, printing). Only the hot path was measured.
- **Enforcement cannot revoke an ALREADY-OPEN fd.** Costin saw live camera
  video while enforcement was on, because Firefox had opened the device earlier
  and kept the descriptor. The LSM hook fires on `open()`, not on reads. This
  is the same class as the PipeWire layer's g1/g2 and is a real limitation, not
  a bug — but "I enabled blocking and still saw video" is exactly how someone
  concludes the tool does not work, so it must be stated plainly wherever the
  camera feature is described. Closing it would mean hooking
  `security_file_permission` (intercepting every read, not every open) or
  revoking on policy change. That is a design step, not a patch.
