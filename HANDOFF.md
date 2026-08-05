# HANDOFF — 2026-08-04 23:30

Written at the end of the session that reopened this project cold. Read this
first, then `CLAUDE.md`, then `docs-yaml/ROADMAP.yaml`.

---

## Where things stand in one paragraph

hwprivacy was found to be **feature-complete but structurally blind**: it
polices the PipeWire graph, and both camera and microphone can be taken by
going straight to `/dev/video0` / `/dev/snd/*`, which is what Firefox and
Chrome actually do for the camera. That was measured, not inferred. The project
pivoted to a **two-layer** design — keep the PipeWire layer for what it is
genuinely good at (playback-monitor taps, per-app mic), and add a **kernel eBPF
LSM layer** underneath for direct device access. The kernel layer's Phase 1
(observe-only) is **built, tested, and validated live**. Phases 2–4 have not
started, and nothing enforces anything new yet.

---

## What is running on this machine right now

| | |
|---|---|
| `hwprivacy.service` (user) | **active**, restarted 2026-08-04 23:40 |
| Binary it runs | `~/.local/bin/hwprivacy-daemon` — **no longer the dev tree** |
| `hwprivacy-ctl/-tui/-gui` | also in `~/.local/bin`, which is on `PATH` — call them by name |
| `hwprivacy-lsm` | **not** installed, **not** running, no systemd unit. Runs only when invoked by hand as root. |

**Changed 2026-08-04:** the service used to run straight out of
`target/release/`, so `cargo build --release` swapped the binary underneath a
live service. It now runs from `~/.local/bin`. Consequence: **after rebuilding
you must re-install for the change to take effect** —

```bash
cargo build --release --workspace
install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/
systemctl --user restart hwprivacy
```

Also fixed then: the D-Bus activation file had been pointing at
`/home/perieteanu/hwprivacy/...` — a path that does not exist (the project is
under `projects/`). D-Bus activation had therefore never worked; the service
only ever started because systemd started it. Both files are regenerated
correctly by `hwprivacy-daemon install`.

**Nothing new enforces anything.** The kernel program denies nothing by
construction and is never pinned — stopping the process detaches it.

---

## The measurements that changed the project

Both run against the live system, both with the PipeWire daemon running:

```
ffmpeg -f v4l2 -i /dev/video0 -frames:v 90   → 90 frames captured,  0 events logged
ffmpeg -f alsa -i hw:0,0      -t 3           → 3s of mic audio,     0 events logged
```

Then, with the kernel observer attached, the same 7-second window seen by both
layers at once:

```
KERNEL   23:09:12  firefox-esr → /dev/video0  ×10
                   firefox-esr → /dev/video1  ×3
         23:09:13  pipewire    → pcmC0D0c     ×1   (MIC)

PIPEWIRE 23:09:13  Firefox → microphone  ASKED ×2
         23:09:16  Firefox → microphone  STREAM_DENIED
         camera events: 0
```

Read that twice — it is the whole argument. The kernel sees the camera and
cannot tell who is behind the mic (it only sees `/usr/bin/pipewire` holding the
device). PipeWire sees who wants the mic and is blind to the camera. **Neither
layer alone is sufficient**, which is why both stay.

---

## Pick up here

```bash
cd ~/projects/hwprivacy/hwprivacy-lsm
cargo build && cargo test          # should be clean, 12/12
sudo ./target/debug/hwprivacy-lsm --summarize
```

Three things are queued, in this order:

1. ~~Measure the LSM hook's cost.~~ **DONE 2026-08-05 — the architecture passes.**
   `+13.75 ns/open` mean, 95 % CI `[+7.3, +20.2]`, 9/10 cycles positive,
   sign test p = 0.021. That is **1.88 % of a 733 ns `open()`** — i.e.
   0.0014 % of a core at 1 000 opens/sec, 0.0138 % at 10 000, and **0 % at
   idle**. The PipeWire layer burns 1.2 % constantly; at heavy load that is
   ~87× more, and at idle the ratio is infinite. Detail and the two false
   starts: `docs-yaml/ROADMAP.yaml > kernel_layer > hook_overhead_measured`.
2. **Phase 2 — camera enforcement.** Policy hash map keyed on
   `(exe_dev, exe_ino)`, `-EPERM` on miss, default-deny, `--observe` retained.
   Must coalesce: one camera session is 13 opens.
3. **Phase 3 — integration.** NDJSON over `/run/hwprivacy/lsm.sock`,
   `AppRule.exe` in config, `lsm_client.rs` in the daemon. All three frontends
   then display kernel blocks with **zero** frontend changes.

Full plan with file lists, verification and risks:
`docs-yaml/PLAN-kernel-enforcement.md`.

---

## Two decisions Costin has NOT made

Do not assume either. Both were explicitly left open.

1. **deny-by-default vs ask-by-default** for the PipeWire layer. README says
   deny-all; the live config says `ask`. See `DECISIONS.yaml
   d-posture-unsettled`.
2. **Should `firefox-esr` start allowed or denied** when Phase 2 lands.

Also unanswered: whether Phase 2 should proceed before the CPU measurement.
Costin's last instruction was "none of them yet" — he stopped to wrap up.

---

## Traps that already bit once

- **Two dev_t encodings.** `stat()`'s `st_rdev` (glibc) and the kernel's
  `inode->i_rdev` are *different layouts*. Decoding one with the other's rules
  yields major 0 and silently matches nothing — while synthetic unit tests
  pass. There is now a regression test asserting the two disagree.
- **`bpftool` is in `/usr/sbin`**, which Debian keeps off a non-root PATH.
- **`libelf.h: No such file or directory`** during `cargo build` means the
  Phase 0 toolchain script has not been run. Our own `build.rs` guard never
  fires, because cargo builds *dependency* build scripts first.
- **`/usr/bin/firefox` is a shell script.** The real binaries are
  `/usr/lib/firefox-esr/firefox-esr` and
  `/home/perieteanu/firefox-developer/firefox-bin` — different inodes, so they
  are different policy keys. That is correct behaviour, not a bug.
- **A camera session is 13 `open()` calls**, not one. Phase 2 must coalesce or
  it will emit 13 notifications.

---

## Deliberately NOT done

- **Phase 2, 3, 4** — no enforcement code exists.
- **The four PipeWire-layer defects b1–b4** — untouched. Dismissing a prompt on
  the plain `ask` path still writes a permanent `deny` rule.
- **`hwprivacy-lsm` is its own workspace**, not a member of the parent. This is
  deliberate so `cargo build --workspace` cannot break the running service. Fold
  it in once the toolchain is a given.
- **README.md is uncorrected.** It still presents camera as protected and
  documents D-Bus signals that are never emitted. `CLAUDE.md` lists exactly
  which of its claims to distrust.
- The LSM hook cost, `.deb` packaging, portability, and audio enforcement.

**Now done (was listed here, corrected 2026-08-05):** git exists — 2 commits,
`.git` is 864 KB against a 4.1 GB tree, `target/` and the machine-specific
`vmlinux.h` ignored.
