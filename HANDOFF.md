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
| `hwprivacy.service` (user) | **active**, PID 2331, ~15 h uptime, 1.3 % of a core, 20 MB RSS |
| Binary it runs | `~/projects/hwprivacy/target/release/hwprivacy-daemon` — the **dev tree**, not `/usr/bin` |
| `hwprivacy-lsm` | **not** installed, **not** running, no systemd unit. Runs only when invoked by hand as root. |

`cargo build --release` in this tree swaps the binary underneath a live
service. Restart with `systemctl --user restart hwprivacy` after building.

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

1. **Measure the LSM hook's cost.** It fires on *every* `open()` system-wide.
   Unmeasured. Costin rejected the PipeWire layer's 1.2 % idle burn, so this
   number can invalidate the architecture — do it before building more.
   Method: time ~200k `open`/`close` of `/dev/null` with and without the
   program attached.
2. **Phase 2 — camera enforcement.** Policy hash map keyed on
   `(exe_dev, exe_ino)`, `-EPERM` on miss, default-deny, `--observe` retained.
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
- **No git.** 3.2 GB, no version control, no undo. `.gitignore target/` before
  any first commit.
- The LSM hook cost, `.deb` packaging, portability, and audio enforcement.
