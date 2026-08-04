# hwprivacy-lsm

Kernel-level hardware access enforcement for hwprivacy, via an eBPF LSM program
attached to `security_file_open`.

## Why this exists

hwprivacy's original design polices the PipeWire graph. On 2026-08-04 that was
measured against reality and found insufficient — **both** device classes:

```
ffmpeg -f v4l2 -i /dev/video0 -frames:v 90   → 90 frames captured,  0 events logged
ffmpeg -f alsa -i hw:0,0      -t 3           → 3s of mic audio,     0 events logged
```

Firefox and Chrome open `/dev/video0` **directly via V4L2**. No PipeWire node is
created, no link appears, and the link-diff monitoring substrate has nothing to
observe. The same holds for direct ALSA capture. This is structural blindness,
not a bug — see `docs-yaml/ROADMAP.yaml > security_gaps` g5 and g6.

This crate is the layer below.

## Current phase: 1 — OBSERVE ONLY

**Nothing is denied.** The eBPF program returns the incoming LSM verdict
unchanged. Its job right now is to answer two questions:

1. Does BPF LSM attach and do CO-RE struct reads work on this kernel?
2. *Which executables actually touch the camera and microphone on this
   machine?* — the input to writing any policy at all.

Phase 1 watches **both** majors (81 video4linux, 116 alsa) because observation
is free and the audio data is wanted anyway. Enforcement (`-EPERM`) arrives in
Phase 2 and is **camera only**; audio enforcement is a separate feature.

```bash
sudo hwprivacy-lsm                 # CAMERA + MIC opens, live
sudo hwprivacy-lsm --summarize     # collapse to a per-consumer table
sudo hwprivacy-lsm --all           # include playback/control noise
sudo hwprivacy-lsm --json          # one JSON object per line
```

## Safety model

The BPF program is **never pinned**. When this process exits — cleanly, on
Ctrl-C, killed, or crashed — the kernel detaches it and camera access returns
to normal. There is no state left behind and no way to lock yourself out of
your own webcam.

```
sudo pkill hwprivacy-lsm     # enforcement gone, immediately
```

## Identity model

The policy key is `(exe_sb_dev, exe_inode)`, read from
`task->mm->exe_file->f_inode`.

A process cannot lie about which binary it exec'd, which makes this stronger
than PipeWire's self-declared `application.name`. It also solves a real problem
on this machine: `/usr/bin/firefox` is a **shell script**, and two different
Firefox installs run here —

```
/usr/lib/firefox-esr/firefox-esr
/home/perieteanu/firefox-developer/firefox-bin
```

PipeWire reports both as `Firefox`. Inode keying tells them apart.

Known limit: a package upgrade replaces the binary and changes the inode, so a
rule silently stops matching. Mitigated in Phase 3 by periodic re-resolution.

## Device model

Match on **device major 81** (`video4linux`, confirmed in `/proc/devices`).
This covers `/dev/video0`, `/dev/video1`, and any webcam plugged in later
without enumerating paths. At this layer "device discovery" is major/minor —
not PipeWire's `media.class`.

## Build

Needs the eBPF toolchain (`clang`, `libbpf-dev`, `bpftool`, `libelf-dev`) and a
generated `src/bpf/vmlinux.h`:

```bash
~/projects/claude-run/hwprivacy-ebpf-toolchain-20260804.sh   # one time, needs sudo
cargo build
sudo ./target/debug/hwprivacy-lsm
```

`src/bpf/vmlinux.h` is generated from the running kernel's BTF. It is
machine-specific and is not committed.

### If the build fails with `libelf.h: No such file or directory`

The toolchain step above has not been run. `libbpf-sys` vendors libbpf's C
source and builds it, so it needs `libelf-dev` headers.

Note that this crate's own `build.rs` carries a friendly check for a missing
`vmlinux.h`, but you will not see it in this case: cargo runs *dependency*
build scripts first, so `libbpf-sys` fails before our guard ever executes.
A confusing wall of `fatal error: libelf.h` almost always means exactly one
thing — run the toolchain script.

This crate is **deliberately its own workspace** during Phase 1, so that
`cargo build --release --workspace` in the parent tree — which builds the
daemon currently running as a service — keeps working before the toolchain is
installed. It joins the parent workspace once Phase 1 compiles.

## Verification

```bash
sudo ./target/debug/hwprivacy-lsm &
ffmpeg -hide_banner -f v4l2 -i /dev/video0 -frames:v 90 -f null -
```

Phase 1 passes when the ffmpeg open appears with the correct exe path.
Phase 2 passes when that same command fails with `EPERM` for a denied binary.

## Layout

```
src/bpf/camera.bpf.c   the only C in the project (~100 lines)
src/event.rs           wire format shared with the C struct, hand-decoded + tested
src/main.rs            loader, ring buffer drain, exe resolution
build.rs               libbpf-cargo skeleton generation
```
