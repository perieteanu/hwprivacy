# hwprivacy — kernel-level camera enforcement (eBPF LSM)

## Context

hwprivacy observes the PipeWire graph. On 2026-08-04 two experiments on the live
system proved that is not enough:

```
ffmpeg -f v4l2 -i /dev/video0 -frames:v 90   → 90 frames captured, 0 events logged
ffmpeg -f alsa -i hw:0,0      -t 3           → 3s of mic audio,     0 events logged
```

Firefox and Chrome take the camera through **V4L2 directly**. No PipeWire node,
no link, nothing for the link-diff substrate to see. The PipeWire camera node
never left `suspended` during the test. **Camera protection today is a
placeholder** — recorded as `docs-yaml/ROADMAP.yaml > security_gaps > g5`.

This is not fixable in the PipeWire layer. It needs a layer below it.

This machine already supports one, with no boot change:

```
/sys/kernel/security/lsm →  ...,apparmor,tomoyo,bpf,ipe,...   ← bpf is live
CONFIG_BPF_LSM=y   CONFIG_DEBUG_INFO_BTF=y   kernel 6.12   /sys/kernel/btf/vmlinux ✓
```

**Outcome:** a denied application's `open("/dev/video0")` returns `EPERM` from the
kernel, unbypassable from userspace, with the block surfacing in the existing
notification / event log / ctl / tui / gui with no frontend changes.

**Scope: camera only.** Audio is a separate feature (Costin's call, 2026-08-04) and
is deliberately out of scope here.

---

## What gets built

```
root:  hwprivacy-lsm.service  (NEW, system unit)
         ├─ loads camera.bpf.o → LSM hook security_file_open
         ├─ owns policy map + ring buffer
         └─ /run/hwprivacy/lsm.sock   0660 root:perieteanu
                   ▲
                   │  NDJSON: policy push ↓ / event stream ↑
                   ▼
user:  hwprivacy.service  (EXISTING, role unchanged)
         ├─ resolves config.toml rules → (dev, ino) keys
         ├─ feeds events into stream_tracker.log_event()
         └─ notifications via existing notification.rs

         → hwprivacy-ctl / -tui / -gui light up for free, unmodified
```

### Decisions taken (2026-08-04)

| Question | Answer |
|---|---|
| eBPF route | **libbpf-rs + one small C file.** Only apt deps; nothing touches the source-built rustc 1.85 or its Debian MSRV pin. |
| Camera UX | **Deny + informational notification.** Kernel denies immediately; the notification's Allow button updates policy; the app must retry. No pretending the kernel can wait. |
| Privilege split | **Root helper + unix socket** to the existing user daemon. Reuses all interactive machinery. |

### Key technical choices

- **Device identity = `major(file->f_inode->i_rdev) == 81`.** Major 81 is
  `video4linux` (confirmed in `/proc/devices`), so this covers `/dev/video0`,
  `/dev/video1`, and any future USB webcam without enumeration. This is the
  answer to "device discovery" at this layer — major/minor, not `media.class`.
- **App identity = `(exe_sb_dev, exe_inode)`** read from
  `task->mm->exe_file->f_inode` via CO-RE. Unspoofable (a process cannot lie
  about which binary it exec'd), stable across launches, and an exact-match
  hash lookup — the fastest thing available in a syscall path.
  It also solves a real problem: `/usr/bin/firefox` is a **shell script**, and
  two different Firefoxes run on this machine
  (`/usr/lib/firefox-esr/firefox-esr` and
  `/home/perieteanu/firefox-developer/firefox-bin`). PipeWire calls both
  `Firefox`; inode keying tells them apart.
- **Fail-open by design.** The BPF program is *not pinned*. If the helper dies
  or is stopped, the program is detached and the camera works normally. This is
  the escape hatch during development and it is deliberate.

---

## Phases

### Phase 0 — toolchain (needs your sudo)

Deliverable: `~/projects/claude-run/hwprivacy-ebpf-toolchain-20260804.sh`
(per that directory's README convention — I cannot run sudo).

```
apt install clang libbpf-dev bpftool libelf-dev zlib1g-dev
```
Then verify: `clang --version`, `bpftool version`, and generate
`vmlinux.h` from `/sys/kernel/btf/vmlinux`.

*~20 min, mostly download.*

### Phase 1 — observe-only spike

New crate `hwprivacy-lsm`, **logging only, denies nothing**.

- `src/bpf/camera.bpf.c` (~150 lines, the only C in the project):
  `SEC("lsm/file_open")`, filter major 81, guard `mm == NULL` (kernel threads),
  emit `{pid, tgid, comm, exe_dev, exe_ino, minor}` to a `BPF_MAP_TYPE_RINGBUF`,
  `return 0` always.
- `src/main.rs`: load via `libbpf-rs`, drain the ringbuf, resolve
  `/proc/<pid>/exe`, print a line per camera open.

Validates in one step: BPF LSM attaches on this kernel, CO-RE struct reads
work, ringbuf works. **And it measures what actually opens the camera on your
system** — which is the input to writing any policy at all.

Acceptance: run `ffmpeg -f v4l2 -i /dev/video0`, then a real camera app; both
appear with correct exe paths.

*~3–5 h — first eBPF program, skeleton build integration.*

### Phase 2 — enforcement

- Add `BPF_MAP_TYPE_HASH`: key `{u32 dev, u64 ino}` → value `u32` permission bits.
- Program returns `-EPERM` on miss (default-deny), `0` on an allowing entry.
- `--observe` flag retained to run without denying.
- Userspace seeds the map from a plain allowlist file before any integration.

Acceptance (the harness already written for the bypass tests):
`ffmpeg -f v4l2 -i /dev/video0` must fail with `EPERM` for a non-allowed binary
and succeed for an allowed one. Stopping the service must restore normal access.

*~2–3 h.*

### Phase 3 — integration with the existing daemon

- **Socket protocol**: newline-delimited JSON over `/run/hwprivacy/lsm.sock`.
  `serde_json` is already a workspace dependency — no new crate.
- **Config**: extend `AppRule` in
  [hwprivacy-common/src/config.rs](hwprivacy-common/src/config.rs) with
  `exe: Option<String>`. One rule then governs both layers — `app_name` for the
  PipeWire path, `exe` for the kernel path. Avoids a second rule table.
- **New module** `hwprivacy-daemon/src/lsm_client.rs`: connect, resolve each
  `exe` path to `(dev, ino)` with `std::fs::metadata`, push policy, read events.
- **Reuse, do not rebuild**: events go through the existing
  `StreamTracker::log_event()` and `notification::notify_blocked()`. Because
  ctl/tui/gui are pure D-Bus viewers of that state, **all three display kernel
  blocks with zero changes**.
- **Inode staleness**: a package upgrade changes the inode and silently breaks a
  rule. v1 mitigation — re-resolve on daemon start, on config change, and every
  30 s; log when a resolved inode moves.

*~4–6 h.*

### Phase 4 — systemd (minimal)

System unit for `hwprivacy-lsm`, socket dir with correct mode/group,
`ExecStart` with `--observe` togglable. No .deb, no packaging polish.

*~1 h.*

**Total ≈ 11–16 h.**

---

## Files

**New:**
- `hwprivacy-lsm/Cargo.toml`, `build.rs` (libbpf-cargo skeleton gen)
- `hwprivacy-lsm/src/bpf/camera.bpf.c` — the only C file
- `hwprivacy-lsm/src/main.rs`, `src/policy.rs`, `src/socket.rs`
- `hwprivacy-daemon/src/lsm_client.rs`
- `debian/hwprivacy-lsm.service`
- `~/projects/claude-run/hwprivacy-ebpf-toolchain-20260804.sh`

**Modified:**
- `Cargo.toml` — add the workspace member
- `hwprivacy-common/src/config.rs` — `AppRule.exe: Option<String>`
- `hwprivacy-daemon/src/main.rs` — spawn the lsm_client task
- `docs-yaml/ARCHITECTURE.yaml`, `DECISIONS.yaml`, `ROADMAP.yaml`, `CLAUDE.md`

**Untouched:** all three frontends, `policy_engine.rs`, `pipewire_monitor.rs`,
`link_manager.rs`, `notification.rs`.

---

## Verification

1. **Bypass harness** (already used to find the problem):
   `ffmpeg -hide_banner -f v4l2 -i /dev/video0 -frames:v 90 -f null -`
   — must return `EPERM` when denied, exit 0 when allowed.
2. **Snapshot deltas** before/during/after: hwprivacy event count, blocked
   count, `v4l2_fds_open`. A working layer moves the event count.
3. **Fail-open**: `systemctl stop hwprivacy-lsm` → camera works immediately.
4. **Frontends**: kernel blocks appear in `hwprivacy-ctl log`, the TUI Events
   panel, and the GUI Events tab, with no frontend code changed.
5. **Identity**: allow `firefox-esr` only; confirm the Developer Edition in
   `$HOME` is still denied. This is the check the PipeWire layer cannot pass.
6. **First tests in the workspace** (there are currently zero): pure-function
   coverage for exe-path → `(dev, ino)` resolution and the NDJSON protocol.

---

## Risks

| Risk | Mitigation |
|---|---|
| Locking yourself out of the camera | Program is never pinned; stopping the service detaches it. Phase 1 denies nothing at all. |
| Denying PipeWire or the loader itself | Phase 1 observe-mode reveals every camera-opening exe before any policy is written. |
| Verifier rejects the program | Keep the C minimal; no loops, no unbounded reads. This is why libbpf+C over Aya. |
| Inode changes on package upgrade | Periodic re-resolve + log on change. Documented as a known v1 limit. |
| `libbpf-rs` MSRV vs rustc 1.85 | Pin the version and verify it builds before writing the C. Cheap to check in Phase 0. |

---

## Explicitly out of scope

- **Audio / ALSA enforcement** (`g6`) — separate feature, separate plan.
- The four existing behavioural blockers b1–b4 (dismiss-writes-deny, stale
  one-shot grants, duplicate prompts, dead config rules). Untouched here.
- The deny-vs-ask posture question for the PipeWire layer — camera policy is
  static allow/deny and does not depend on it.
- The `pipewire-rs` event-driven substrate swap (`d-event-driven-substrate`).
- `git init`, portability, degradation tiers, .deb packaging, other distros.
