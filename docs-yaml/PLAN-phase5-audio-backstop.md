<!-- Manual copy of ~/.claude/plans/cheerful-jumping-ritchie.md.
     There is no plan-mirror hook, so this CAN drift from the original.
     Approved and IMPLEMENTED 2026-09-06; g6 closed the same evening.
     What the plan did not predict is recorded in ROADMAP > phase_5_audio_backstop:
     the desktop-baseline preset makes the DEFAULT config one where enforcing
     kills all audio, which is why audio_backstop_blocker() exists. -->

# Phase 5 — the ALSA microphone backstop

## Context

hwprivacy's microphone protection has a hole it has never covered, and the
project's own docs call it the largest one open: **an application that opens
ALSA directly bypasses hwprivacy entirely.** Measured 2026-08-04 and never
fixed — `ffmpeg -f alsa -i hw:0,0 -t 3` captured three seconds of real audio
with **zero** events logged. Layer 1 only sees applications that route through
PipeWire; the kernel layer sees the `open()` but has never denied audio
(`devices.bpf.c:237` — "ALSA is never denied here").

This is now the **only thing blocking publication**. The README was corrected
on 2026-09-06 to state the gap honestly (Known Limitations #1), and Costin's
decision was to hold publication until the gap is closed rather than ship a
tool that oversells the microphone.

**What this phase does NOT do, and must not claim to:** per-application
microphone policy at the kernel level is *impossible here*. `/dev/snd/pcmC0D0c`
is opened by `/usr/bin/pipewire` on every application's behalf, so the kernel
sees the audio server, not the app behind it. Per-app mic identity exists only
in layer 1. This phase delivers a **backstop**: only the audio stack may open a
capture device. That closes the bypass without claiming an attribution the
kernel cannot make.

## The observe-only census (done — this is what shaped the design)

The roadmap required an observe-only pass before denying anything. It has run,
against 30 days of the helper's own journal. Every capture-device consumer on
this machine, with inodes resolved:

| opens (30d) | binary | verdict |
|---|---|---|
| 27064 | `/usr/bin/wireplumber` | allowlist — audio stack |
| 10549 | `/usr/bin/pipewire` | allowlist — audio stack |
| 7032 | `/usr/lib/virtualbox/VirtualBoxVM` | **allowlist — decided 2026-09-06** |
| 692 | `/usr/sbin/alsactl` | allowlist — saves/restores mixer state at boot |
| 9 | `/usr/bin/amixer` | allowlist — audio stack |

Two facts that came out of the census and matter:

1. **Only one capture device exists here**: `pcmC0D0c`, minor 9, against five
   playback nodes. A minor-scoped rule is genuinely narrow — playback, control,
   seq and timer nodes are untouched.
2. **`VirtualBoxVM` opens capture devices directly.** This is exactly the
   "direct-ALSA application" risk `ROADMAP > phase_5_audio_backstop > risk`
   warned about, found live. Denying it would be a self-inflicted regression
   discovered mid-VM-call. It is allowlisted.

A caveat to carry into implementation: every AUDIO record in the journal is a
`burst_summary`, which carries **no device field**. The per-event records that
name the device are suppressed by coalescing. The census is trustworthy for
*which executables* (the emitter filters to `role.is_capture()` at
`main.rs:489`, so everything logged IS capture) but cannot break down by minor.

## Design

**Enforce on (capture minor) AND (exe not allowlisted for audio).** Never on
major 116 alone — that would deny `/usr/bin/pipewire` and take out every
application's microphone.

### 1. Kernel: a capture-minors map + the ALSA verdict arm

- New BPF map `capture_minors` (`BPF_MAP_TYPE_HASH`, key `__u32` minor, value
  `__u8`), mirroring the existing map declarations at `devices.bpf.c:127-176`.
- New verdict arm beside the camera one at `devices.bpf.c:230-237`:
  ```c
  else if (major == ALSA_MAJOR && cfg->enforce_audio) {
      __u32 minor = DEV_MINOR(rdev);
      if (bpf_map_lookup_elem(&capture_minors, &minor)) {
          __u32 *perm = bpf_map_lookup_elem(&policy, &pk);
          if (!perm || !(*perm & PERM_AUDIO)) { verdict = -EPERM; denied = 1; }
      }
  }
  ```
  `rdev` is already read at line 196 and `DEV_MINOR` already exists at line 45,
  so the minor costs nothing extra on the hot path.
- **Fail-open direction is deliberate and must be preserved:** a minor absent
  from `capture_minors` is not enforced. An unknown device is allowed, matching
  the existing `if (!cfg) return ret; // fail OPEN, never lock the user out` at
  line 220. A stale map under-blocks; it never locks the user out of audio.
- **Release tracking stays camera-only** (line 243, `major == V4L2_MAJOR`).
  Audio gets no sessions — same reasoning as `d-camera-is-allow-or-deny`, and
  there is no requirement for one here.

### 2. `struct config`: claim the `_pad` slot

`devices.bpf.c:99-103` is `{ u32 enforce_camera; u32 _pad; u64 coalesce_ns; }`.
`_pad` becomes `enforce_audio`, keeping the struct at **16 bytes** — no map
redefinition, no size change.

**This is the highest-risk edit in the phase**, because the Rust side has *no
`#[repr(C)]` mirror*: the struct is hand-assembled as `[0u8; 16]` in two
duplicated places (`main.rs:353-361` and `write_config` at `main.rs:803-808`),
with nothing asserting the layout. Contrast `DevEvent`, which has
`EVENT_SIZE = 56` plus a runtime drift check at `main.rs:466-472`.

Mitigations, both required:
- A single `fn config_bytes(enforce_camera, enforce_audio, coalesce_ns) -> [u8;16]`
  used by **both** writers, so the layout is expressed once.
- A test pinning the 16 bytes and each field's offset, mirroring
  `policy.rs:193-208` (`key_serialises_to_sixteen_bytes_with_zero_padding`).

### 3. Userspace: populate the minors map

- Add `DeviceIndex::capture_minors(&self) -> BTreeSet<u32>` in
  `device_index.rs`, iterating the private `map` for
  `k.0 == ALSA_MAJOR && v.role == DeviceRole::AudioCapture`. The classification
  work already exists (`classify()` at `device_index.rs:209-226`, tested at
  line 300); only the accessor is missing.
- **Hotplug staleness is a real gap and must be handled.** `rescan()` runs only
  in `new()` and lazily on a `lookup()` miss (`device_index.rs:144-150`) — that
  cannot help, because the kernel has already decided by then. Plug a USB mic
  and its minor is absent from the map, so it is silently unenforced.
  **Fix:** re-scan and re-push the minors map on every `SetPolicy`, and on the
  existing `exe_recheck_secs` tick. Cheap (a `/dev/snd` readdir), reuses a
  timer that already exists, and needs no new dependency — the same reasoning
  that rejected inotify in `policy_staleness_2026_08_21 > deliberately_not_inotify`.

### 4. Allowlist: audio entries carry `PERM_AUDIO`

**No wire-protocol change is needed for the allowlist.** `PolicyEntry` is
already `{ exe_path, perms: u32 }` (`hwprivacy-proto/src/lib.rs:44-53`), and
`Policy::to_map()` at `policy.rs:137-143` already ORs perms per inode
(`|= e.perms`), so a binary in both lists collapses to
`PERM_CAMERA|PERM_AUDIO` correctly.

- Add `Config::kernel_audio_allowlist()` in `hwprivacy-common/src/config.rs`,
  beside `kernel_camera_allowlist_with_sessions()` at line 698, filtering
  `r.microphone == Some(Permission::Allow)` with an `exe_path`.
- **No sessions for audio.** `while_in_use` is accepted for the microphone at
  layer 1 (`config.rs:511`, test at 1447) and stays working there, but it must
  **not** grant a kernel audio allowlist entry — that is the
  probe-close hazard (`config.rs:482-497`) in a new place. Only
  `Permission::Allow` reaches the kernel. This asymmetry needs a comment and a
  test, or someone will "fix" it later.
- `intended_policy()` (`lsm_client.rs:190-196`) merges both lists, OR-ing perms
  per path instead of the current 1:1 `perms: PERM_CAMERA`.

### 5. `PolicyFingerprint` — the silent-failure trap

`PolicyFingerprint` (`lsm_client.rs:116-137`) **discards `perms`**: `take()`
maps each entry to `(exe_path, stat_identity(path))` only. If a binary moves
between the camera and audio lists with no path change, the fingerprint
compares **equal and no re-push happens** — enforcement silently diverges from
`config.toml`. This is precisely the failure class the fingerprint exists to
prevent (its own doc comment at lines 92-114 describes the 16-hour silent
camera loss).

Required: add `perms` to the `files` tuple and an `enforce_audio` field, and
extend `describe_change()` (line 141-176, which special-cases `enforce_camera`
at 143-147). Mirror the existing test `toggling_enforcement_is_a_change`
(`lsm_client.rs:1027`).

### 6. The boot-window trap: the policy cache

`/var/lib/hwprivacy/policy` is **bare paths**, and `Policy::parse()` hardcodes
`perms: PERM_CAMERA` on reload (`policy.rs:104-108`; same at `allow_path()`
line 125). `render_cache()` (line 153) writes no perms column.

Left alone, every audio grant silently degrades to camera-only after a reboot,
during the window before the user session pushes `config.toml` — and with
`enforce_audio` on, **the audio server itself would be denied the microphone at
boot**. That is the worst possible failure in this phase.

**Fix:** extend the cache format to carry perms per line (e.g.
`camera,audio /usr/bin/pipewire`), with the bare-path form still parsing as
camera-only so an existing file keeps working. Round-trip test exists to mirror
at `policy.rs:214-228`.

### 7. Flags and config surface

- New `--enforce-audio` CLI flag on the helper (beside `--enforce`,
  `main.rs:89-91`), **defaulting off**.
- `Request::SetPolicy` gains `enforce_audio: bool` with `#[serde(default)]`, so
  no `PROTO_VERSION` bump — the precedent is `AccessEvent.released` at
  `lib.rs:132-133`. `Reply::Hello` gains `enforcing_audio` the same way.
- Daemon sources it from `devices.microphone` (`config.rs:308-315`), exactly
  mirroring `enforce_camera` ← `devices.camera` at `lsm_client.rs:199`.
- Three `SetPolicy` construction sites in `lsm_client.rs` (~254, ~292, ~334)
  must all be updated, or enforcement flips inconsistently.
- `presets/desktop-baseline.toml` gains the five census binaries with
  `microphone = "allow"` + `exe_path`.

## Files to change

| File | What |
|---|---|
| `hwprivacy-lsm/src/bpf/devices.bpf.c` | `capture_minors` map; `_pad` → `enforce_audio`; the ALSA verdict arm |
| `hwprivacy-lsm/src/main.rs` | `config_bytes()` helper + both writers; `--enforce-audio`; push minors map; thread `enforcing_audio` |
| `hwprivacy-lsm/src/device_index.rs` | `capture_minors()` accessor |
| `hwprivacy-lsm/src/policy.rs` | cache format with perms; `PERM_AUDIO` no longer dead |
| `hwprivacy-proto/src/lib.rs` | `SetPolicy.enforce_audio`, `Hello.enforcing_audio`, both `#[serde(default)]` |
| `hwprivacy-common/src/config.rs` | `kernel_audio_allowlist()` |
| `hwprivacy-daemon/src/lsm_client.rs` | merge both allowlists; fingerprint carries perms + `enforce_audio`; 3 SetPolicy sites |
| `presets/desktop-baseline.toml` | the five audio binaries |
| `tools/doc-check` | sentinel: `perms: PERM_CAMERA` must not return as the only construction |

## Verification

Staged deliberately — **one variable at a time**, which is Costin's rule and
has already paid off twice in this project.

1. **Unit** — `cargo test --workspace` (226 now). New tests, each **proven to
   fail against the defect it catches** before being kept:
   - `struct config` is 16 bytes with `enforce_audio` at offset 4
   - `capture_minors()` returns `{9}` here and never a playback minor
   - a `while_in_use` microphone rule does **not** reach the kernel allowlist
   - the fingerprint changes when a path moves camera→audio with no path change
   - the cache round-trips perms, and a bare-path line still parses as camera
2. **Observe-only on the live helper** — run with `--enforce-audio` absent and
   confirm the minors map is populated (`--dump-policy`) and that AUDIO events
   still report. Nothing denied.
3. **The acceptance test that defines success** — the harness already exists in
   `ROADMAP > verification_harness`, and its pass criterion is written:
   ```
   ffmpeg -hide_banner -f alsa -i hw:0,0 -t 3 -f null -
   ```
   must fail with **EPERM** for a non-allowlisted binary. Today it captures
   three seconds of audio. **This is the measurement that closes g6**, and it
   is the same command that opened it on 2026-08-04.
   Caution, from the harness: this records real audio (discarded to null).
4. **Non-interference, which is the real risk** — with enforcement on:
   - PipeWire audio keeps working (play something; `wireplumber`/`pipewire` are
     allowlisted)
   - a VM keeps its microphone (VirtualBoxVM allowlisted)
   - `alsactl` restore at boot is not denied — check the journal after a reboot
   - layer 1 mic prompts still behave (`e1` in the phase-3 criteria)
5. **Reboot** — the boot window is where the cache trap bites. Confirm the
   audio server is not denied the microphone before the user session comes up.

Needs `sudo`, so per the house rule steps 2-5 are scripted into
`~/projects/claude-run/` with the three-part banner (`HOW THIS ENDS`,
`RESULTS APPEAR`, `WHAT TO DO`) for Costin to run and paste back.

## Explicitly not in scope

- **Per-application microphone policy at the kernel layer.** Impossible —
  `/dev/snd` is held by the audio server. Stays in layer 1.
- **Audio sessions / `while_in_use` at the kernel layer.** Layer 1 keeps its
  working mic sessions; the kernel gets `allow`/`deny` only.
- **Denying playback, control, seq or timer nodes.** Capture minors only.
- **`hwprivacy-lsm` release tracking for audio.** Camera-only, unchanged.
- Docs (`README`, `MISSION`, `ROADMAP`) are updated **after** the acceptance
  test passes, not before — the doc/reality gap is this project's recurring
  defect.
