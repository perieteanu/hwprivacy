# HANDOFF — 2026-08-23 (three tranches)

Read this first, then `CLAUDE.md`, then `docs-yaml/ROADMAP.yaml`.

**Before trusting any doc in this repo, run `make doc-check`.** It is green as
of this commit, and it caught four real drifts during this session — including
the b1 anchor disappearing, which is what a *fixed* defect looks like to a gate
that only knows coordinates.

---

## What this session did

It started as "read the logs". Reading two days of live journals found a bug
nobody had seen, and reading the code for *that* found two more of the same
family. Three tranches followed: staleness + b1/b2/b4 + posture; then b3 and
the first tests `classify_link()` has ever had; then notify-on-allow and the
`offenders` → `history` rename.

`git`: **uncommitted**. **132 tests**, all passing (was 78). 7 crates, 10181 LOC.

### The find: enforcement silently stopped for sixteen hours

```
08-20 08:03:35  daemon pushes policy  → "2 executable(s) allowed"
08-20 08:05:16  dpkg: firefox-esr 140.13.0esr → 140.14.0esr   ← inode changes
08-20 09:45:14  DENIED /usr/lib/firefox-esr/firefox-esr  ino=30282365
08-20 18:10:14  DENIED   (same, 8.5 hours later)
08-21 08:42     reboot → helper reloads its cache → ALLOWED again
```

Throughout, `config.toml` said `camera = "allow"` and `hwprivacy-ctl status`
said `Allowed binaries: 2`. Both surfaces reported health while the feature was
dead. It repairs itself at the next boot, which is why it had never been seen.

Two more, found while fixing it — both worse, because neither needs an upgrade:

- **`SetPolicy` was sent only at connect time.** `set_rule`/`remove_rule` never
  poked the kernel layer, so changing a camera rule from `hwprivacy-ctl`, the
  TUI or the GUI did nothing until a restart. For layer 2, all three frontends
  were decorative.
- **`StreamInfo.object_serial` held `node.id`.** PipeWire's `object.serial` is
  never reused; a node id is reused freely. The name is why b2 read as a tuning
  issue rather than a grant landing on someone else's stream.

All three are one mechanism now: `PolicyFingerprint` in `lsm_client.rs`.

### Fixed

| | |
|---|---|
| **b1** dismiss wrote a permanent deny | `PromptOutcome` (Chosen/Dismissed/Failed) + the pure `notification::decide()` |
| **b1b** *(new)* a FAILED notification also wrote a deny | headless or no notify daemon → every prompt became a permanent deny |
| **b2** one-shot grants leaked | keyed on `(node_id, app)`, pruned every poll |
| **b4** dead rules | `sanitize_rule_name()` on write; `set_rule` returns false rather than storing junk |
| **posture** | `default_action` defaults to **deny** |
| **staleness** | s1/s2/s3 above |
| **b3** two identical prompts | split by category — see below |
| **allow path was silent** | `notify_allow.rs` gate + an `allowed` column in the history table |
| *incidental* | a test that had never run — `#[test]` was stacked twice on the function above it |

### b3: the reframe was half right

`d-per-microphone-identity` said "two links are two microphones, label them,
never coalesce". True for the microphone. **False for the playback monitor**,
and the live graph says so plainly:

```
node=46 Audio/Source   capture_FL(64), capture_FR(65)   ← two microphones
node=36 Audio/Sink     monitor_FL(61), monitor_FR(63)   ← two CHANNELS, one sink
```

So: **microphones get one prompt each, labelled `mic1`/`mic2`; a sink's channel
links get coalesced into one prompt.** The test is not "do the links look
alike" — they do, in both cases — it is "can the user meaningfully answer
differently for each".

Ordinals come from the sorted port **name**. Port ids are per-session; sorting
by id would silently move `mic2` to the other microphone after a reboot.

`classify_link()` finally has tests — 14 of them, including the one that never
existed: **ordinary playback into a sink must not be classified as a monitor
tap.** `d-monitor-tap-by-link-direction` rests entirely on that and nothing had
ever checked it.

Every new test was run against the deliberately reintroduced defect and observed
to **fail** before being kept. A test that passes both ways is worthless — and
this session produced one: the first direction-filter test passed with the
filter *removed*, because on this laptop `monitor_*` happens to sort before
`playback_*` and the coincidence hid the bug. Rewritten with a port that sorts
first. That is the entire argument for the discipline.

---

## What is running right now

| | |
|---|---|
| `hwprivacy.service` (user) | active, `NRestarts=0`, from `~/.local/bin/hwprivacy-daemon` |
| `hwprivacy-lsm.service` (system) | **active since 2026-08-20**, enabled, starts *before* the user daemon, enforcing from `/var/lib/hwprivacy/policy` |
| `hwprivacy-ctl/-tui/-gui` | in `~/.local/bin`, on `PATH` |

**Both tranches ARE deployed** — installed to `~/.local/bin` and the service
restarted on 2026-08-23. `hwprivacy-lsm` is unchanged and still the 08-20 build.

The previous binaries are backed up; to roll back:

```bash
install -m 0755 <scratchpad>/bin-backup/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/
systemctl --user restart hwprivacy
```

To redeploy after a rebuild:

```bash
cargo build --release --workspace
install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/
systemctl --user restart hwprivacy
```

The BPF program is still **never pinned** — stopping the service detaches it and
restores normal access.

---

## Pick up here — in this order

### 1. Run the staleness acceptance script

`~/projects/claude-run/hwprivacy-staleness-test-20260821.sh` proves the
staleness fix end to end against the live kernel. Needs `sudo`; it carries the
three-part banner. **The staleness fix is the one thing still unverified against
a running kernel** — b1 and b3 were verified live on 2026-08-23:

```
16:02:33  parecord -> microphone (mic1)  DENIED
16:02:33  parecord -> microphone (mic2)  DENIED     ← b3: distinguishable
16:02:59  parecord -> monitor            ASKED      ← one row, not two
config.toml byte-identical after an unanswered prompt  ← b1
```

### 2. Clean three dead rules out of the live config

`sanitize_rule_name()` stops *new* ones. The three already in
`~/.config/hwprivacy/config.toml` are still there and still dead:
`""`, `"Firefox [pipewire-pulse] (pid:2332)"`, `"pipewire [pipewire-pulse]"`.
**Stop the daemon first** — it rewrites the whole file on any rule change.

### 3. Decide whether the live config adopts deny-by-default

The code default changed; his config sets `default_action = "ask"` explicitly,
so nothing changed underneath him. Flipping it is a deliberate edit.

### 4. Verify notify-on-allow against a real camera access

Verified live for the PipeWire layer (two allowed monitor accesses, **one**
announcement — the cooldown works). The **kernel** allow path is unit-tested
only: it needs an allowed camera open, and `firefox-esr` is already
allowlisted, so opening any camera page more than a minute after login should
produce one `Announced allowed access` line and an `allowed` count in
`hwprivacy-ctl history`.

### 5. Decide what to do about b6 (found live, not fixed)

`Hint::Resident(true)` beats `timeout(60000)`, so an unanswered prompt never
expires: the cooldown never starts, the same app re-prompts on every new stream,
and popups stack. b1's fix holds — nothing is written — but the "ask again
later" half of the contract does not happen. Three options in
`ROADMAP > b6_resident_prompt_never_times_out`; all three are decisions.

### 6. Then: presets → README/MISSION for publication

See `ROADMAP.yaml > next_up`.

---

## Two findings that are not bugs

**The PipeWire camera route is dead system-wide.** `/usr/bin/pipewire` is denied
`/dev/video0` at every boot, so no camera node is created and the camera is
absent from `hwprivacy-ctl devices` entirely. Decided 2026-08-21: the shipped
default will allowlist `pipewire` **and** `wireplumber`, because that hands the
PipeWire camera route back to layer 1, which can attribute it per application —
something layer 2 structurally cannot do. Not implemented yet; see
`ROADMAP > next_up > presets`.

**Layer 1's idle CPU has roughly doubled.** 1.24 % of a core (2026-08-04) →
2.93 % (2026-08-21), same method; 3.03 % over the full 16 h session of 08-20.
The kernel helper over the same window: 0.04 %. Costin rejected 1.2 % as "very
generous". Undiagnosed — measure before proposing anything.

---

## The measurements that decided the architecture

```
ffmpeg -f v4l2 -i /dev/video0   → 90 frames captured, 0 events logged
ffmpeg -f alsa -i hw:0,0        → 3s of mic audio,    0 events logged
```

Hook cost: **+13.75 ns/open**, 95 % CI `[+7.3, +20.2]`, 1.88 % of a 733 ns
`open()`, **0 % at idle**.

---

## Traps that already bit

- **Inodes in documentation rot.** Four docs recorded firefox-esr as
  `ino=30287776`; it is `30282365` now. A hardcoded inode has a half-life of one
  `apt upgrade`.
- **Two `dev_t` encodings.** glibc's and the kernel's differ. Decoding one with
  the other's rules yields major 0 and silently matches *nothing* while unit
  tests pass. Bit twice. All conversion lives in
  `device_index::glibc_to_kernel_dev()`. The daemon's new fingerprint uses raw
  glibc values for *change detection only* and deliberately does not convert.
- **A field name can hide a bug.** `object_serial` holding a node id made b2
  unreadable for months.
- **An attribute can be silently absent.** `#[test]` stacked twice on one
  function left the next one dead. It compiled and read as covered.
- **`cargo test` does not refresh `target/debug/hwprivacy-lsm`.** It builds a
  separate `cfg(test)` harness. Test scripts must `cargo build` themselves.
- **D-Bus activation vs systemd.** Check `MainPID`, not `is-active`.
- **`/usr/bin/firefox` is a shell script.** The real binaries are
  `/usr/lib/firefox-esr/firefox-esr` and `~/firefox-developer/firefox-bin` —
  different inodes, different policy keys. That is the feature.
- **A camera session is 13 `open()` calls.** Coalescing collapses them to one
  event; the count is flushed separately.
- **`bpftool` lives in `/usr/sbin`**, off a non-root `PATH`.
- **`doc-check` only reads files.** It passed green all morning while four docs
  said the kernel helper is started by hand — it has been a boot-time service
  since 2026-08-20. Everything it cannot verify is a claim about the host.

---

## Deliberately NOT done

- **b6 is not fixed** — found while verifying b1; the fix is a decision, not a
  patch. See `ROADMAP > b6_resident_prompt_never_times_out`.
- **The staleness fix is still unverified against a live kernel.** b1 and b3
  were verified live on 2026-08-23; the acceptance script for staleness is
  written and shellcheck-clean but needs sudo and has not been run.
- **Three dead rules are still in the live config** — the code refuses new ones,
  the existing three need a manual clean with the daemon stopped.
- **The live config still says `default_action = "ask"`.** The code default is
  now deny; his file sets it explicitly, so nothing changed underneath him.
- **Presets** — next tranche, by agreement.
- **The tray in-use indicator.** notify-on-allow ships without it: there is no
  "camera released" event, so a dot would light and never go out.
- **Per-device rules.** b3 labels the microphones; it does not let you write
  `mic2 = deny`. Rules are still per category.
- **The CPU regression** — measured, not diagnosed.
- **`doc-check --host`** — agreed as worth building, not built.
- **README** — not rewritten. It still describes the helper as hand-started and
  carries a note saying the default posture is `ask`. Both are now wrong. This
  matters more than usual: publishing to a public repo is the stated goal.
- **MISSION.yaml** — still files the kernel layer under `what_would_fix_it`, in
  the conditional, and says nothing about the executable being the principal.
