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

`git`: **uncommitted**. **172 tests**, all passing (was 78). 7 crates, 12234 LOC.

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
| **b6** *(found live)* prompts stacked forever | `Timeout::Never` said out loud, one pending prompt per (app, device) |
| **presets** | importable TOML rule sets + a desktop baseline `install` imports |
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

## The 2026-08-23 evening session: rules were unusable

The reboot landed and the PipeWire camera route came back (4 devices, camera row
present). Costin then deleted every rule, tried a Firefox video call, and could
not get the camera back. Three defects, all reproduced and all fixed.

```
16:05:23  Rule set: firefox → camera = allow
16:05:36  Kernel layer DENIED firefox-esr -> /dev/video0    ← 13 s, nothing said
```

| | |
|---|---|
| **`exe_path` was unwritable from any frontend** | `ctl rules set`, the GUI form and D-Bus `SetRule` all carried three fields. `kernel_camera_allowlist()` keys on **`exe_path` alone** — so no string typeable in the app field could ever grant a camera. Only a hand-edit could. |
| **The gap warning was unreachable** | `kernel_camera_gaps()` said exactly the right thing but ran only at connect time. The recheck loop could not fire it either: a rule with no `exe_path` contributes no allowlist entry, so `PolicyFingerprint` never changed → no re-push → silence. |
| **Two deny rules nobody asked for** | `set_rule` filled all three categories with `Deny`. Granting a camera silently downgraded the microphone from `ask` to a hard deny. `GetRules` then flattened each rule into three D-Bus rows, so one rule rendered as three. |
| **No autocomplete, and a lying placeholder** | App and device were bare `gtk::Entry` while permission got a `ComboBoxText`. The placeholder advertised `screen`, which `DeviceCategory::from_str` rejects. |

### The thing worth carrying forward

**One text field cannot hold two identities.** The PipeWire layer keys on a name
the app declares about itself (`firefox`); the kernel layer keys on an
executable (`/usr/lib/firefox-esr/firefox-esr`, short name `firefox-esr`).
Costin assumed he had typed the wrong name. He had not — *no* name would have
worked, because the field he was typing into is not the one the camera reads.

The fix makes both visible: `rules allow-camera <path> --as <rule>` and the
GUI's rule dropdown let **one** rule carry both, instead of leaving two rules
for one application.

### What landed

- `AppRule` categories are `Option<Permission>`. Unset → `default_action`,
  printed as `—`, never `deny`. Existing explicit denies are left alone
  (`d-a-rule-has-no-opinion-by-default`).
- D-Bus `SetRuleExe` and `AllowCamera`. `AllowCamera` is **atomic** — the
  halfway state is exactly what warns, so two calls made a successful grant
  announce a failure it was one call away from fixing. A refused path rolls the
  rule back.
- `rules denied-cameras` (the picker source — the kernel already logged the
  path) and `rules allow-camera`.
- Gap warnings: a notification the instant the rule is saved, plus annotations
  in `rules list`, `status`, and the TUI. `gap_delta()` reports only changes.
- `GetRules` → one row per rule with `exe_path` and a gap note. TUI gained a
  ←/→ column cursor, because a row is now a rule rather than a (rule, category).
- GUI: device dropdown, editable app combo, a **Camera denials** section with
  one-click grant.

### Verified live

```
rules set firefox cam allow   → config gains ONLY `camera = "allow"`
                              → WARN + "Announced kernel-gap warning" same ms
                              → rules list and status both flag it
rules allow-camera /usr/lib/firefox-esr/firefox-esr --as firefox
                              → gap closed, policy pushed, Allowed binaries: 1
rules allow-camera /nope/missing --as firefox
                              → nothing written, rule rolled back
```

**172 tests** (was 152). Every new one was run against the deliberately
reintroduced defect and observed to fail — and **two initially passed with the
defect present** and were rewritten: the serialisation test reintroduced the
wrong knob (`toml` omits `None` whatever `skip_serializing_if` says), and the
`set_rule_exe` guards overlap, so one test asserting all three proved none.

### The GUI finally has tests — `make gui-test`

`tools/gui-test` drives the running window over AT-SPI: selects the Rules tab,
reads every label **and placeholder**, clicks *Allow camera*, inspects the
dialog, cancels, and diffs the config. 14 checks. Plus one Rust widget test in
`hwprivacy-gui` for the dropdown model, which AT-SPI cannot read.

Deliberately **not** in `make check`: it needs a session bus, a running daemon
and a *mapped* window, and a gate that fails on a headless box teaches you to
skip the gate.

**Three of the checks were worthless when first written, and two of those
looked GREEN with the bug fully present.** In order of how much they should
worry a future reader:

- `no UI text offers 'screen'` — the `screen` placeholder was reintroduced,
  rebuilt, rerun: **passed**. The check scanned `label` nodes, and GTK does not
  expose a placeholder as one — it is the object attribute `placeholder-text`.
  The check was looking somewhere the defect could never be.
- Two `refresh_app_names` tests asserted that rebuilding the dropdown wipes what
  is being typed. **Measured instead**: `remove_all()` and `append_text()` leave
  a `with_entry` combo's text alone; only `set_active()` touches it. The
  save/restore code being tested could never fire, and was deleted — code
  guarding an impossible hazard reads as evidence the hazard is real.
- `one row per rule` failed first run with `gui=0 daemon=1` — the harness had
  parsed "**No** rules configured." into a rule named `No`. It now calls D-Bus
  instead of scraping CLI text.

Every check was then re-proven by reintroducing the real defect (the `screen`
placeholder; the device field reverted to free text), rebuilding, relaunching,
and watching the right line go red.

Two `doc-check` sentinels were added for the same two defects, because
`gui-test` cannot run headless and `doc-check` can. Both were verified to trip.

### Verified by Costin, at the screen

The two things no tree walk can see:

- The gap notification appears, carries the reason **and** the fix command
  (`Pick a binary with: hwprivacy-ctl rules denied-cameras`), and auto-dismisses.
- No label overlaps, truncates, or is unreadable.

### Late session: the ordinals and the per-stream concept both went

Two removals, both Costin's call after testing.

**`mic1`/`mic2` are gone** (`d-one-device-one-prompt`). They labelled two
CHANNELS of one microphone and called them two devices, and the exemption they
justified — the microphone alone was not coalesced — meant the second channel
hit the b6 guard and was denied on every single attempt. `group_links` now
coalesces by (category, device, stream) for all categories. Verified live:

```
before:  link 96 destroyed  -> microphone (mic1) -> ASKED
         link 90 destroyed  -> microphone (mic2) -> DENIED    (60 ms later)
after:   link 92 destroyed
         link 106 destroyed -> microphone -> ASKED            (both channels, one question)
```

Two REAL microphones still get two prompts — different nodes, and grouping
already keyed on that. `device_instance()` never could have helped there: it
compared sibling ports *within one node*.

**`ask_each` is gone** (`d-no-per-stream-grants`). It could never work — see the
ADR for the two structural reasons and the journal that shows the loop. The
string still parses, to `ask`, so an existing config does not stop the daemon
starting.

**`Hint::Resident(true)` is gone.** It kept the prompt on screen after the user
clicked an answer, which is exactly what the spec says `resident` does. It
survived the b6 fix because that fix targeted the TIMEOUT. Confirmed off the
session bus: hints went from `category, urgency, resident` to `category,
urgency`.

### ⚠ `while_in_use` is NOT implemented — decision pending

Found while answering Costin's direct question. `while_in_use_streams` is
written and **read nowhere**; `AccessAction::RevokedOnDisconnect` is **emitted
nowhere**; `evaluate` maps it to `Allow` under a comment claiming it tracks the
client lifecycle. It is a synonym for `allow` that the UI presents as a narrower
grant — the same lying-surface class this session removed everywhere else.

Removing `ask_each` took away the only grant machinery that could have made it
real. Options are in `ROADMAP > blockers > while_in_use_is_not_implemented`.
Costin asked to keep it pending a decision; it is still on every prompt.

### Also fixed, outside the plan

`~/.config/autostart/hwprivacy-gui.desktop` pointed at
`target/release/hwprivacy-gui` — the same trap the daemon was moved off in
August, where a rebuild swaps the binary underneath the live process. Now
`~/.local/bin/hwprivacy-gui`. The GUI was restarted from the installed path.

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

### 2. ~~Clean three dead rules~~ — DONE 2026-08-23

The live config is clean; `pipewire`/`wireplumber` carry `exe_path` entries.

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

### 5. README and MISSION — the publication blocker

Costin is publishing this on public GitHub. Both files state things that are
flatly false, and `doc-check` cannot catch either because it only reads files:

- **README** — says the helper is started by hand (boot-time service since
  2026-08-20) and that the default posture is `ask` (code default is `deny`
  since 2026-08-21). Known Limitations omits that the executable is the
  principal.
- **MISSION.yaml** — frozen 2026-08-04 22:37, still files the kernel layer
  under `what_would_fix_it`, in the conditional.

Add the credit line to README Credits at the same time.

### 6. The CPU regression

1.24 % of a core (2026-08-04) → 2.93 % (2026-08-21), same method, undiagnosed.
Costin rejected 1.2 % as "very generous", so publishing a number 2.4× worse
without an explanation is its own problem. Measure before proposing.

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

- **The staleness fix is still unverified against a live kernel.** b1 and b3
  were verified live on 2026-08-23; the acceptance script for staleness is
  written and shellcheck-clean but needs sudo and has not been run.
- **The microphone findings from this session are untouched, by Costin's
  decision.** Three of them, from reading the 18:46 video-call journal:
  `mic1`/`mic2` label the two CHANNELS of one stereo microphone and call them
  two microphones — `device_instance()` filters siblings by `node_id`, so two
  *physical* mics are two nodes and it can only ever label channels; the b6
  one-prompt-per-(app, device) rule then denies the second channel
  deterministically, every time; and it logs that at `debug!` while the service
  runs `RUST_LOG=info`, so the denial has no visible reason. Answering a prompt
  also never re-establishes the destroyed link — the app must retry.
- **The TUI has no tests.** It gained a column cursor this session and none of
  it is covered; `tools/gui-test` is GTK-only.
- **The live config still says `default_action = "ask"`.** The code default is
  now deny; his file sets it explicitly, so nothing changed underneath him.
- **`preset import --apply` was never run against the live config.** Previewed
  only. Applying it changes which processes may open the camera — Costin's
  call, not mine.
- **`v4l_id`** is denied at every boot and is deliberately NOT in the baseline.
  Whether that denial breaks anything is unknown.
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
