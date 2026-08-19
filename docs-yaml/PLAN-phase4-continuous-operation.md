<!-- Manual copy of ~/.claude/plans/cheeky-seeking-clock.md, approved 2026-08-19.
     There is no plan-mirror hook, so this CAN DRIFT from the original.
     Status as of 2026-08-19 21:20 — stages 1, 3 and 4 verified live;
     stage 2 (the systemd unit) is written and committed but has NEVER been
     installed or booted. See ROADMAP.yaml > phase_4_stage_1_verified_2026_08_19. -->

# Phase 4 — continuous operation and a persistent audit trail

## Context

hwprivacy's kernel layer works — proven end-to-end on 2026-08-19, both
directions, with Costin's own Firefox-ESR. But **it only runs when a human
starts it by hand as root**, and everything it records dies with the terminal.

Costin's stated requirement:

> "i expect a long time usage with some logs that you'll visit later (after few
> days etc) and have a better grasp of who tried to connect etc"

That is not satisfied by a unit alone. Today the daemon's event log is a
500-entry **in-memory** ring buffer (g3) that dies on restart, its timestamps
carry **no date** (g4) so they are ambiguous across days, and the helper prints
to a terminal. Phase 4 therefore has two halves: the unit makes the helper
*run*, and persistence makes the running *worth anything*.

Decisions taken 2026-08-19:

| | choice |
|---|---|
| boot posture | **persist the allowlist, reload at boot** — protection live from boot, Firefox still works pre-login |
| scope | **unit + journal audit + offenders report** |
| BPF pinning | **stay unpinned** — stopping the service must restore the camera predictably |

## What I verified first (not assumed)

- `PolicyEntry` on the wire carries **`exe_path`, a path** — not `(dev, ino)`.
  So the cache stores paths and re-resolves inodes at boot. Storing inodes
  would go stale on the next Firefox package upgrade.
- The helper's allowlist comes **only** from `--allow` / `--policy-file` at
  startup. With neither, `--enforce` denies the camera to everything.
- The socket accept loop already handles reconnects correctly
  (`socket.rs:80`, "each accepted connection replaces the previous one").
- **Costin is in neither `adm` nor `systemd-journal`.** A *system* unit's
  journal is invisible to him today. This is the single biggest trap in the
  plan — the audit trail would exist and he could not read it.
- No `hwprivacy` group exists. `video` exists but contains **ollama** too, so
  it is not an acceptable owner for a socket that sets camera policy.
- Persistent journal is present and healthy: `/var/log/journal`, 323 MB,
  36 days retained, default retention.

## Stage 1 — the helper persists its own policy

**Why the helper and not the daemon:** the daemon runs unprivileged as the
user; `/var/lib` is root-owned. Having the root process read a user-writable
file introduces a TOCTOU/symlink surface for no benefit. The helper already
*receives* the policy over the socket, so it should own its own state.
The daemon needs no changes at all.

- `hwprivacy-lsm/src/main.rs`, `policy.rs`
  - new flag `--policy-cache PATH` (default `/var/lib/hwprivacy/policy`)
  - on `set_policy` from the socket: write the resolved `exe_path` list, one
    per line — the format `Policy::parse()` already reads
  - at startup: load it, exactly as `--policy-file` does today
  - write atomically (temp + rename) so a crash mid-write cannot leave a
    truncated allowlist that silently denies everything
- Precedence: explicit `--allow` / `--policy-file` override the cache, so the
  existing acceptance tests keep working unchanged.

Reuse `Policy::from_file()` / `Policy::parse()` (`hwprivacy-lsm/src/policy.rs`)
rather than inventing a format.

**Tests:** round-trip through the cache file; a corrupt/truncated cache must
fail loudly rather than silently yielding an empty allowlist (that failure mode
denies the camera to everything, which is exactly what it looks like when
enforcement is "broken").

## Stage 2 — the system unit

- New `debian/hwprivacy-lsm.service` (**system**, not user — the existing
  `hwprivacy-daemon.service` stays a user unit):
  ```
  ExecStart=/usr/bin/hwprivacy-lsm \
      --socket /run/hwprivacy/lsm.sock --socket-group hwprivacy \
      --policy-cache /var/lib/hwprivacy/policy --enforce --json
  Restart=on-failure
  ```
  No `--duration`. Not pinned, per the decision above.
- **Do not add `ProtectHome=`.** The helper must resolve executables under
  `/home` — `~/firefox-developer/firefox-bin` is a real allowlist target.
  Worth a comment in the unit so nobody "hardens" it into breaking.
- A dedicated **`hwprivacy` group** owns the socket; the desktop user joins it.
  Created in `debian/postinst`, and documented for the manual install path.
- `Makefile` + `debian/` currently install **neither** `hwprivacy-lsm` nor any
  system unit — `debian/hwprivacy-daemon.install` covers only the user unit.
  Add the binary, the unit, and a `debian/hwprivacy-lsm.install`.

## Stage 3 — make the audit trail readable

- **Fix g4** in `hwprivacy-daemon/src/stream_tracker.rs:log_event()` —
  timestamps are `"%H:%M:%S"` with no date. A log meant to be read "after a few
  days" is unusable without one. This is a one-line format change plus the
  column width in `hwprivacy-ctl`.
- `--json` to stdout means systemd captures one NDJSON object per event, with
  real timestamps, rotation and retention already solved. No storage code.
- **Add the user to `systemd-journal`** (postinst + documented). Without this
  the whole audit half is inaccessible to him — this must be an explicit,
  visible step, never a silent one.

Target queries, from the roadmap:
```
journalctl -u hwprivacy-lsm --since "3 days ago" | grep DENIED
journalctl -u hwprivacy-lsm --since "1 week ago" --output=cat   # raw NDJSON
```

## Stage 4 — `hwprivacy-ctl offenders`

Two tiers, deliberately:

- **The journal** is the complete raw record — every event, including
  pre-login, readable with group membership. Forensics.
- **Daemon-side counters** are the day-to-day view. Kernel events already reach
  the daemon over the socket (`lsm_client::handle_event`, proven tonight), so
  it aggregates per `exe_path` and persists to
  `~/.local/state/hwprivacy/offenders.json` — user-owned, no privilege needed,
  readable even without journal access.
- New D-Bus method `GetOffenders()` + `hwprivacy-ctl offenders`.

```
$ hwprivacy-ctl offenders
  EXECUTABLE                        DEVICE   DENIED  FIRST      LAST
  /usr/bin/signal-desktop           camera      12   Mon 14:02  Wed 19:40
  /usr/lib/firefox-esr/firefox-esr  camera       4   Wed 20:10  Wed 20:10
```

Aggregate over the structured events we already have — **do not regex-scrape
our own text output**, the trap ROADMAP calls out. Key on `exe_path`, which is
stable across restarts; the PipeWire layer's `(pid:N)` labels fragment into
noise over long windows (this is b4 getting worse with time).

The point is not catching hostile apps. It is the **discovery loop**: "signal
denied 12 times" means *add an exe_path*, which is the reverse of what
fail2ban is for and probably the more useful direction day to day.

**Documented gap:** the daemon only runs while the session is up, so its
counters miss pre-login events. The journal has those. Say so in the output
rather than letting the table look complete.

## Deferred — allow one microphone, deny the other

Measured, so the answer is definite rather than a guess:

- ALSA presents **one** capture device: `card 0 device 0` → `/dev/snd/pcmC0D0c`,
  one subdevice. The two mics are the **L and R channels of a single stereo
  stream**, not two devices.
- **Kernel layer: impossible.** The LSM hook fires on `open()` of one device
  node. There is no channel at `open()` time — you get the device or you don't.
- **PipeWire layer: possible.** The node exposes independently linkable ports
  `capture_FL` and `capture_FR` (verified via `pw-dump` and `pw-link -o`).
  Destroying one link and keeping the other is mechanically the same operation
  the daemon already performs.

Caveats that make this a design step, not a patch: the app receives a stereo
stream with one channel **silent**, not a mono mic, and behaviour varies by
app; which physical mic is FL vs FR depends on codec wiring and must be
determined empirically; and it interacts directly with **b3**, whose fix is to
*coalesce* per-channel links — the two features pull in opposite directions and
b3 should land first.

Not in this plan: the repo's own rule is "don't add features before the
blockers are cleared". Recording it in `ROADMAP.yaml` as a feasibility finding.

## Verification

1. `cargo test --workspace` — unit tests including the Stage 1 cache round-trip.
2. `make doc-check` — must stay green.
3. Cache: start the helper with `--policy-cache`, push a policy from the
   daemon, kill the helper, restart it **with no daemon running**, confirm via
   `--dump-policy` that the allowlist is present from the first instant.
4. Boot: reboot, and before logging in confirm the helper is active and
   enforcing with the cached allowlist.
5. End-to-end, with the existing rig: `tools/camera-accounting-check` must stay
   green, and the Firefox-ESR allow/deny pair must still behave as it did
   tonight.
6. Audit: after a few days, `journalctl -u hwprivacy-lsm --since "3 days ago"`
   returns real dated events, and `hwprivacy-ctl offenders` lists consumers.
7. Safety valve: `systemctl stop hwprivacy-lsm` → camera works again
   immediately.

## What this does NOT do

- Does not fix **b1–b4**. b3 in particular is what Costin experiences on every
  call (duplicate mic prompts, four popups seen tonight).
- Does not touch the **~51s reconnect delay** — parked by decision, recorded in
  ROADMAP as observed-not-diagnosed.
- Does not add **Phase 5** audio enforcement. Denying major 116 would deny
  `/usr/bin/pipewire`, i.e. every app's mic path; that needs its own design.
- Does not settle the **deny-vs-ask posture** (`d-posture-unsettled`).
- Does not add headless-Firefox or VLC as test subjects — on hold pending
  discussion.
