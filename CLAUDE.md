# CLAUDE.md — hwprivacy

Android-style hardware permission manager for the Linux desktop. Gates native
(non-sandboxed) applications' access to **microphone**, **camera**, and
**playback monitor** by policing the PipeWire graph.

Rust workspace, 5 crates, 3434 LOC. Debian 13 / PipeWire / KDE + GNOME.
Registered in project-tracker as `hwprivacy`, short name `hw`.

---

## Read first (all short, in this order)

0. **`HANDOFF.md`** — where the last session stopped, what runs right now, what
   to pick up, and the two decisions Costin has not made. Start here.
1. `docs-yaml/MISSION.yaml` — why it exists, threat model, what it is *not*.
2. `docs-yaml/ARCHITECTURE.yaml` — crates, enforcement pipeline, D-Bus API, measured costs.
3. `docs-yaml/CONVENTIONS.yaml` — permission/device vocabulary, app-naming rules, config hazards.
4. `docs-yaml/DECISIONS.yaml` — settled ADRs. **Do not rehash.**
5. `docs-yaml/ROADMAP.yaml` — blockers, security gaps, `kernel_layer`, ordered next steps.
6. `docs-yaml/PLAN-kernel-enforcement.md` — approved plan for the eBPF LSM layer.
   Manual copy of `~/.claude/plans/curried-swinging-scone.md`; **can drift**, there
   is no plan-mirror hook.
7. `docs-yaml/claude-memory.md` — auto-generated mirror of what Claude remembers.
   Read-only; edits there do not propagate back.
8. `README.md` — 26 KB, accurate on **scope**, wrong on some **behaviour** (see below).
9. `PLAN.md` — original design doc, largely superseded by README.

---

## The one thing to know

**hwprivacy guards the PipeWire path, well. It is not a hardware permission
manager.** Measured by experiment on 2026-08-04, not inferred:

- `ffmpeg -f v4l2 -i /dev/video0` captured 90 frames — **0 events logged**.
- `ffmpeg -f alsa -i hw:0,0` captured 3s of microphone — **0 events logged**.

Firefox and Chrome take the camera through V4L2 directly. PipeWire is never
involved, so the link-diff substrate has nothing to see. The camera feature is
a placeholder; the microphone feature covers the common path but not the
threat. **The playback-monitor feature is real and unique** — there is no
straightforward kernel-level way to tap a sink monitor, so PipeWire is
genuinely the right layer for that one. Detail: `ROADMAP.yaml > security_gaps`
g5/g6 and `honest_coverage_2026_08_04`.

**It is also feature-complete and has been running continuously.** Costin
reopened it on 2026-08-04 not remembering that, and reported it "didn't work
properly". Both are true: all five planned phases exist and build clean, but
four behavioural defects made daily use unpredictable — `ROADMAP.yaml >
blockers` (b1–b4). The headline one: **dismissing a notification writes a
permanent `deny` rule** (`notification.rs:146`). Months of ignored popups
became policy the user never chose.

---

## Docs vs code — where README lies

README is the best single overview but predates the defects being found. It is
**correct** about what was built and **wrong** about:

- "Dismiss = no rule saved + 60s cooldown" → dismiss writes a permanent deny.
- D-Bus signals `AccessAttempt` / `StreamEvent` documented as API → declared but
  **never emitted**. Frontends poll (TUI 1s, GUI 2s).
- "Default policy: **deny all**" → the live config ships `default_action = "ask"`.
  Unresolved; see `d-posture-unsettled`.
- Known Limitations omits two real holes: links existing at daemon start are
  never evaluated, and `BlockAll` does not stop anything already recording.

Per the global rule: **once a project has code, verify a doc claim against the
filesystem or the running host, never against another document.** This project
is the cautionary example.

---

## Live system facts (verify, don't assume — measured 2026-08-04)

```bash
systemctl --user status hwprivacy      # unit is hwprivacy.service, NOT hwprivacy-daemon.service
hwprivacy-ctl status                   # or ./target/release/hwprivacy-ctl
journalctl --user -u hwprivacy -f      # the defects are visible here, not just in code
```

- Daemon runs from **`~/.local/bin/hwprivacy-daemon`** (since 2026-08-04; it
  used to run out of `target/release/`, where a rebuild swapped the binary
  underneath the live service). All four binaries are in `~/.local/bin`, which
  is on `PATH`. **After rebuilding you must re-install for it to take effect:**
  `install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/`
  then `systemctl --user restart hwprivacy`.
  `make install` (which targets `/usr/bin`, needs sudo) has never been run; no
  `.deb` has ever been built.
- Config: `~/.config/hwprivacy/config.toml`. The daemon **rewrites the whole
  file** on any rule change — comments and hand-formatting are destroyed.
  Stop the daemon before hand-editing.
- Measured idle cost: `pw-dump` (272 KB JSON) twice a second → **1.2% of a
  core**, 20.7 MB RSS. Costin has explicitly rejected this price.

---

## Build / run

```bash
cargo build --release --workspace       # or: make build
cargo check --workspace                 # clean: 5 warnings, 0 errors
cargo clippy                            # NOT AVAILABLE — no such command on this toolchain
cargo test                              # runs nothing — there are zero tests
```

Binaries: `hwprivacy-daemon` (the only enforcer), `hwprivacy-ctl` (CLI),
`hwprivacy-tui` (ratatui), `hwprivacy-gui` (GTK4 + tray). The three frontends
are pure D-Bus viewers with no authority.

---

## Current direction (set 2026-08-04, not yet implemented)

Three separate complaints — idle CPU, the ~500ms race window, and links being
grandfathered at startup — are **one root cause**: polling `pw-dump`. The
direction is to replace that substrate with event-driven `pipewire-rs` registry
callbacks, which fixes all three at once and leaves `policy_engine`, config,
D-Bus and all three frontends untouched. See `d-event-driven-substrate`.

Do **not** "fix" the CPU by raising `poll_interval_ms`. It is already a config
knob and needs no code, but it buys CPU by widening the race window — the wrong
trade for a security tool.

Ordering matters: settle the deny-vs-ask posture → fix blockers b1–b4 → write
the first tests → only then touch the substrate.

---

## House rules specific to this repo

- **No git.** 3.2 GB, almost all `target/`. There is currently no way to undo a
  bad edit. If git is added, `.gitignore target/` **before** the first commit.
- **No hardcoded values.** Global rule applies and is currently violated in ~7
  places (cooldowns, buffer sizes, notification timeouts, refresh intervals) —
  catalogued in `ROADMAP.yaml > debt`. Flag them when touching nearby code.
- **MSRV is whatever Debian 13 ships (rustc 1.85).** `notify-rust` is pinned to
  `=4.11.3` for this reason. Do not bump pinned crates or adopt newer language
  features without checking Debian.
- **`classify_link()` and `normalize_app_name()` hold the entire security
  decision** and have zero test coverage. They are pure functions. Any test work
  starts there.
- **Write rules as the bare lowercase app name** (`firefox`, `obs`). Never with
  `(pid:N)` — normalization does not strip it and the rule is dead on arrival.
  Three such dead rules exist in the live config right now.
- `LOG.md` is append-only, global format:
  `DD-MM-YYYY HH:MM | DDD | hw | [TYPE] desc`.

---

## Don'ts

- Don't add features before `ROADMAP.yaml > blockers` is cleared — the project
  does not need more surface, it needs the surface it has to behave.
- Don't trust README on behaviour. Verify against the running daemon.
- Don't claim the security model is stronger than it is: a process running as
  the same user can `systemctl --user stop hwprivacy`. Honest framing is
  "prevents accidental capture and gives visibility", not "enforces permissions
  against an adversary". See `MISSION.yaml > threat_model`.
- Don't put explanatory comments in `config.toml` — they are wiped on the next
  rule change.
