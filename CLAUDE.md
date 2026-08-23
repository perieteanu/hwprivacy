# CLAUDE.md — hwprivacy

Android-style hardware permission manager for the Linux desktop. Gates native
(non-sandboxed) applications' access to **microphone**, **camera**, and
**playback monitor** across **two enforcement layers**: the PipeWire graph, and
an eBPF LSM in the kernel.

Rust workspace, **7 crates, 8814 LOC** (BPF C included; generated `vmlinux.h`
excluded). Debian 13 / PipeWire / KDE + GNOME.
Registered in project-tracker as `hwprivacy`, short name `hw`.

Verified against the filesystem and the live daemon on **2026-08-21**.
Run `make doc-check` before trusting any number in this file.

---

## Read first (all short, in this order)

0. **`HANDOFF.md`** — where the last session stopped, what runs right now, what
   to pick up, and the two decisions Costin has not made. Start here.
1. `docs-yaml/ROADMAP.yaml` — blockers, security gaps, `kernel_layer`, ordered
   next steps. **The most current doc in the repo** alongside HANDOFF.
2. `docs-yaml/DECISIONS.yaml` — settled ADRs. **Do not rehash.** Start at
   `d-kernel-lsm-layer`, which is the current direction.
3. `docs-yaml/ARCHITECTURE.yaml` — crates, both enforcement pipelines, D-Bus
   API, measured costs.
4. `docs-yaml/MISSION.yaml` — why it exists, threat model, what it is *not*.
   **Frozen 2026-08-04 22:37, minutes before the kernel pivot. Files the kernel
   layer under "what would fix it", in the conditional. That layer now exists.**
5. `docs-yaml/CONVENTIONS.yaml` — permission/device vocabulary, app-naming rules, config hazards.
6. `docs-yaml/PLAN-kernel-enforcement.md` — approved plan for the eBPF LSM layer.
   Manual copy of `~/.claude/plans/curried-swinging-scone.md`; **can drift**, there
   is no plan-mirror hook.
7. `docs-yaml/claude-memory.md` — auto-generated mirror of what Claude remembers.
   Read-only; edits there do not propagate back.
8. `README.md` — 26 KB. **Describes only layer 1**; zero occurrences of
   "kernel", "eBPF" or "LSM". Also wrong on behaviour (see below).
9. `PLAN.md` — original design doc, largely superseded by README.

---

## The one thing to know

**There are two layers, and neither is sufficient alone.** Measured by
experiment on 2026-08-04, not inferred:

- `ffmpeg -f v4l2 -i /dev/video0` captured 90 frames — **0 events logged**.
- `ffmpeg -f alsa -i hw:0,0` captured 3s of microphone — **0 events logged**.

Firefox and Chrome take the camera through V4L2 directly. PipeWire is never
involved, so the link-diff substrate has nothing to see. **That is what the
kernel layer was built to close**, and it works: Phase 2 acceptance 5/5, denied
live against Firefox and WhatsApp.

| | sees | blind to |
|---|---|---|
| **PipeWire layer** (`hwprivacy-daemon`) | *which app* wants the mic; the playback monitor | the camera entirely |
| **Kernel layer** (`hwprivacy-lsm`) | any `open()` of a camera/ALSA node, by inode | *which app* wants the mic — `/dev/snd` is held by `/usr/bin/pipewire` |

**The playback-monitor feature is unique to layer 1** — there is no
straightforward kernel-level way to tap a sink monitor. That is why layer 1 is
not merely legacy. Detail: `DECISIONS.yaml > d-kernel-lsm-layer` and
`ROADMAP.yaml > security_gaps` g5/g6.

**Layer 1 is feature-complete and has been running continuously.** Costin
reopened the project on 2026-08-04 not remembering that, and reported it
"didn't work properly". Both are true: all five planned phases existed and built
clean, but four behavioural defects made daily use unpredictable —
`ROADMAP.yaml > blockers` (b1–b4). **all four were fixed on
2026-08-21.**

**The kernel layer runs at boot.** `hwprivacy-lsm.service` is installed,
enabled, and starts before the user daemon, enforcing from
`/var/lib/hwprivacy/policy`. The BPF program is still **never pinned**, so
stopping the service detaches it and restores normal access. Docs written before
2026-08-20 say the helper is started by hand — they are wrong, and `doc-check`
cannot catch that because it only reads files.

---

## "Two-layer" means two different things — read this before using the phrase

| phrase in context | means |
|---|---|
| `d-kernel-lsm-layer` (2026-08-04) | **PipeWire + kernel.** The pivot. What this file means throughout. |
| `d-per-stream-gating` (2026-03-27) | **app-rule + per-stream gating.** A browser-tab problem, entirely inside layer 1. Predates the pivot by four months. |

That second ADR was **renamed on 2026-08-19 from `d-two-layer-model`** to kill
the collision. `DECISIONS.yaml` carries `renamed_from:`, so grepping the old id
still lands on it.

---

## Docs vs code — where README lies

README was realigned on 2026-08-19 and now leads with both layers, so the older
warning here ("zero mentions of the kernel") is itself retired. What it is
**still** wrong or silent about:

- D-Bus signals `AccessAttempt` / `StreamEvent` documented as API → declared but
  **never emitted**. (`RuleChanged` *is* emitted.) Frontends poll (TUI 1s, GUI 2s).
- Posture: README carries a note saying the default is `ask`. Since 2026-08-21
  the code default is **deny** (`d-deny-by-default`). The note and the example
  config both need updating.
- Known Limitations omits four real holes: links existing at daemon start are
  never evaluated, `BlockAll` does not stop anything already recording,
  **kernel enforcement cannot revoke an already-open fd** — the hook is on
  `open()`, not on read — and **the executable is the principal**, so allowing
  `firefox` allows every website that ever obtained a per-origin grant
  (`d-executable-is-the-principal`, measured live 2026-08-21).
- It describes `hwprivacy-lsm` as run by hand. It has been a boot-time systemd
  service since 2026-08-20.

Per the global rule: **once a project has code, verify a doc claim against the
filesystem or the running host, never against another document.** This project
is the cautionary example. Nothing here fails when a doc goes stale — there is
no `doc-check` gate yet.

---

## Live system facts (verify, don't assume — measured 2026-08-19)

```bash
systemctl --user status hwprivacy      # unit is hwprivacy.service, NOT hwprivacy-daemon.service
hwprivacy-ctl status
journalctl --user -u hwprivacy -f      # the defects are visible here, not just in code
```

- Daemon runs from **`~/.local/bin/hwprivacy-daemon`** (since 2026-08-04; it
  used to run out of `target/release/`, where a rebuild swapped the binary
  underneath the live service). **Four of the five binaries are installed
  there**; `hwprivacy-lsm` lives in **`/usr/bin`** and is started by systemd.
  **After rebuilding you must re-install for it to take effect:**
  `install -m 0755 target/release/hwprivacy-{daemon,ctl,tui,gui} ~/.local/bin/`
  then `systemctl --user restart hwprivacy`.
  `make install` (which targets `/usr/bin`, needs sudo) has never been run; no
  `.deb` has ever been built.
- Config: `~/.config/hwprivacy/config.toml`. The daemon **rewrites the whole
  file** on any rule change — comments and hand-formatting are destroyed.
  Stop the daemon before hand-editing.
- Measured idle cost of layer 1: `pw-dump` (272 KB JSON) twice a second.
  **1.24% of a core on 2026-08-04; 2.93% on 2026-08-21** (same method —
  cgroup CPU ÷ uptime; 3.03% over the full 16h session of 08-20). Costin
  rejected 1.2% as "very generous"; the regression is undiagnosed.
  The kernel helper over the same window: **0.04%**.
- Measured cost of layer 2: **+13.75 ns per `open()`**, 95% CI `[+7.3, +20.2]`
  — 1.88% of a 733 ns `open()`, and **0% at idle**.

---

## Build / run

```bash
cargo build --release --workspace       # or: make build
cargo check --workspace                 # 5 warnings, 0 errors
cargo clippy                            # NOT AVAILABLE — no such command on this toolchain
cargo test --workspace                  # 120 tests, all pass
```

Binaries (5): `hwprivacy-daemon` (layer 1 enforcer + policy owner),
`hwprivacy-lsm` (layer 2, **runs as root**), `hwprivacy-ctl` (CLI),
`hwprivacy-tui` (ratatui), `hwprivacy-gui` (GTK4 + tray). The three frontends
are pure D-Bus viewers with no authority.

Test coverage is **not** evenly spread:

| crate | tests |
|---|---|
| hwprivacy-lsm | 49 |
| hwprivacy-daemon | 50 |
| hwprivacy-common | 15 |
| hwprivacy-proto | 6 |
| hwprivacy-ctl / -tui / -gui | 0 |

`classify_link()` was covered on 2026-08-21 — 14 tests, including the one that
had never existed: that ordinary playback into a sink is **not** classified as a
monitor tap. `parse_node()`/`parse_link()` against real pw-dump JSON, and the
three frontends, remain uncovered.

**`cargo test` does not refresh `target/debug/hwprivacy-lsm`** — it builds a
separate `cfg(test)` harness. 30 passing tests once said nothing about the
binary being executed. Test scripts must `cargo build` themselves.

---

## Current direction (`d-kernel-lsm-layer`)

**The kernel layer is the direction.** Phases 1–4 have landed. Phase 3 closed
13/13 (C5 and D1 both resolved 2026-08-19). Phase 4's systemd unit is installed
and boot-verified. **Phase 5** (audio backstop) has not started — note its
shape: you cannot simply deny major 116, because that denies `/usr/bin/pipewire`,
which is every application's microphone path.

`d-event-driven-substrate` (replace `pw-dump` polling with `pipewire-rs`) is
**deferred and applies to layer 1 only**. It is not the current direction; it
merely happens to sit near the end of `DECISIONS.yaml`. No code has been
written for it.

Do **not** "fix" layer 1's CPU by raising `poll_interval_ms`. It is already a
config knob and needs no code, but it buys CPU by widening the race window —
the wrong trade for a security tool.

Layer-1 ordering, updated 2026-08-21: posture is **settled (deny)**, b1–b4 are
**all fixed**, and `classify_link()` is covered. What remains: notify-on-allow →
presets → README/MISSION for publication → only then touch the substrate.

---

## House rules specific to this repo

- **Git exists** (added 2026-08-04, 25 commits, `target/` ignored). It did not
  before, and older docs say "No git" — they are wrong.
- **No hardcoded values.** Global rule applies and is currently violated in ~7
  places (cooldowns, buffer sizes, notification timeouts, refresh intervals) —
  catalogued in `ROADMAP.yaml > debt`. Flag them when touching nearby code.
- **MSRV is whatever Debian 13 ships (rustc 1.85.0).** `notify-rust` is pinned
  to `=4.11.3` for this reason. Do not bump pinned crates or adopt newer
  language features without checking Debian.
- **Two prompts are not always a bug — it depends on the category.** Two mic
  links are two physical microphones and get one prompt each, labelled
  `mic1`/`mic2`. Two monitor links are two channels of one sink and get a
  single coalesced prompt. Applying either rule to the other category is what
  made b3 look unfixable. See `d-per-microphone-identity` + ROADMAP b3.
- **When you coalesce a prompt, never coalesce the teardown.** `LinkGroup`
  carries every link id for exactly this reason.
- **Prove a new test fails against the bug it catches**, before keeping it. Every
  test added on 2026-08-21 was run against the deliberately reintroduced defect
  and observed to fail. A test that passes both ways is worthless.
- **`tools/doc-check` carries regression SENTINELS** — source patterns that must
  never reappear. Add one only after a defect has actually shipped.
- **Write rules as the bare lowercase app name** (`firefox`, `obs`). Since
  2026-08-21 `set_rule()` sanitises this for you — a pasted `(pid:N)` label is
  cleaned, and a name that cannot become a key is REFUSED rather than stored.
  The **matcher** (`normalize_app_name`) is deliberately unchanged; only writes
  are sanitised. **Three dead rules still sit in the live config** — cleaning
  them is a manual step with the daemon stopped.
- **Two `dev_t` encodings.** glibc's `stat()` and the kernel's are different
  layouts. Decoding one with the other's rules yields major 0 and silently
  matches *nothing* — while unit tests pass. This bit twice. All conversion
  lives in `device_index::glibc_to_kernel_dev()`.
- `LOG.md` is append-only, global format:
  `DD-MM-YYYY HH:MM | DDD | hw | [TYPE] desc`.

---

## Don'ts

- Don't add features before `ROADMAP.yaml > blockers` is cleared — the project
  does not need more surface, it needs the surface it has to behave.
- Don't trust README on behaviour, and don't trust it at all on the kernel
  layer. Verify against the running daemon.
- Don't route kernel denials through the action-notification path. They use an
  *informational* notification with no buttons **on purpose** — the action path
  carries b1, and a new event source wired into it inherits that bug on day one.
- Don't claim the security model is stronger than it is: a process running as
  the same user can `systemctl --user stop hwprivacy`. The kernel layer raises
  the floor for the camera but is not pinned, so killing the root helper
  restores access. See `MISSION.yaml > threat_model`.
- Don't put explanatory comments in `config.toml` — they are wiped on the next
  rule change.
