<!-- Manual copy of ~/.claude/plans/functional-wibbling-rainbow.md, taken
     2026-08-23 23:12. There is no plan-mirror hook, so this CAN drift.

     APPROVED AND DELIVERED, plus four things the plan did not cover, all
     decided by Costin during implementation and recorded as ADRs:
       d-one-device-one-prompt            mic1/mic2 deleted
       d-no-per-stream-grants             ask_each deleted
       d-while-in-use-is-a-session        while_in_use made real (layer 1)
       d-camera-sessions-via-file-release camera sessions via lsm/file_release
     Read DECISIONS.yaml, not this file, for what the code actually does. -->

# Make rules writable, honest, and discoverable

## Context

On 2026-08-23 Costin deleted every rule, tried a Firefox video call, and could
not get the camera back. Reproduced end to end:

```
16:05:23  Rule set: firefox → camera = allow
16:05:36  Kernel layer DENIED firefox-esr -> /dev/video0    ← 13 s later, silently
```

Four defects, all confirmed against the running daemon:

1. **`exe_path` is unwritable from any frontend.** `ctl rules set` takes three
   args, the GUI has three fields, D-Bus `set_rule` has three parameters.
   `kernel_camera_allowlist()` ([config.rs:444-450](../../projects/hwprivacy/hwprivacy-common/src/config.rs#L444))
   keys **only** on `exe_path`, so no string typeable in the app field can ever
   grant a camera. `exe_path` is settable only by hand-editing `config.toml`
   with the daemon stopped.
2. **The gap warning is unreachable.** `kernel_camera_gaps()` exists and says
   exactly the right thing, but it is only consumed in `session()` at connect
   time ([lsm_client.rs:217](../../projects/hwprivacy/hwprivacy-daemon/src/lsm_client.rs#L217)).
   The recheck loop computes gaps and **throws them away**
   ([lsm_client.rs:247](../../projects/hwprivacy/hwprivacy-daemon/src/lsm_client.rs#L247):
   `let (entries, want_enforce, _)`). It could not catch this case anyway:
   `PolicyFingerprint` is built from entries that *have* an `exe_path`, so a
   rule without one leaves the fingerprint unchanged → no re-push → no warning.
   Same failure class as the 2026-08-20 staleness bug, but worse: `rules list`
   affirmatively reports `camera allow`.
3. **Two deny rules nobody asked for.** `set_rule()` builds a whole `AppRule`
   with `default_deny()` on the two untouched categories. Granting a camera
   silently downgraded firefox's microphone from `ask` (via `default_action`)
   to a hard `deny`. `get_rules()` then explodes every rule into three D-Bus
   rows, so one rule renders as three in both frontends.
4. **No autocomplete, and a placeholder that lies.** `app_entry` and
   `dev_entry` are bare `gtk::Entry` while `perm_combo` is a `ComboBoxText`
   ([window.rs:87-97](../../projects/hwprivacy/hwprivacy-gui/src/window.rs#L87)).
   Device has exactly three valid values and gets free text. The placeholder
   reads `device (camera/microphone/screen/...)` — `screen` is not a category
   ([device.rs:38-41](../../projects/hwprivacy/hwprivacy-common/src/device.rs#L38)
   accepts only `microphone|mic`, `camera|cam`, `monitor|mon`).

**Outcome:** a camera grant is achievable from the GUI and the CLI without
knowing a path; a rule that cannot reach the layer it names says so loudly; and
setting one category stops writing opinions about the other two.

Decisions taken with Costin: pick the executable **from the kernel denial
list** (no manual path field); gap warnings are a **notification plus listing
annotations**; existing explicit denies are **left as-is**.

---

## Part 1 — `Option<Permission>` per category

`AppRule` in [hwprivacy-common/src/config.rs](../../projects/hwprivacy/hwprivacy-common/src/config.rs):

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub microphone: Option<Permission>,   // same for camera, monitor
```

Drop `fn default_deny()`. **The agreed migration falls out of serde for free** —
an existing `microphone = "deny"` still deserialises to `Some(Deny)`, so nothing
changes underneath any current config. New rules simply omit what was not set,
and the daemon's whole-file rewrite drops nothing that was there.

Callers to update (only 6 `AppRule {` sites, in `config.rs` and `preset.rs`):

- `AppRule::get_permission()` → returns `Option<Permission>`; callers resolve
  the fallback.
- `Config::get_permission(app, cat)` → resolves to the **effective** permission,
  falling back to `policy.default_action` when the rule has no opinion. This is
  the one used at [main.rs:462](../../projects/hwprivacy/hwprivacy-daemon/src/main.rs#L462).
- `set_rule()` → constructs with all three `None`, then sets the one category.
  Keep `sanitize_rule_name()` and the `false` return unchanged (b4).
- `rules_map()`, `kernel_camera_allowlist()` (`== Some(Permission::Allow)`),
  `kernel_camera_gaps()` (`Some(Deny) | None => None`).
- `preset.rs` conversion wraps in `Some(_)`; the shipped `presets/*.toml` set
  all three and are untouched. Leaving `PresetApp` non-optional is deliberate —
  see Not doing.

**Edge case to handle:** with `default_action = "allow"`, an unset camera means
allow at layer 1 and deny at layer 2 for *every* app. That is a global gap, not
a per-rule one — emit a single startup WARN rather than one per rule.

## Part 2 — `exe_path` becomes writable

New D-Bus method in [dbus_interface.rs](../../projects/hwprivacy/hwprivacy-common/src/dbus_interface.rs):

```rust
/// Attach (or clear, with "") the kernel-layer executable for an app's rule.
fn set_rule_exe(&self, app_name: &str, exe_path: &str) -> zbus::Result<bool>;
```

Returns `false` — following the b4 precedent of refusing rather than storing
something that can never work — when the app has no rule, the path is not
absolute, or the path does not resolve. Reuse `preset::path_exists()`
([preset.rs:239](../../projects/hwprivacy/hwprivacy-common/src/preset.rs#L239)).
Log the reason on every refusal.

Note the asymmetry, and keep it: a `camera = "allow"` with **no** `exe_path` is
refused nowhere, because it is the correct rule for a portal/Flatpak app that
takes the camera through PipeWire. It gets warned about (Part 3), never blocked.

CLI, in [hwprivacy-ctl/src/main.rs](../../projects/hwprivacy/hwprivacy-ctl/src/main.rs):

- `rules denied-cameras` — binaries the kernel has denied, from `get_history()`
  filtered to `source == "kernel" && device == "camera"`. This is the discovery
  surface; the data already exists.
- `rules allow-camera <PATH> [--as <APP>]` — sets `camera = allow` **and**
  `exe_path` in one call. `--as` defaults to `short_name(PATH)`.

Move `short_name()` from [lsm_client.rs:596](../../projects/hwprivacy/hwprivacy-daemon/src/lsm_client.rs#L596)
into `hwprivacy-common` so the CLI and GUI can derive the same suggestion.

No re-push plumbing is needed: adding an `exe_path` changes `PolicyFingerprint`,
and the existing 30 s recheck loop pushes it. Verify this rather than assume it.

## Part 3 — the gap becomes loud

**a. Recheck loop.** Capture the third element at
[lsm_client.rs:247](../../projects/hwprivacy/hwprivacy-daemon/src/lsm_client.rs#L247)
and hold `last_gaps` beside `fingerprint`. Warn only when the gap **set**
changes — warning every 30 s would flood the journal and train the reader to
ignore it.

**b. Notify at the moment of the mistake.** In `dbus_service::set_rule`, after a
successful save, recompute `kernel_camera_gaps()`; if this app is now in it,
show an **informational** notification. Route it through the kernel-denial
notification path, **never** the action path — per the house rule, the action
path carries b1 and a new source wired into it inherits that bug on day one.
Log the announcement (`info!`) as well as showing it: a popup is invisible to
every automated check, and C4 was scored wrong twice for exactly this reason.

**c. Richer `get_rules`.** One row per rule instead of three per rule:

```rust
/// (app_name, microphone, camera, monitor, exe_path, gap_note)
/// Permissions are "" when unset; exe_path "" when absent; gap_note "" when fine.
fn get_rules(&self) -> zbus::Result<Vec<(String, String, String, String, String, String)>>;
```

Three consumers, all in-repo: [ctl main.rs:227](../../projects/hwprivacy/hwprivacy-ctl/src/main.rs#L227),
[gui window.rs:371](../../projects/hwprivacy/hwprivacy-gui/src/window.rs#L371),
[tui app.rs:86](../../projects/hwprivacy/hwprivacy-tui/src/app.rs#L86).

`ctl rules list` becomes:

```
App          Mic        Camera   Monitor   Executable
firefox      ask_each   allow    —         (none)   ⚠ PipeWire only — kernel still denies
obs          —          allow    allow     /usr/bin/obs

—  follows default_action ("ask")
```

**d. `ctl status`** gains one line when gaps exist:
`Rules that cannot reach the kernel: 1 (see: hwprivacy-ctl rules list)`.

## Part 4 — GUI

[hwprivacy-gui/src/window.rs](../../projects/hwprivacy/hwprivacy-gui/src/window.rs), Rules tab:

- **Device** → `ComboBoxText` with `camera` / `microphone` / `monitor`. Delete
  the placeholder that advertises `screen`.
- **App** → `ComboBoxText::with_entry()` (gtk4 0.9.7, system GTK 4.18.6; matches
  the `ComboBoxText` already in the file), populated from existing rule names +
  active stream app names + pipewire-source history identities. Editable, so a
  new name is still typeable.
- **Rule rows** → render `exe_path` and the gap note inline, same wording as the
  CLI.
- **New "Camera denials" section** — the answer to "I had no chance to guess it".
  Lists kernel-denied binaries from `get_history()`, each with an *Allow camera*
  button. The button opens a small dialog to choose the rule the binary attaches
  to, defaulting to `short_name(path)` with a dropdown of existing rule names —
  so Costin can land it on the existing `firefox` rule instead of creating a
  second `firefox-esr` one. Then calls `set_rule` + `set_rule_exe`.

That dropdown is the fix for the deeper problem behind the complaint: the
PipeWire layer keys on a self-declared app name and the kernel layer keys on an
executable, and one text field cannot carry both. The dialog makes the two
identities visible and lets one rule hold both.

---

## Tests

House rule: **each new test is run against the deliberately reintroduced defect
and observed to fail** before being kept. A test that passes both ways is
deleted. Current baseline is 152 passing.

| test | reintroduce to prove it fails |
|---|---|
| an `AppRule` with only `camera` set serialises without `microphone`/`monitor` | restore `default_deny` |
| an old file with `microphone = "deny"` still loads as `Some(Deny)` | change to `#[serde(default)]` without `Option` |
| `set_rule` touches exactly one category | restore the three-field constructor |
| effective permission of an unset category is `default_action`, not deny | make `get_permission` return `Deny` on `None` |
| `kernel_camera_gaps` flags `Some(Allow)` + no exe_path, ignores `None` | drop the `None` arm |
| the gap set changing triggers a warn; unchanged is silent | drop the `last_gaps` comparison |
| `set_rule_exe` refuses relative path / missing file / unknown app | remove each guard in turn |
| `ctl` renders an unset category as `—`, not `deny` | render `Option::unwrap_or(Deny)` |

`cargo test` does not rebuild `target/debug/hwprivacy-lsm` — irrelevant here,
nothing in this plan touches the helper, but do not let a green run imply it.

## Verification (live, on this machine)

Negative case first — reproduce the original failure and see it now announce
itself:

```bash
hwprivacy-ctl rules set firefox cam allow
hwprivacy-ctl rules list      # expect: ⚠ PipeWire only — kernel still denies
hwprivacy-ctl status          # expect: Rules that cannot reach the kernel: 1
journalctl --user -u hwprivacy -n20 | grep -a "gap\|Announced"
```

Then the fix:

```bash
hwprivacy-ctl rules denied-cameras     # expect /usr/lib/firefox-esr/firefox-esr
hwprivacy-ctl rules allow-camera /usr/lib/firefox-esr/firefox-esr --as firefox
hwprivacy-ctl rules list               # exe_path shown, gap note gone
hwprivacy-ctl status                   # Allowed binaries: 1
journalctl --user -u hwprivacy -f      # "Kernel layer: 1 executable(s) allowed"
```

Then Costin opens a camera page in Firefox-ESR and confirms video, with
`Kernel layer ALLOWED firefox-esr` in the journal. Config check afterwards:
`grep -c 'deny' ~/.config/hwprivacy/config.toml` must not have grown.

GUI: launch `hwprivacy-gui`, confirm the device dropdown has three entries and
no `screen`, the app box lists known names, and the Camera denials section
grants a camera in one click.

None of this needs `sudo`, so I run all of it and report — except the two steps
that require a human at the screen (seeing the notification, seeing Firefox
video), which I will hand over with the three-part banner.

## Deliberately not doing

- **No manual exe-path text field** (Costin chose denial-list only).
  Consequence: pre-authorising a binary that has never been denied still needs
  a preset or a hand-edit. `presets/browsers.toml` already covers Firefox and
  Chrome via `exe_candidates`.
- **`PresetApp` stays non-optional.** Letting preset authors omit a category is
  a nice-to-have that widens the blast radius of Part 1 for no gain today.
- **No GUI tests.** The three frontends have 0 tests and this plan does not add
  a GTK harness — so Part 4 is verified by hand only. Stated because silence
  reads as done.
- **TUI untouched** beyond the `get_rules` signature. It is view-only.
- **The microphone findings from earlier today are not in this plan** — the
  false `mic1`/`mic2` split, the b6 suppression that denies the second channel,
  and the debug-level denial reason. Costin deferred those.
- **README / MISSION** — still the publication blocker, still not addressed.
- **The CPU regression** — untouched.
