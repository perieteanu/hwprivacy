# CI: prove the install actually installs

## Context

CI went green today, but it only proves the code **builds and tests**. Nobody
has ever run `make install` — not once, on any machine. There is no `.deb`, no
release, and the README's install path has never been executed by anyone but
Costin, whose machine got there by accretion over months rather than by
following those steps.

A hosted runner *is* a clean stranger's machine. The part of "can someone
install this" that needs no VM, no reboot and no hardware is **staging the
install into a `DESTDIR` and checking the right files landed in the right
places with the right modes**. That is free, deterministic, and runs on every
push. This plan does exactly that half.

Deferred by explicit decision: `dpkg-buildpackage` / `.deb` (Costin wants to
talk about it first), and the VM that would test the reboot-and-attach story.

### A defect found while planning

`debian/hwprivacy-daemon.install` declares `usr/share/hwprivacy/presets/*.toml`,
but `debian/rules > override_dh_auto_install` **never stages the presets**. So
`dh_install` would fail to find them and `dpkg-buildpackage` would break. The
Makefile's `install` target *does* install them, so the two packaging manifests
disagree. This is a one-line fix and is included below, flagged separately so
it can be dropped if Costin wants it held for the `.deb` conversation.

---

## Approach

### 1. `tools/install-check` (new)

Python 3, imitating `tools/doc-check` exactly: module docstring with a
`WHY THIS EXISTS` section, `ROOT` derived from `__file__`, `ok()`/`fail()`
accumulators, two-space `ok` / `FAIL` output, `--json` flag, no `main()`.

**The expected file list is NOT written by hand.** It is parsed from
`debian/*.install`, which already declares every installed path and is a
human-visible file. Inventing a third manifest would create exactly the drift
this repo keeps getting bitten by. Glob lines (`usr/share/hwprivacy/presets/*.toml`)
are expanded against the staged tree and must match at least one file.

Checks:
- every declared path exists under `--destdir`
- **unexpected extras** — anything in the tree not declared, reported as a
  failure, so adding an install line without a manifest line is caught
- modes: `usr/bin/*` is `0755`, everything else `0644`
- the five binaries are non-empty and ELF

Exit codes follow `tools/gui-test`'s precedent: `0` pass, `1` real failure,
**`2` cannot run** (destdir missing or empty) — never a vacuous pass on an
empty tree.

Arguments via `argparse`, matching `tools/camera-accounting-check`:
`--destdir` (required), `--prefix` (default `/usr`, mirroring the Makefile).

### 2. `Makefile` — new `install-check` target

```make
install-check:
	@tools/install-check --destdir $(shell mktemp -d) ...
```
Staged into a temp dir by the target itself so it is environment-independent.
**Not added to `check`**, following the `gui-test` rationale already in the
Makefile: it needs `target/release/`, and a gate that fails where it cannot run
teaches you to skip the gate. Added to `.PHONY`.

### 3. `.github/actions/bpf-toolchain/action.yml` (new, local composite)

The new job needs the same apt deps + `vmlinux.h` generation + header-compile
gate the `test` job already has. Copy-pasting ~35 lines into a second job is
how these two copies drift apart. Extract the existing steps verbatim into a
local composite action and have both jobs `uses:` it. No behaviour change.

### 4. `.github/workflows/ci.yml` — new `install` job

Own job, outside the toolchain matrix (it does not need to run twice):

1. checkout (existing pinned SHA)
2. `./.github/actions/bpf-toolchain`
3. pinned `dtolnay/rust-toolchain` + `Swatinem/rust-cache`
4. `cargo build --release --workspace` — the install targets read from
   `target/release/`, which is why this cannot ride along on the debug matrix
5. `make install DESTDIR="$RUNNER_TEMP/stage"` and
   `make install-lsm DESTDIR="$RUNNER_TEMP/stage"`
6. `tools/install-check --destdir "$RUNNER_TEMP/stage"`
7. print the staged tree (`find`) so a human can eyeball it in the log

### 5. `debian/rules` — stage the presets (separable)

Add the missing line to `override_dh_auto_install`:

```make
	install -d debian/hwprivacy-daemon/usr/share/hwprivacy/presets
	install -m 0644 presets/*.toml debian/hwprivacy-daemon/usr/share/hwprivacy/presets/
```

Drop this item if the `.deb` is to stay untouched until we discuss it.

### 6. Docs

`CLAUDE.md` (CI section), `HANDOFF.md`, `LOG.md` — all gitignored, local only.
Note in `README.md` only if the install instructions themselves change; they
do not, so probably nothing.

---

## Files

| file | change |
|---|---|
| `tools/install-check` | new |
| `Makefile` | new `install-check` target + `.PHONY` |
| `.github/actions/bpf-toolchain/action.yml` | new; steps moved verbatim from `ci.yml` |
| `.github/workflows/ci.yml` | `test` job uses the composite; new `install` job |
| `debian/rules` | one missing install (separable — see above) |

## Verification

Local first, per house rule, then CI:

1. `cargo build --release --workspace`
2. `make install DESTDIR=/tmp/stage && make install-lsm DESTDIR=/tmp/stage`
3. `tools/install-check --destdir /tmp/stage` → expect pass
4. **Prove it fails** (`house_rule_prove_the_test_fails`), three separate ways,
   each reverted after:
   - delete one staged file → FAIL (missing)
   - `touch /tmp/stage/usr/bin/stray` → FAIL (undeclared extra)
   - `chmod 0644` a staged binary → FAIL (mode)
   Record the observed exit codes.
5. `tools/install-check --destdir /tmp/definitely-not-there` → exit **2**, not 0
6. `make doc-check` and `cargo test --workspace` still green
7. Push, watch the run, confirm all four jobs pass and the `install` job's
   printed tree looks right

## Out of scope

- `dpkg-buildpackage` / building a `.deb` — Costin wants to discuss first
- A VM, and anything needing a reboot, root, `bpf` in the LSM cmdline, or real
  camera/mic hardware
- `make install` on the real machine (still never run there, deliberately)
- The `install-lsm` `PREFIX` inconsistency: the system unit is hardcoded to
  `/usr/lib/systemd/system` while everything else honours `$(PREFIX)`. Probably
  correct for a systemd system unit, but noted rather than changed.
