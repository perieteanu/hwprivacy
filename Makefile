PREFIX ?= /usr
DESTDIR ?=

.PHONY: build install install-lsm install-check clean deb doc-check gui-test tui-screen check

build:
	cargo build --release --workspace

# Assert the docs do not contradict the code. Read-only, exits non-zero on a
# contradiction, so it works as a commit or deploy gate. See tools/doc-check
# for why each check exists — every one of them corresponds to a contradiction
# that actually occurred in this repo.
doc-check:
	@tools/doc-check

# Drive the running GUI over AT-SPI and assert what the window actually says.
#
# NOT part of `check`, on purpose. It needs a session bus, a running daemon and
# a MAPPED hwprivacy-gui window — a gate that fails on a headless box teaches
# you to skip the gate, which is the failure mode tools/doc-check exists to
# prevent. Run it deliberately, after touching the GUI.
gui-test:
	@tools/gui-test

# Not a pass/fail gate — it prints what the TUI actually looks like, which is
# more than existed before. The TUI has no tests at all.
tui-screen:
	@tools/tui-screen $(PANEL)

check: doc-check
	cargo test --workspace

# Prove `make install` puts the declared files in the declared places.
#
# Stages into a throwaway DESTDIR and compares the result against
# debian/*.install — the manifest this repo already has, rather than a third
# hand-written list that would only drift from the other two.
#
# NOT part of `check`, same reasoning as gui-test: it needs target/release/,
# and a gate that fails where it cannot run teaches you to skip the gate.
# Run it after touching the install targets or debian/*.install.
install-check:
	@d=$$(mktemp -d); \
	  { $(MAKE) --no-print-directory install DESTDIR=$$d && \
	    $(MAKE) --no-print-directory install-lsm DESTDIR=$$d; } >/dev/null && \
	  tools/install-check --destdir $$d; \
	  rc=$$?; rm -rf $$d; exit $$rc

install:
	install -D -m 0755 target/release/hwprivacy-daemon $(DESTDIR)$(PREFIX)/bin/hwprivacy-daemon
	install -D -m 0755 target/release/hwprivacy-ctl $(DESTDIR)$(PREFIX)/bin/hwprivacy-ctl
	install -D -m 0755 target/release/hwprivacy-tui $(DESTDIR)$(PREFIX)/bin/hwprivacy-tui
	install -D -m 0755 target/release/hwprivacy-gui $(DESTDIR)$(PREFIX)/bin/hwprivacy-gui
	install -D -m 0644 debian/hwprivacy-daemon.service $(DESTDIR)$(PREFIX)/lib/systemd/user/hwprivacy-daemon.service
	install -D -m 0644 dbus/org.hwprivacy.Daemon.service $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.hwprivacy.Daemon.service
	install -D -m 0644 debian/hwprivacy-gui.desktop $(DESTDIR)$(PREFIX)/share/applications/hwprivacy-gui.desktop
	install -d $(DESTDIR)$(PREFIX)/share/hwprivacy/presets
	install -m 0644 presets/*.toml $(DESTDIR)$(PREFIX)/share/hwprivacy/presets/

# The kernel layer, installed separately and ON PURPOSE.
#
# It runs as root and denies the camera by default, so pulling it in silently
# with the rest of the tool would change the machine's behaviour in a way
# nobody asked for. It is also the only component with a kernel requirement
# (CONFIG_BPF_LSM=y, CONFIG_DEBUG_INFO_BTF=y, 'bpf' in /sys/kernel/security/lsm).
install-lsm:
	install -D -m 0755 target/release/hwprivacy-lsm $(DESTDIR)$(PREFIX)/bin/hwprivacy-lsm
	install -D -m 0644 debian/hwprivacy-lsm.service $(DESTDIR)/usr/lib/systemd/system/hwprivacy-lsm.service
	@echo
	@echo "hwprivacy-lsm installed. Three steps remain, none of them automatic:"
	@echo
	@echo "  sudo addgroup --system hwprivacy"
	@echo "  sudo adduser \$$USER hwprivacy          # to push policy to the kernel"
	@echo "  sudo adduser \$$USER systemd-journal    # to READ the audit trail"
	@echo "  sudo install -d -m 0755 /var/lib/hwprivacy"
	@echo "  sudo systemctl daemon-reload && sudo systemctl enable --now hwprivacy-lsm"
	@echo
	@echo "Log out and back in for the group changes to take effect."
	@echo "Stopping the service restores camera access immediately — it is never pinned."
	@echo

clean:
	cargo clean

deb:
	dpkg-buildpackage -us -uc -b
