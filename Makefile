PREFIX ?= /usr
DESTDIR ?=

.PHONY: build install install-lsm clean deb doc-check check

build:
	cargo build --release --workspace

# Assert the docs do not contradict the code. Read-only, exits non-zero on a
# contradiction, so it works as a commit or deploy gate. See tools/doc-check
# for why each check exists — every one of them corresponds to a contradiction
# that actually occurred in this repo.
doc-check:
	@tools/doc-check

check: doc-check
	cargo test --workspace

install:
	install -D -m 0755 target/release/hwprivacy-daemon $(DESTDIR)$(PREFIX)/bin/hwprivacy-daemon
	install -D -m 0755 target/release/hwprivacy-ctl $(DESTDIR)$(PREFIX)/bin/hwprivacy-ctl
	install -D -m 0755 target/release/hwprivacy-tui $(DESTDIR)$(PREFIX)/bin/hwprivacy-tui
	install -D -m 0755 target/release/hwprivacy-gui $(DESTDIR)$(PREFIX)/bin/hwprivacy-gui
	install -D -m 0644 debian/hwprivacy-daemon.service $(DESTDIR)$(PREFIX)/lib/systemd/user/hwprivacy-daemon.service
	install -D -m 0644 dbus/org.hwprivacy.Daemon.service $(DESTDIR)$(PREFIX)/share/dbus-1/services/org.hwprivacy.Daemon.service
	install -D -m 0644 debian/hwprivacy-gui.desktop $(DESTDIR)$(PREFIX)/share/applications/hwprivacy-gui.desktop

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
