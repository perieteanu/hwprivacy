PREFIX ?= /usr
DESTDIR ?=

.PHONY: build install clean deb doc-check check

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

clean:
	cargo clean

deb:
	dpkg-buildpackage -us -uc -b
