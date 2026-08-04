PREFIX ?= /usr
DESTDIR ?=

.PHONY: build install clean deb

build:
	cargo build --release --workspace

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
