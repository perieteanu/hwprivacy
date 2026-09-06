#!/usr/bin/env bash
set -uo pipefail

cat <<'BANNER'
═══════════════════════════════════════════════════════════════════════
 hwprivacy — install the Phase 5 helper and TURN THE BACKSTOP ON

 This changes your machine: from now on only allowlisted executables can
 open the microphone directly. Six are allowed (audio stack + VirtualBox).

 HOW THIS ENDS: self-terminating, ~40 seconds. Every step is bounded.
                It VERIFIES after enabling and tells you to roll back if
                verification fails. Nothing else stops it — no timer.

 RESULTS APPEAR: in THIS terminal, between the ==== markers. Nowhere else.

 WHAT TO DO: paste the marked block into the chat.

 TO UNDO, any time:
   sudo sed -i '/--enforce-audio/d' /usr/lib/systemd/system/hwprivacy-lsm.service
   sudo systemctl daemon-reload && sudo systemctl restart hwprivacy-lsm
═══════════════════════════════════════════════════════════════════════
BANNER
[[ $EUID -ne 0 ]] && exec sudo -- "$0" "$@"

REPO=/home/perieteanu/projects/hwprivacy
UNIT=/usr/lib/systemd/system/hwprivacy-lsm.service
PROBE=$REPO/target/openprobe
CAP=/dev/snd/pcmC0D0c

# Keep a copy of whatever is working now, and put it back on ANY failure.
#
# The camera is enforced by this service. A half-applied upgrade that leaves it
# crash-looping means the eBPF program is detached and the camera is
# UNPROTECTED — which is exactly what happened on the first attempt. Failing
# safe here means failing back to the state that was already working.
UNIT_BAK=$(mktemp); BIN_BAK=$(mktemp)
cp "$UNIT" "$UNIT_BAK" 2>/dev/null || true
cp /usr/bin/hwprivacy-lsm "$BIN_BAK" 2>/dev/null || true
OK=0
rollback() {
  if [[ $OK -eq 1 ]]; then
    rm -f "$UNIT_BAK" "$BIN_BAK"
    return 0
  fi
  echo
  echo "    !! aborting — restoring the previous helper and unit"
  systemctl stop hwprivacy-lsm 2>/dev/null || true
  [[ -s $BIN_BAK ]] && install -m 0755 "$BIN_BAK" /usr/bin/hwprivacy-lsm
  [[ -s $UNIT_BAK ]] && cp "$UNIT_BAK" "$UNIT"
  systemctl daemon-reload 2>/dev/null || true
  systemctl start hwprivacy-lsm 2>/dev/null || true
  sleep 2
  if systemctl is-active hwprivacy-lsm >/dev/null 2>&1; then
    echo "    restored: hwprivacy-lsm is active again (camera protected)"
  else
    echo "    *** COULD NOT RESTORE. Run: sudo systemctl restart hwprivacy-lsm"
  fi
  rm -f "$UNIT_BAK" "$BIN_BAK"
}
trap rollback EXIT INT TERM

gcc -o "$PROBE" "$REPO/tools/acceptance/openprobe.c" 2>/dev/null || {
  echo "cannot build the open() probe"; exit 1; }
ask(){ timeout 10 sudo -u perieteanu "$PROBE" "$CAP" 2>&1; }

echo "════ PASTE FROM HERE ════"
echo "enable backstop — $(date '+%H:%M:%S')"

echo
echo "[1] BEFORE: open() as an ordinary user"
echo "    $(ask)"

echo
echo "[2] Installing the Phase 5 helper and unit"
# STOP FIRST, and use `install`, not `cp`.
#
# `cp` writes THROUGH to the existing inode, which the kernel refuses while
# that binary is executing: "Text file busy". On 2026-09-06 that left the old
# binary in place while the new unit demanded --enforce-audio, and the service
# crash-looped with the eBPF program detached — i.e. the CAMERA was
# unprotected. `install` renames a new file over the old one, which is atomic
# and works on a running executable.
systemctl stop hwprivacy-lsm 2>/dev/null || true
sleep 1
install -m 0755 "$REPO/target/release/hwprivacy-lsm" /usr/bin/hwprivacy-lsm || {
  echo "    could not install the helper binary"; exit 1; }
cp "$REPO/debian/hwprivacy-lsm.service" "$UNIT"

# The binary must actually understand the flag the unit is about to pass. Order
# matters: verify BEFORE daemon-reload, so a mismatch never reaches systemd.
if ! /usr/bin/hwprivacy-lsm --help 2>&1 | grep -q -- --enforce-audio; then
  echo "    INSTALLED BINARY DOES NOT SUPPORT --enforce-audio — aborting"
  echo "    (the unit was NOT reloaded; restart the service to recover)"
  exit 1
fi
echo "    binary: $(date -r /usr/bin/hwprivacy-lsm '+%Y-%m-%d %H:%M')"
grep -q -- --enforce-audio "$UNIT" && echo "    unit carries --enforce-audio" \
                                   || { echo "    UNIT MISSING THE FLAG"; exit 1; }
systemctl daemon-reload
systemctl restart hwprivacy-lsm
sleep 4
systemctl is-active hwprivacy-lsm >/dev/null || {
  echo "    helper failed to start:"; journalctl -u hwprivacy-lsm -n 15 --no-pager | sed 's/^/      /'
  echo "    ROLL BACK — see the header."; exit 1; }
echo "    service: active"
systemctl --user restart hwprivacy 2>/dev/null || \
  sudo -u perieteanu XDG_RUNTIME_DIR=/run/user/1000 systemctl --user restart hwprivacy
sleep 5

echo
echo "[3] AFTER: the same open(), which must now be REFUSED"
echo "    $(ask)"
echo "    ^ 'Operation not permitted' = the bypass is closed."

echo
echo "[4] Is normal audio still working?"
PA="sudo -u perieteanu XDG_RUNTIME_DIR=/run/user/1000"
$PA pactl info >/dev/null 2>&1 && echo "    PipeWire responds: OK" \
                               || echo "    *** PipeWire DOES NOT RESPOND — roll back ***"
$PA pactl list short sources 2>/dev/null | head -3 | sed 's/^/      /'

echo
echo "[5] What hwprivacy reports"
$PA hwprivacy-ctl status 2>&1 | sed -n '/Kernel layer/,$p' | sed 's/^/      /'
echo "    --- helper journal ---"
journalctl -u hwprivacy-lsm --since "1 min ago" --no-pager 2>/dev/null \
  | grep -iE "backstop|capture minors|denied" | tail -4 | sed 's/^/      /'
OK=1
echo "════ TO HERE ════"
