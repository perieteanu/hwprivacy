#!/usr/bin/env bash
set -uo pipefail

cat <<'BANNER'
═══════════════════════════════════════════════════════════════════════
 hwprivacy — does the ALSA backstop actually deny? (v2)

 The v1 probe asked ffmpeg, which could not tell a denial from a hang.
 This asks open() directly and prints the errno by name.

 HOW THIS ENDS: self-terminating, ~35 seconds. Every step is bounded by
                `timeout`. Restarts hwprivacy-lsm on any exit, including
                Ctrl-C. Nothing else stops it — no timer needed.

 RESULTS APPEAR: in THIS terminal, between the ==== markers. Nowhere else.

 WHAT TO DO: paste the marked block into the chat.
═══════════════════════════════════════════════════════════════════════
BANNER
[[ $EUID -ne 0 ]] && exec sudo -- "$0" "$@"

REPO=/home/perieteanu/projects/hwprivacy
BIN=$REPO/target/release/hwprivacy-lsm
PROBE=$REPO/target/openprobe
CAP=/dev/snd/pcmC0D0c
LOG=/tmp/hwp-probe2.log
POL=$(mktemp)

restore(){ rm -f "$POL"; systemctl start hwprivacy-lsm 2>/dev/null || true; }
trap restore EXIT INT TERM

gcc -o "$PROBE" "$REPO/tools/acceptance/openprobe.c" 2>/dev/null || {
  echo "cannot build the open() probe"; exit 1; }

# The probe runs as the USER: root is not what we are policing.
ask() { timeout 10 sudo -u perieteanu "$PROBE" "$CAP" 2>&1; }

echo "════ PASTE FROM HERE ════"
echo "probe v2 — $(date '+%H:%M:%S')"
echo "helper: $(date -r "$BIN" '+%Y-%m-%d %H:%M')"

systemctl stop hwprivacy-lsm 2>/dev/null; sleep 1
echo
echo "[1] BASELINE — nothing attached. open() must SUCCEED."
echo "    $(ask)"

echo
echo "[2] ENFORCING, pipewire allowlisted, the prober is NOT."
printf 'audio /usr/bin/pipewire\n' > "$POL"
timeout 30 "$BIN" --enforce-audio --policy-file "$POL" --duration 20 --json > "$LOG" 2>&1 &
H=$!
sleep 3
if ! kill -0 $H 2>/dev/null; then
  echo "    helper died early:"; head -20 "$LOG" | sed 's/^/      /'; exit 1
fi
echo "    minors: $(grep -o 'audio capture minors: .*' "$LOG" | head -1)"
echo "    open(): $(ask)"
echo "    ^ EACCES or EPERM here means the backstop WORKS."

echo
echo "[3] Same helper, prober ALLOWLISTED. open() must SUCCEED again —"
echo "    otherwise we are denying everything, not enforcing a policy."
kill $H 2>/dev/null; wait $H 2>/dev/null || true
printf 'audio /usr/bin/pipewire\naudio %s\n' "$PROBE" > "$POL"
timeout 30 "$BIN" --enforce-audio --policy-file "$POL" --duration 15 --json > "$LOG.2" 2>&1 &
H2=$!
sleep 3
echo "    open(): $(ask)"
kill $H2 2>/dev/null; wait $H2 2>/dev/null || true

echo
echo "[4] What the kernel recorded in step 2:"
echo "    denied:true count: $(grep -c '"denied":true' "$LOG" 2>/dev/null || echo 0)"
grep '"role":"AUDIO"' "$LOG" 2>/dev/null | tail -3 | sed 's/^/      /' || echo "      (no AUDIO events)"
echo "════ TO HERE ════"
