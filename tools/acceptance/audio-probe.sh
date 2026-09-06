#!/usr/bin/env bash
set -uo pipefail
cat <<'BANNER'
═══════════════════════════════════════════════════════════════════════
 hwprivacy — why did the ALSA arm not deny? (diagnostic probe)

 HOW THIS ENDS: self-terminating, ~25 seconds. Restarts hwprivacy-lsm
                at the end. Nothing else stops it — no timer needed.

 RESULTS APPEAR: in THIS terminal, between the ==== markers.

 WHAT TO DO: paste the marked block into the chat.
═══════════════════════════════════════════════════════════════════════
BANNER
[[ $EUID -ne 0 ]] && exec sudo -- "$0" "$@"

REPO=/home/perieteanu/projects/hwprivacy
BIN=$REPO/target/release/hwprivacy-lsm
POL=$(mktemp); printf 'audio /usr/bin/pipewire\n' > "$POL"
LOG=/tmp/hwp-probe.log

restore(){ rm -f "$POL"; systemctl start hwprivacy-lsm 2>/dev/null || true; }
trap restore EXIT INT TERM

echo "════ PASTE FROM HERE ════"
echo "probe $(date '+%H:%M:%S')"
systemctl stop hwprivacy-lsm 2>/dev/null; sleep 1

echo
echo "[A] What userspace resolved, and what the KERNEL holds:"
"$BIN" --enforce-audio --policy-file "$POL" --dump-policy 2>&1 | grep -E "perms|policy as|empty|minors" | head -12

echo
echo "[B] Live run: is ffmpeg denied, and what does the helper record?"
"$BIN" --enforce-audio --policy-file "$POL" --duration 12 --json > "$LOG" 2>&1 &
H=$!
sleep 3
echo -n "    ffmpeg exit: "
sudo -u perieteanu ffmpeg -hide_banner -loglevel error -f alsa -i hw:0,0 -t 2 -f null - >/tmp/hwp-ff.txt 2>&1
echo "$?"
echo "    ffmpeg said:"; tail -2 /tmp/hwp-ff.txt | sed 's/^/      /'
wait $H 2>/dev/null

echo
echo "[C] Helper's own records (stderr banner + AUDIO events):"
grep -vE '^\{' "$LOG" | head -8 | sed 's/^/      /'
echo "    --- events ---"
grep '"role":"AUDIO"' "$LOG" | tail -4 | sed 's/^/      /'
echo "    denied:true count: $(grep -c '"denied":true' "$LOG")"
echo "════ TO HERE ════"
