#!/usr/bin/env bash
set -euo pipefail

# hwprivacy Phase 5 — ALSA capture backstop acceptance test.
#
# Proves TWO things, and the second matters more than the first:
#   1. a non-allowlisted binary can no longer record the microphone
#   2. the audio stack still can  (i.e. we did not break all sound)

MARK_A="════ PASTE FROM HERE ════"
MARK_B="════ TO HERE ════"
CAP=/dev/snd/pcmC0D0c
REPO=/home/perieteanu/projects/hwprivacy
HELPER_BIN=$REPO/target/release/hwprivacy-lsm

cat <<'BANNER'
═══════════════════════════════════════════════════════════════════════
 hwprivacy — ALSA capture backstop acceptance test

 HOW THIS ENDS: self-terminating. Roughly 60-90 seconds, no input needed
                after your sudo password. It restores the previous state
                on exit, including on Ctrl-C or on failure.

 RESULTS APPEAR: in THIS terminal only, between the two marker lines.
                 Nothing appears in a GUI, a tray icon or a popup —
                 do not watch for one.

 WHAT TO DO: paste the block between the ==== markers into the chat.
═══════════════════════════════════════════════════════════════════════
BANNER
echo

if [[ $EUID -ne 0 ]]; then
  echo "This needs root (it restarts the LSM helper). Re-running under sudo…"
  exec sudo -- "$0" "$@"
fi

command -v ffmpeg >/dev/null || { echo "ffmpeg is required for this test."; exit 1; }

# Test the binary that was just BUILT, never the installed one. `cargo test`
# does not refresh the release binary either, so this is checked, not assumed —
# a stale binary has already cost this project a full test round.
[[ -x $HELPER_BIN ]] || { echo "Not built: $HELPER_BIN — run: cargo build --release --workspace"; exit 1; }
if ! "$HELPER_BIN" --help 2>&1 | grep -q -- --enforce-audio; then
  echo "FATAL: $HELPER_BIN has no --enforce-audio flag."
  echo "It predates Phase 5. Rebuild first:  cargo build --release --workspace"
  exit 1
fi
echo "helper under test: $HELPER_BIN  (built $(date -r "$HELPER_BIN" '+%Y-%m-%d %H:%M'))" 
[[ -e $CAP ]] || { echo "No capture device at $CAP — nothing to test."; exit 1; }

RESTORED=0
restore() {
  [[ $RESTORED -eq 1 ]] && return 0
  RESTORED=1
  echo
  echo "--- restoring the previous service state ---"
  systemctl restart hwprivacy-lsm 2>/dev/null || true
  sleep 2
  systemctl is-active hwprivacy-lsm >/dev/null 2>&1 \
    && echo "hwprivacy-lsm is active again." \
    || echo "WARNING: hwprivacy-lsm is NOT active — run: sudo systemctl restart hwprivacy-lsm"
}
trap restore EXIT INT TERM

# ffmpeg as the unprivileged user: root is not what we are policing, and a
# root-owned recording would also litter the user's session.
# Returns ffmpeg's OWN exit status, and leaves its output in $REC_OUT.
#
# The obvious `ffmpeg ... | tail -3` is a trap: in a pipeline the status is
# tail's, which is always 0, so the test would report the bypass CLOSED no
# matter what the kernel did. Assert on the thing under test, never on a proxy
# that has its own reason to succeed.
REC_OUT=""
rec() {
  local tmp rc
  tmp=$(mktemp)
  sudo -u perieteanu ffmpeg -hide_banner -loglevel error \
       -f alsa -i hw:0,0 -t 2 -f null - >"$tmp" 2>&1
  rc=$?
  REC_OUT=$(tail -3 "$tmp")
  rm -f "$tmp"
  return $rc
}

echo "$MARK_A"
echo "hwprivacy audio backstop — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "kernel: $(uname -r)"
echo

echo "[1] BASELINE — backstop off, ffmpeg should record fine"
systemctl stop hwprivacy-lsm 2>/dev/null || true
sleep 1
if rec; then
  echo "    ffmpeg exit 0 — recorded. (This is the hole, still open.)"
else
  echo "    ffmpeg FAILED with nothing attached:"
  echo "    $REC_OUT"
  echo "    Something else is holding the device; the rest of the test is meaningless."
  exit 1
fi
echo

echo "[2] ENFORCING — backstop on, allowlist = audio stack only"
POLICY=$(mktemp)
cat > "$POLICY" <<EOF
audio /usr/bin/pipewire
audio /usr/bin/wireplumber
audio /usr/sbin/alsactl
EOF
"$HELPER_BIN" --enforce-audio --policy-file "$POLICY" \
    --duration 25 --json > /tmp/hwp-backstop.log 2>&1 &
HELPER=$!
sleep 3

if ! kill -0 $HELPER 2>/dev/null; then
  echo "    helper exited early — the BPF verifier probably rejected the program:"
  sed -n '1,25p' /tmp/hwp-backstop.log
  rm -f "$POLICY"
  exit 1
fi

echo "    capture minors the helper found:"
grep -o 'audio capture minors: [^"]*' /tmp/hwp-backstop.log | sed 's/^/      /' || \
  echo "      (none reported — see the log below)"
echo

echo "    ffmpeg (NOT allowlisted) attempting to record:"
if rec; then
  echo "      *** FAIL — ffmpeg still recorded. The bypass is NOT closed. ***"
  VERDICT_DENY="FAIL"
else
  echo "      denied (ffmpeg exit non-zero):"
  echo "$REC_OUT" | sed 's/^/      /'
  # A denial must be EPERM specifically. ffmpeg also exits non-zero if the
  # device is busy or missing, which would look like a pass for the wrong
  # reason — the exact mistake that made an earlier phase's test meaningless.
  if echo "$REC_OUT" | grep -qiE "permission denied|operation not permitted"; then
    VERDICT_DENY="PASS"
  else
    VERDICT_DENY="INCONCLUSIVE — denied, but not with a permissions error"
  fi
fi
echo

echo "[3] NON-INTERFERENCE — is the audio stack still alive?"
# pactl talks to the user's session bus, so it needs XDG_RUNTIME_DIR. Without
# it `sudo -u` finds no socket and reports failure even though audio is
# perfectly healthy — a FALSE FAIL that made the 2026-09-06 20:37 run look like
# the backstop had broken sound. The instrument was wrong, not the product.
PA="sudo -u perieteanu XDG_RUNTIME_DIR=/run/user/1000"
if $PA pactl info >/dev/null 2>&1; then
  echo "      PipeWire/pulse responds: PASS"
  VERDICT_AUDIO="PASS"
else
  echo "      *** PipeWire/pulse does NOT respond — audio may be broken: FAIL ***"
  VERDICT_AUDIO="FAIL"
fi
$PA pactl list short sources 2>/dev/null | sed 's/^/      /' | head -4
echo

kill $HELPER 2>/dev/null || true
wait $HELPER 2>/dev/null || true
rm -f "$POLICY"

echo "[4] DENIAL RECORDS from the helper:"
grep -c '"denied":true' /tmp/hwp-backstop.log 2>/dev/null \
  | sed 's/^/      denied events: /' || echo "      (none)"
grep '"role":"AUDIO"' /tmp/hwp-backstop.log 2>/dev/null | tail -3 | sed 's/^/      /' || true
echo

echo "SUMMARY"
echo "  bypass closed (ffmpeg denied) : ${VERDICT_DENY:-UNKNOWN}"
echo "  audio stack unaffected        : ${VERDICT_AUDIO:-UNKNOWN}"
echo "  full helper log: /tmp/hwp-backstop.log"
echo "$MARK_B"
