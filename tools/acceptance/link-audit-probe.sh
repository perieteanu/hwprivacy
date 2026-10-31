#!/usr/bin/env bash
# Prove, against the running daemon, that every link leaves a trace and that a
# denied link really stops. See DECISIONS.yaml > d-every-link-is-accounted-for.
#
# Needs two rules that already exist, so nothing is changed to run it:
#   --denied NAME   a rule with monitor = deny
#   --allowed NAME  a rule with monitor = allow
#
# What it does to the machine: short captures of the default sink's monitor to
# /dev/null under those names, silent playback, and one stop and start of the
# user daemon (the kernel helper is not touched). It never opens a microphone and
# writes no audio anywhere. Desktop popups will appear; none needs a click.
#
# Cannot be exercised here: a destroy that fails. That path is unit-tested.
#
# Leaves behind: history rows for those names, and identities.json pairs joining
# each name to pw-cat, because that is what the probe truthfully declares. Harmless
# unless a rule owns the pw-cat binary, and a fair picture of how little a name is.
#
#   --check   prerequisites only, through the same code, changing nothing
set -euo pipefail

DENIED_ID=""
ALLOWED_ID=""
CHECK_ONLY=no
TRIALS=3
CTL="${HWPRIVACY_CTL:-hwprivacy-ctl}"
UNIT=hwprivacy
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/hwprivacy/config.toml"

while [ $# -gt 0 ]; do
    case "$1" in
        --denied) DENIED_ID="$2"; shift 2 ;;
        --allowed) ALLOWED_ID="$2"; shift 2 ;;
        --check) CHECK_ONLY=yes; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

result() { echo; echo "RESULT: $*"; }

# Never `ctl | grep -q`: grep exits at its match, ctl panics printing the next
# line, and pipefail reports a healthy daemon as failed. Capture, then match.
daemon_up() {
    local status devices
    status="$(timeout 3 "$CTL" status </dev/null 2>/dev/null)" || return 1
    devices="$(timeout 3 "$CTL" devices </dev/null 2>/dev/null)" || return 1
    [[ "$status" =~ Connected:\ *yes ]] || return 1
    [[ $'\n'"$devices" == *$'\n'"monitor "* ]] || return 1
}

wait_for_daemon() {
    local _
    for _ in $(seq 1 30); do
        if daemon_up; then return 0; fi
        sleep 0.5
    done
    return 1
}

rule_says() { # app, expected monitor permission
    python3 -c '
import sys, tomllib
app, want = sys.argv[1:3]
rules = tomllib.load(open(sys.argv[3], "rb"))["rules"]
sys.exit(0 if any(r["app_name"] == app and r.get("monitor") == want for r in rules) else 1)
' "$1" "$2" "$CONFIG"
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Link ids currently feeding a node that declares this application name.
cat >"$WORK/links.py" <<'PY'
import json, sys
name = sys.argv[1]
d = json.load(sys.stdin)
nodes = {o["id"] for o in d if o.get("type", "").endswith("Node")
         and o["info"]["props"].get("application.name") == name}
print(" ".join(str(o["id"]) for o in d if o.get("type", "").endswith("Link")
               and o["info"]["input-node-id"] in nodes))
PY

# Every link in an independent capture must have its line in the daemon's journal.
# Prints: links, missing, then up to five of the missing.
cat >"$WORK/account.py" <<'PY'
import json, re, sys
stream, journal = sys.argv[1], sys.argv[2]
text = open(stream).read()
dec, i, links, first = json.JSONDecoder(), 0, set(), True
while True:
    while i < len(text) and text[i].isspace():
        i += 1
    if i >= len(text):
        break
    try:
        block, i = dec.raw_decode(text, i)
    except ValueError:
        break
    if not first:
        for o in block:
            if o.get("type", "").endswith("Link") and o.get("info"):
                serial = o["info"].get("props", {}).get("object.serial")
                if serial is not None:
                    links.add((o["id"], serial))
    first = False
lines = open(journal).read()
missing = sorted(l for l in links if f"Link {l[0]} serial {l[1]}:" not in lines)
print(len(links), len(missing), " ".join(f"{a}/{b}" for a, b in missing[:5]))
PY

check_prereqs() {
    local bad=0 c
    for c in pw-record pw-play pw-dump pactl python3 journalctl "$CTL"; do
        command -v "$c" >/dev/null || { echo "missing command: $c"; bad=1; }
    done
    if [ -z "$DENIED_ID" ] || [ -z "$ALLOWED_ID" ]; then
        echo "--denied and --allowed are required"
        return 1
    fi
    rule_says "$DENIED_ID" deny || { echo "no rule '$DENIED_ID' with monitor = deny"; bad=1; }
    rule_says "$ALLOWED_ID" allow || { echo "no rule '$ALLOWED_ID' with monitor = allow"; bad=1; }
    SINK="$(timeout 5 pactl get-default-sink </dev/null)" || { echo "no default sink"; bad=1; }
    daemon_up || { echo "the daemon is not up, or not connected to the kernel helper"; bad=1; }
    # The instrument itself, against a known answer, before it is trusted.
    printf '[{"id":1,"type":"PipeWire:Interface:Node","info":{"props":{}}}]\n' >"$WORK/c.json"
    printf '[{"id":90,"type":"PipeWire:Interface:Link","info":{"props":{"object.serial":5}}},{"id":91,"type":"PipeWire:Interface:Link","info":{"props":{"object.serial":6}}}]\n' >>"$WORK/c.json"
    echo "Link 90 serial 5: a -> b" >"$WORK/c.log"
    [ "$(python3 "$WORK/account.py" "$WORK/c.json" "$WORK/c.log")" = "2 1 91/6" ] \
        || { echo "the accounting check gives the wrong answer on its own control"; bad=1; }
    return "$bad"
}

if [ "$CHECK_ONLY" = yes ]; then
    if check_prereqs; then
        result "ok — prerequisites present, nothing changed (default sink: $SINK)"
        exit 0
    fi
    result "FAIL — prerequisites missing, see above"
    exit 1
fi

cat <<'BANNER'
════════════════════════════════════════════════════════════════════════
HOW THIS ENDS:   by itself, in about 40 seconds. It never waits for you.
RESULTS APPEAR:  in this terminal, on the final RESULT: line. Desktop popups
                 will come and go during the run: expected, they are not the
                 results, and none needs a click.
WHAT TO DO:      nothing to paste. The RESULT line and the daemon's journal
                 hold the answer.
════════════════════════════════════════════════════════════════════════
BANNER

check_prereqs || { result "FAIL — prerequisites missing, nothing changed"; exit 1; }

python3 - "$WORK/silence.wav" <<'PY'
import sys, wave
w = wave.open(sys.argv[1], "wb")
w.setnchannels(2); w.setsampwidth(2); w.setframerate(48000)
w.writeframes(b"\0" * 4 * 12000)
w.close()
PY

sample() { timeout 5 pw-dump </dev/null 2>/dev/null | python3 "$WORK/links.py" "$1" || true; }
start_capture() {
    timeout 8 pw-record --raw --rate 48000 --channels 2 --target "$SINK" \
        -P "{ stream.capture.sink=true application.name=$1 }" - </dev/null >/dev/null 2>&1 &
    CAPTURE_PID=$!
}
stop_capture() { kill "$CAPTURE_PID" >/dev/null 2>&1 || true; wait "$CAPTURE_PID" 2>/dev/null || true; }
journal_since() { journalctl --user -u "$UNIT" --since "@$1" --no-pager -o cat 2>/dev/null || true; }
active_streams() {
    local status
    status="$(timeout 5 "$CTL" status </dev/null)"
    sed -n 's/.*Active streams: *//p' <<<"$status"
}
# A link sitting there through three samples 0.6 s apart was not denied.
survivors() {
    local a b c id out=""
    sleep 1;   a="$(sample "$1")"
    sleep 0.6; b="$(sample "$1")"
    sleep 0.6; c="$(sample "$1")"
    for id in $a; do
        if [[ " $b " == *" $id "* && " $c " == *" $id "* ]]; then out="$out $id"; fi
    done
    echo "$out"
}

echo "== 1. Denied captures on reused ids, with every link cross-checked"
since="$(date +%s)"
timeout 30 pw-dump --monitor </dev/null >"$WORK/graph.stream" 2>/dev/null &
monitor=$!
sleep 1
leaked=0
for t in $(seq 1 "$TRIALS"); do
    timeout 5 pw-play --volume=0 "$WORK/silence.wav" </dev/null >/dev/null 2>&1 || true
    sleep 0.3
    start_capture "$DENIED_ID"
    stuck="$(survivors "$DENIED_ID")"
    stop_capture
    if [ -n "$stuck" ]; then
        leaked=$((leaked + 1))
        echo "    trial $t: LINK SURVIVED, ids:$stuck"
    else
        echo "    trial $t: no link survived"
    fi
    sleep 0.5
done
sleep 1
kill "$monitor" >/dev/null 2>&1 || true
wait "$monitor" 2>/dev/null || true
journal_since "$since" >"$WORK/journal.log"
denied="$(grep -c "Event: $DENIED_ID .*monitor → DENIED" "$WORK/journal.log" || true)"
read -r links missing missing_ids < <(python3 "$WORK/account.py" "$WORK/graph.stream" "$WORK/journal.log")
echo "    surviving=$leaked/$TRIALS  DENIED events=$denied"
echo "    links in an independent capture=$links  with no journal line=$missing ${missing_ids:-}"

echo "== 2. A stream that ended leaves the list"
base="$(active_streams)"
start_capture "$ALLOWED_ID"
sleep 1.5
during="$(active_streams)"
stop_capture
sleep 1.5
ended="$(active_streams)"
echo "    active streams: before=$base during=$during after it ended=$ended"

echo "== 3. A link that already exists when the daemon starts (ROADMAP g1)"
systemctl --user stop "$UNIT"
start_capture "$DENIED_ID"
sleep 1
before_start="$(sample "$DENIED_ID")"
restart_since="$(date +%s)"
systemctl --user start "$UNIT"
if ! wait_for_daemon; then
    stop_capture
    result "FAIL — the daemon did not come back after the g1 check. systemctl --user status $UNIT"
    exit 1
fi
stuck="$(survivors "$DENIED_ID")"
stop_capture
journal_since "$restart_since" >"$WORK/restart.log"
restart_denied="$(grep -c "Event: $DENIED_ID .*monitor → DENIED" "$WORK/restart.log" || true)"
echo "    links before the daemon started:${before_start:- none}"
echo "    surviving after it started:${stuck:- none}  DENIED events=$restart_denied"
if [ -z "$before_start" ]; then
    g1="NOT TESTED (no link formed)"
elif [ -z "$stuck" ] && [ "$restart_denied" -gt 0 ]; then
    g1="closed"
else
    g1="STILL OPEN"
fi
echo "    g1: $g1"

echo "== 4. What the daemon reports"
status="$(timeout 5 "$CTL" status </dev/null)"
sed -n '/Links:/p; /Split rules:/p' <<<"$status"

echo
if [ "$links" -eq 0 ] || [ "$denied" -eq 0 ] || [ "$during" -le "$base" ]; then
    result "INCONCLUSIVE — the probe did not exercise the daemon (links=$links, denied=$denied, streams $base->$during)"
    exit 2
fi
if [ "$leaked" -ne 0 ] || [ "$missing" -ne 0 ] || [ "$ended" -ne "$base" ]; then
    result "FAIL — surviving=$leaked/$TRIALS, links with no line=$missing/$links, streams $base->$during->$ended; g1 $g1"
    exit 1
fi
result "ok — 0/$TRIALS denied captures survived, $links/$links links have a journal line, an ended stream leaves the list; g1 $g1"
