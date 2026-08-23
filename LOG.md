# Project Log

27-03-2026 20:49 | Fri | hw | [note] doc present: PLAN.md
27-03-2026 23:22 | Fri | hw | [note] doc present: README.md
24-04-2026 09:41 | Fri | hw | [note] seeded from existing state on 24-04-2026 Fri
04-08-2026 19:20 | Tue | hw | [note] reopened cold; verified against code + live daemon — project is feature-complete, not unfinished
04-08-2026 19:29 | Tue | hw | [add] wrote project CLAUDE.md + docs-yaml (MISSION, ARCHITECTURE, CONVENTIONS, DECISIONS, ROADMAP)
04-08-2026 19:35 | Tue | hw | [note] found 4 live behavioural defects b1-b4; dismiss-writes-permanent-deny explains why daily use failed
04-08-2026 22:20 | Tue | hw | [note] measured: ffmpeg -f v4l2 /dev/video0 captured 90 frames, hwprivacy logged 0 events — camera bypass
04-08-2026 22:25 | Tue | hw | [note] measured: ffmpeg -f alsa hw:0,0 captured 3s of mic audio, 0 events — ALSA bypasses too
04-08-2026 22:37 | Tue | hw | [pivot] PipeWire-only enforcement is structurally blind; adding a kernel eBPF LSM layer beneath it
04-08-2026 22:40 | Tue | hw | [decide] libbpf-rs + one C file; deny-plus-notification UX; root helper over unix socket to the user daemon
04-08-2026 22:45 | Tue | hw | [add] plan approved for kernel camera enforcement, phases 0-4, camera first and audio deferred
04-08-2026 22:46 | Tue | hw | [add] Phase 0 toolchain script in claude-run (clang, libbpf-dev, bpftool, libelf-dev, vmlinux.h)
04-08-2026 22:55 | Tue | hw | [add] new crate hwprivacy-lsm: eBPF LSM on security_file_open, observe-only, majors 81 + 116
04-08-2026 23:00 | Tue | hw | [fix] device_index decoded stat() st_rdev with kernel dev_t rules — index was silently empty
04-08-2026 23:05 | Tue | hw | [fix] toolchain script aborted on bpftool version print; Debian puts bpftool in /usr/sbin, off non-root PATH
04-08-2026 23:09 | Tue | hw | [done] Phase 1 validated live: LSM attached first try; 13 camera opens by firefox-esr, 0 seen by PipeWire
04-08-2026 23:30 | Tue | hw | [defer] Phase 2 enforcement not started; LSM hook CPU cost still unmeasured
05-08-2026 10:24 | Wed | hw | [fix] allowlist inserted glibc st_dev where the kernel reads its own dev_t; every lookup missed
05-08-2026 10:29 | Wed | hw | [fix] test ran a stale binary — cargo test does not refresh target/debug; scripts now build first
05-08-2026 10:31 | Wed | hw | [done] Phase 2 acceptance PASSED 5/5 — camera denied by default, allowed by inode, restored on detach
05-08-2026 10:40 | Wed | hw | [done] Firefox end-to-end: call failed when denied, worked after allow, one click, no restart
05-08-2026 10:52 | Wed | hw | [fix] coalescing counters were stranded — 12 of 13 denials never reached the log
05-08-2026 11:05 | Wed | hw | [decide] test contract: how it ends, where results appear, what to paste back — promoted to global
05-08-2026 11:20 | Wed | hw | [decide] script matrix: test+sudo = Costin+banner, sudo only = Costin, test only = Claude
05-08-2026 19:05 | Wed | hw | [add] hwprivacy-proto crate — NDJSON wire protocol, serde only so root links no D-Bus stack
05-08-2026 19:12 | Wed | hw | [add] hwprivacy-lsm serves a unix socket; BPF maps never leave the main thread
05-08-2026 19:20 | Wed | hw | [add] AppRule.exe_path — one rule now governs both layers; renamed from exe, which read as Windows
05-08-2026 19:30 | Wed | hw | [add] daemon connects to the kernel layer; events flow to ctl/tui/gui with no frontend changes
05-08-2026 19:35 | Wed | hw | [fix] D-Bus activation raced systemd — daemon crash-looped 32x; now delegates via SystemdService=
05-08-2026 19:45 | Wed | hw | [note] Phase 3 acceptance criteria written before the test script; C2-C4 need human eyes
05-08-2026 19:47 | Wed | hw | [defer] Phase 3 unproven — script not written; Phases 4 (systemd) and 5 (audio backstop) not started
05-08-2026 20:32 | Wed | hw | [fix] third stale-binary mechanism: workspace fold moved target dir; guard now compares mtimes
05-08-2026 20:40 | Wed | hw | [note] Phase 3 run 1: 8/4 — A2 waited 3s against a 10s reconnect loop, cascading into B1/D1/B4
05-08-2026 20:45 | Wed | hw | [fix] burst summaries were printed but never sent to the daemon; kernel now records the verdict too
05-08-2026 20:46 | Wed | hw | [fix] burst summary carries pid 0 so it counts but does not fire a second notification
05-08-2026 20:52 | Wed | hw | [note] Phase 3 run 2: 11/2 — connection, policy, gaps, enforcement, event flow, restore all pass
05-08-2026 20:56 | Wed | hw | [note] C5 unverifiable as written: Firefox is allowlisted so its burst is not denied; needs a denied burster
05-08-2026 20:57 | Wed | hw | [note] D1 unresolved — call failed although firefox-esr was allowlisted; two untested hypotheses recorded
05-08-2026 20:58 | Wed | hw | [defer] Phase 3 substantially proven; burst counting and D1 still open. Phases 4-5 not started
04-08-2026 23:38 | Tue | hw | [work] commit: Initial commit: PipeWire permission manager + kernel eBPF LSM layer
04-08-2026 23:40 | Tue | hw | [work] commit: Decouple the running service from the dev tree; fix broken D-Bus activation
05-08-2026 09:36 | Wed | hw | [work] commit: HANDOFF: correct stale 'No git' entry — git was added at the end of that session
05-08-2026 09:47 | Wed | hw | [work] commit: Measure the eBPF LSM hook overhead: +13.75 ns/open, architecture passes
05-08-2026 10:09 | Wed | hw | [work] commit: hwprivacy-lsm: announce up front how a run terminates
05-08-2026 10:10 | Wed | hw | [work] commit: docs: refresh memory mirror (4 memories)
05-08-2026 10:18 | Wed | hw | [work] commit: Phase 2: kernel camera enforcement (-EPERM), default deny, coalesced
05-08-2026 10:27 | Wed | hw | [work] commit: Fix: allowlist inserted glibc st_dev where the kernel reads its own dev_t
05-08-2026 10:30 | Wed | hw | [work] commit: Add --dump-policy; make the acceptance test build before it tests
05-08-2026 10:35 | Wed | hw | [work] commit: Phase 2 acceptance PASSED; add the Firefox end-to-end test
05-08-2026 10:48 | Wed | hw | [work] commit: Flush stranded coalescing counters so denials are not silently lost
05-08-2026 10:48 | Wed | hw | [work] commit: docs: record the Firefox end-to-end result and the getUserMedia finding
05-08-2026 11:08 | Wed | hw | [work] commit: Test contract: announce how it ends, where results appear, what to paste back
05-08-2026 14:48 | Wed | hw | [work] commit: Scope the test banner correctly: test AND sudo, not either alone
05-08-2026 18:51 | Wed | hw | [work] commit: Phase 3a-c: workspace folded, wire protocol, root helper serves a socket
05-08-2026 19:04 | Wed | hw | [work] commit: Rename exe -> exe_path; add it to AppRule with kernel-layer helpers
05-08-2026 19:38 | Wed | hw | [work] commit: Phase 3d-f: daemon connects to the kernel layer; fix a D-Bus activation race
05-08-2026 19:47 | Wed | hw | [work] commit: docs: Phase 3 acceptance criteria, rewritten HANDOFF, refreshed mirrors
05-08-2026 19:50 | Wed | hw | [work] commit: log: 2026-08-05 session — Phase 2 proven, Phase 3 code-complete
05-08-2026 19:56 | Wed | hw | [work] commit: Phase 4 reshaped: continuous operation AND a persistent audit trail
05-08-2026 19:57 | Wed | hw | [work] commit: Phase 4: record the fail2ban-shaped reporting proposal
05-08-2026 20:32 | Wed | hw | [work] commit: Stop scripts running a stale binary — third mechanism, real guard this time
05-08-2026 20:50 | Wed | hw | [work] commit: Fix C5 (burst count never reached the daemon) and three test bugs
05-08-2026 20:59 | Wed | hw | [work] commit: Phase 3 result: 11/13. Record what is proven, what is not, and why
05-08-2026 21:33 | Wed | hw | [work] commit: HANDOFF: correct stale counts and the 'never been run' line
19-08-2026 16:52 | Wed | hw | [note] doc audit vs code+live host: HANDOFF/ROADMAP accurate; ARCHITECTURE/MISSION/CLAUDE.md stale by one whole layer
19-08-2026 16:53 | Wed | hw | [note] measured drift: docs said 5 crates/3434 LOC/0 tests; actual 7 crates/7079 LOC/63 tests passing
19-08-2026 16:55 | Wed | hw | [add] d-kernel-lsm-layer ADR — the 2026-08-04 pivot had NO decision entry for 15 days
19-08-2026 16:55 | Wed | hw | [fix] d-event-driven-substrate demoted from "DIRECTION SET" to layer-1-only/deferred; it read as current direction
19-08-2026 16:56 | Wed | hw | [fix] renamed d-two-layer-model -> d-per-stream-gating; "two-layer" meant two different things since the pivot
19-08-2026 17:02 | Wed | hw | [fix] CLAUDE.md rewritten against the filesystem: git exists, 63 tests, 8 warnings, notification.rs:146 -> :196
19-08-2026 17:08 | Wed | hw | [fix] ARCHITECTURE.yaml now covers both layers — it had omitted hwprivacy-lsm and -proto entirely (~3000 LOC)
19-08-2026 17:09 | Wed | hw | [note] still stale and untouched: README.md (0 mentions of kernel/eBPF/LSM) and MISSION.yaml
19-08-2026 17:24 | Wed | hw | [fix] README rewritten: kernel layer added, false "every device flows through PipeWire" premise corrected
19-08-2026 17:26 | Wed | hw | [fix] README dismiss section now says the code writes a permanent deny; signals table marks the two dead declarations
19-08-2026 17:28 | Wed | hw | [fix] README Known Limitations +5: already-open fd, grandfathered links, BlockAll, unpinned BPF, same-user stop
19-08-2026 17:35 | Wed | hw | [add] tools/doc-check + make doc-check — 7 checks, each one a contradiction that actually happened here
19-08-2026 17:38 | Wed | hw | [fix] doc-check precision: LOC/anchor/test checks were flagging scoped claims; a noisy gate is worse than none
19-08-2026 17:40 | Wed | hw | [note] gate found 4 real stale claims I had missed by hand: 5-crates x2, 3434 LOC, notification.rs:146
19-08-2026 17:44 | Wed | hw | [fix] HANDOFF.md rewritten for a clean base: pick-up order is C5 -> D1 -> Phase 4 -> Phase 5
19-08-2026 19:38 | Wed | hw | [note] drove the camera from headless Chrome — real /dev/video0 via V4L2, no human, no notifications
19-08-2026 19:42 | Wed | hw | [note] C5 MEASURED: 13 denied opens, kernel reports 13, daemon counted 14 — constant off-by-one
19-08-2026 19:44 | Wed | hw | [note] D1 mechanism PROVEN with Chrome: denied before allowlisting, allowed after, by exe inode
19-08-2026 19:45 | Wed | hw | [note] reconnect after daemon restart works; helper logged 'policy set by daemon - 2 allowed'
19-08-2026 19:48 | Wed | hw | [fix] burst summary (pid 0) no longer counted as an access — was +1 and a spurious pid-0 event row
19-08-2026 19:49 | Wed | hw | [fix] PipeWire cooldown path double-counted: log_event already increments blocked_count
19-08-2026 19:50 | Wed | hw | [add] denied_opens() as the single accounting rule + 4 tests incl. the measured 13-open case
19-08-2026 19:55 | Wed | hw | [add] tools/camera-accounting-check — C5 as a repeatable check, no browser and no human
19-08-2026 19:56 | Wed | hw | [done] C5 CLOSED — fix verified live at 1/5/13/27 opens and with headless Chrome, all exact
19-08-2026 19:57 | Wed | hw | [done] event log now one row per session, not two; the pid-0 duplicate is gone
19-08-2026 20:02 | Wed | hw | [done] D1 allow direction: Firefox-ESR camera ALLOWED, 13 opens, live video on screen
19-08-2026 20:10 | Wed | hw | [done] D1 deny direction: same inode DENIED, 4 opens, no video — WhatsApp reported no camera/mic
19-08-2026 20:11 | Wed | hw | [done] PHASE 3 COMPLETE 13/13 — both confounds excluded before the run, not argued away after
19-08-2026 20:12 | Wed | hw | [note] b1 is NARROWER than documented: ask_each never writes config; only the plain ask path does
19-08-2026 20:12 | Wed | hw | [note] reconnect after daemon restart took ~51s not ~10s — helper enforces the OLD policy meanwhile
19-08-2026 20:13 | Wed | hw | [decide] Firefox-ESR is THE test browser; firefox-bin is a different inode and not allowlisted
19-08-2026 20:22 | Wed | hw | [add] Phase 4 stage 1: --policy-cache — the helper persists the pushed allowlist and reloads it at boot
19-08-2026 20:26 | Wed | hw | [add] Phase 4 stage 2: system unit debian/hwprivacy-lsm.service + packaging + make install-lsm
19-08-2026 20:31 | Wed | hw | [fix] g4 CLOSED — event timestamps now carry a full date; ctl and TUI columns widened to match
19-08-2026 20:36 | Wed | hw | [add] Phase 4 stage 4: offenders table, persistent per-identity denial counters + ctl offenders
19-08-2026 20:40 | Wed | hw | [note] verified: daemon restart wipes the event ring but the offenders table survives
19-08-2026 20:41 | Wed | hw | [note] doc-check caught a real anchor drift: g4 moved grant_one_shot 128 -> 133
19-08-2026 20:52 | Wed | hw | [done] policy cache WRITE verified: daemon push -> /var/lib/hwprivacy/policy holds firefox-esr
19-08-2026 20:57 | Wed | hw | [done] policy cache RELOAD verified with NO --socket: kernel map matches userspace exactly
19-08-2026 20:58 | Wed | hw | [fix] socket.rs conflated timeout with disconnect; a 0.22s disconnect read as a 5s timeout
19-08-2026 20:58 | Wed | hw | [note] the two cache failures were a race in MY test script, not the product — helper killed mid-push
19-08-2026 21:14 | Wed | hw | [note] ROADMAP shape figures refreshed to 7817 LOC / 78 tests; g4 marked closed
19-08-2026 21:15 | Wed | hw | [add] install script for hwprivacy-lsm as a system service — typed INSTALL gate, enable+start, no reboot
19-08-2026 21:16 | Wed | hw | [note] Phase 4 stage 2 stays UNPROVEN until the unit is installed and survives a boot
19-08-2026 21:21 | Wed | hw | [done] Phase 4 stage 2 PROVEN: unit installed, enforcing from the cache with no daemon connected
19-08-2026 21:26 | Wed | hw | [fix] ctl said "Camera enforced: no" while the camera WAS enforced; now UNKNOWN when disconnected
19-08-2026 21:27 | Wed | hw | [fix] --json hid the cache-load line, so the installed service never logged whether the allowlist loaded
19-08-2026 21:54 | Wed | hw | [done] PHASE 4 COMPLETE — unit started 7s after boot, enforcing from cache, daemon connected, NRestarts 0
19-08-2026 21:59 | Wed | hw | [note] firefox-esr camera ALLOWED by rule (17 opens, denied=false) while python denied 3/3 — both correct
19-08-2026 22:04 | Wed | hw | [decide] allow wireplumber the camera — Costin's call; restores the PipeWire camera node, costs kernel attribution
19-08-2026 22:06 | Wed | hw | [note] b5 DIAGNOSED: helper stops accepting clients after the first disconnects; the "51s delay" was this
19-08-2026 22:08 | Wed | hw | [add] ctl devices now shows a kernel-layer row — a camera absent from PipeWire is not an unprotected one
19-08-2026 22:14 | Wed | hw | [note] allowing wireplumber alone changed nothing — /usr/bin/pipewire is what opens /dev/video0 to publish the node
19-08-2026 22:18 | Wed | hw | [decide] revert the pipewire camera grant; wireplumber stays allowed. Granting pipewire would extend /dev/snd blindness to video
19-08-2026 22:20 | Wed | hw | [fix] b5 FIXED — events thread parked in recv() forever, so join() wedged the accept loop after every disconnect
19-08-2026 22:22 | Wed | hw | [add] b5 regression test, verified to FAIL against the reintroduced bug and pass against the fix
19-08-2026 22:33 | Wed | hw | [note] MEASURED: right mic link cut mid-capture -> rms 0.0, left kept recording, parecord never noticed
19-08-2026 22:35 | Wed | hw | [decide] b3 is a LABELLING bug not a duplication bug — two prompts are two MICROPHONES; do not coalesce
19-08-2026 22:36 | Wed | hw | [note] mic was MUTED for every microphone test tonight until 22:32; link-level results unaffected
19-08-2026 22:40 | Wed | hw | [decide] naming for indistinguishable devices: mic1..micN, cam1..camN — never left/right — unless the device publishes a name
19-08-2026 22:41 | Wed | hw | [note] ordinals must derive from a REBOOT-STABLE key (port name, not port id) or a rule silently moves to another device
23-08-2026 11:00 | Sun | hw | [note] READ THE LOGS: firefox-esr denied the camera 16h on 08-20 — dpkg upgraded it 2min after the policy push, kernel map kept the old inode
23-08-2026 11:05 | Sun | hw | [note] every status surface said healthy throughout: config said allow, ctl said "Allowed binaries: 2". Self-healed at reboot, which is why it was never seen
23-08-2026 11:20 | Sun | hw | [note] found while fixing it: SetPolicy only ever sent at connect — camera rule changes from ctl/tui/gui never reached the kernel at all
23-08-2026 11:25 | Sun | hw | [note] StreamInfo.object_serial actually held node.id — serials are never reused, node ids are. The name is why b2 read as a tuning issue
23-08-2026 12:10 | Sun | hw | [fix] PolicyFingerprint: daemon re-stats the allowlist every exe_recheck_secs and re-pushes on change. One mechanism, all three staleness modes
23-08-2026 12:40 | Sun | hw | [fix] b1 — PromptOutcome Chosen/Dismissed/Failed; only a button press can reach SavePermanentRule. Decision extracted to a pure, testable fn
23-08-2026 12:45 | Sun | hw | [note] b1 had a second half nobody had recorded: a FAILED notification also wrote a permanent deny. Headless = every prompt becomes deny
23-08-2026 13:00 | Sun | hw | [fix] b2 — one-shot grants keyed on (node_id, app) and pruned each poll; b4 — sanitize_rule_name() refuses names that can never match
23-08-2026 13:10 | Sun | hw | [decide] posture SETTLED: deny-by-default. Dismiss = block, save nothing, cooldown, ask again
23-08-2026 13:20 | Sun | hw | [add] doc-check SENTINELS — source patterns that must never reappear. First two: the b1 expression and the b2 Vec<u32>
23-08-2026 13:25 | Sun | hw | [note] found a test that had never run: #[test] was stacked twice on the fn above it, leaving the next one dead. Compiled, read as covered
23-08-2026 15:40 | Sun | hw | [decide] b3 splits by CATEGORY — mics get one labelled prompt each (mic1/mic2), a sink's channel links get coalesced into one
23-08-2026 15:45 | Sun | hw | [note] the test is not "do the links look alike" but "can the user meaningfully answer differently for each". Two mics yes, two channels of one sink no
23-08-2026 16:00 | Sun | hw | [add] classify_link() has tests for the first time since 2026-03-27 — 14, incl. that ordinary playback is NOT a monitor tap
23-08-2026 16:05 | Sun | hw | [note] one of those tests proved nothing at first: on this laptop monitor_* sorts before playback_*, so it passed with the direction filter REMOVED
23-08-2026 16:10 | Sun | hw | [note] LIVE: parecord mic -> two rows "microphone (mic1)" / "(mic2)"; monitor tap -> ONE row. b3 verified end to end
23-08-2026 16:20 | Sun | hw | [note] NEW b6 found while verifying b1: Hint::Resident(true) beats timeout(60000) — the prompt never expires, so the cooldown never starts
23-08-2026 16:22 | Sun | hw | [note] b1's fix holds (config byte-identical, no rule written) but "ask again later" does not happen — the first ask never ends. Not fixed, needs a decision
23-08-2026 17:05 | Sun | hw | [add] notify-on-allow: the allow path was silent while the deny path was loud. Gate is a pure fn — startup grace + per-(app,device) cooldown
23-08-2026 17:08 | Sun | hw | [decide] kernel layer announces CAMERA allows only — it sees /usr/bin/pipewire for the mic, and layer 1 already names the real app. One access, one notification
23-08-2026 17:15 | Sun | hw | [add] offenders -> history, with an allowed column. Migration preserved all 115 accumulated denials; old file left in place
23-08-2026 17:35 | Sun | hw | [note] LIVE: two allowed monitor accesses -> ONE announcement. Cooldown verified end to end
23-08-2026 17:38 | Sun | hw | [note] added an "Announced allowed access" log line — whether a popup appeared is otherwise unassertable, which is how C4 got scored wrong twice
23-08-2026 17:55 | Sun | hw | [decide] b6: prompts STAY until answered — a permission question is a to-do item, not a nag. The stacking is the defect, not the persistence
23-08-2026 18:00 | Sun | hw | [fix] b6: Timeout::Never said out loud, one pending prompt per (app,device) normalised, claim released on every exit path
23-08-2026 18:05 | Sun | hw | [note] LIVE: three repeats of the same access -> ONE ASKED then DENIED, DENIED. Before the fix all three raised a popup
