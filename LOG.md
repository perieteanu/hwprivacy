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
