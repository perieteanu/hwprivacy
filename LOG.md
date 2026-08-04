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
