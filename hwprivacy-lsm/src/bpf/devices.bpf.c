// SPDX-License-Identifier: GPL-3.0-or-later
//
// hwprivacy — hardware device access control (Phase 2: camera enforcement)
//
// Attaches to the LSM hook `security_file_open`.
//
//   CAMERA (major 81, video4linux)  — enforced when enforce_camera is set.
//                                     Denied opens return -EPERM.
//   AUDIO  (major 116, alsa)        — OBSERVE ONLY. Never denied in Phase 2.
//                                     Audio is a separate feature; the kernel
//                                     cannot see which app is behind
//                                     /usr/bin/pipewire anyway.
//
// Why this layer exists at all — measured 2026-08-04, both invisible to the
// PipeWire monitoring substrate:
//
//   ffmpeg -f v4l2 -i /dev/video0   ->  90 frames captured, 0 events logged
//   ffmpeg -f alsa -i hw:0,0        ->  3s of mic audio,    0 events logged
//
// Enforcement is OFF unless userspace sets it. The default is observe.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Confirmed against /proc/devices on this machine:
//     81 video4linux   ->  /dev/video0 (81:0), /dev/video1 (81:1)
//    116 alsa          ->  /dev/snd/pcmC0D0c (116:9), controlC0 (116:11), ...
//
// Matching on the major covers every node of that class, including hardware
// plugged in later, without enumerating device paths.
#define V4L2_MAJOR 81
#define ALSA_MAJOR 116

// vmlinux.h carries no errno definitions.
#define EPERM 1

// Kernel dev_t encoding (include/linux/kdev_t.h).
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define DEV_MAJOR(dev) ((__u32)((dev) >> MINORBITS))
#define DEV_MINOR(dev) ((__u32)((dev)&MINORMASK))

// Not TASK_COMM_LEN: vmlinux.h may already define that as an enum.
#define HWP_COMM_LEN 16

// Permission bits in the policy map value.
#define PERM_CAMERA (1U << 0)
#define PERM_AUDIO (1U << 1) // reserved; audio is not enforced in Phase 2

// ---------------------------------------------------------------------------
// Policy key: the executable behind the calling task.
//
// A process cannot lie about which binary it exec'd, which makes this stronger
// identity than PipeWire's self-declared application.name. It also separates
// two Firefox installs that PipeWire reports under one name.
//
// EXPLICIT _pad: BPF hash-map keys are compared byte-for-byte, so an
// implicitly-padded struct would hash on uninitialised stack bytes and lookups
// would miss at random. Every key is zero-initialised before use.
// ---------------------------------------------------------------------------
struct policy_key {
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 _pad;
};

// Notification coalescing key: one burst per (executable, device class).
// Keyed on the MAJOR, not the minor: one camera session touches both
// /dev/video0 and /dev/video1, and the user thinks "camera", not "video1".
struct coalesce_key {
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 dev_major;
};

struct coalesce_val {
	__u64 last_ns;
	__u32 suppressed;
	/* Verdict this burst received. Every open in a burst is the same
	 * executable hitting the same device class, so they share a verdict.
	 * Recorded here because userspace flushes stale bursts LATER and has no
	 * other way to know whether the swallowed opens were denied — without it
	 * a burst of 13 denials reports as 1. Occupies what used to be padding,
	 * so the struct size is unchanged. */
	__u32 denied;
};

// Runtime configuration, updatable from userspace without reloading the
// program — so enforcement can be switched off instantly in an emergency.
struct config {
	__u32 enforce_camera;
	__u32 _pad;
	__u64 coalesce_ns;
};

// Layout must match `DevEvent` in src/event.rs exactly.
// 8 +4+4 +4+4 +4+4 +4+4 +16 = 56 bytes, naturally aligned.
struct dev_event {
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 pid;
	__u32 tgid;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 denied;
	__u32 suppressed;
	__u32 _pad;
	char comm[HWP_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct policy_key);
	__type(value, __u32);
} policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct coalesce_key);
	__type(value, struct coalesce_val);
} coalesce SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config_map SEC(".maps");

// LSM programs receive the return value of previously-run LSM modules as a
// trailing argument. Returning it unchanged is the "no opinion" answer.
SEC("lsm/file_open")
int BPF_PROG(hwp_file_open, struct file *file, int ret)
{
	// Someone above us already denied this open. Do not second-guess it,
	// and do not spend cycles on it.
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return ret;

	// Hot path: security_file_open fires on EVERY open() system-wide, so
	// bail as early as possible. i_rdev is 0 for regular files, so this
	// costs two probe reads for the overwhelming majority of opens.
	// Measured cost of the whole hook: +13.75 ns/open (95% CI +7.3..+20.2).
	dev_t rdev = BPF_CORE_READ(inode, i_rdev);
	__u32 major = DEV_MAJOR(rdev);
	if (major != V4L2_MAJOR && major != ALSA_MAJOR)
		return ret;

	// --- from here on we are only handling camera / audio device opens ---

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return ret;

	// Kernel threads have no mm and therefore no executable. Nothing to
	// identify, and they are not what we are policing.
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return ret;

	struct file *exe = BPF_CORE_READ(mm, exe_file);
	if (!exe)
		return ret;

	__u32 cfg_key = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
	if (!cfg)
		return ret; // no config yet: fail OPEN, never lock the user out

	struct policy_key pk = {}; // zero-init: padding must not be garbage
	pk.exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
	pk.exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);

	// ------------------------------- verdict -------------------------------
	int verdict = 0;
	__u32 denied = 0;

	if (major == V4L2_MAJOR && cfg->enforce_camera) {
		__u32 *perm = bpf_map_lookup_elem(&policy, &pk);
		if (!perm || !(*perm & PERM_CAMERA)) {
			verdict = -EPERM;
			denied = 1;
		}
	}
	// ALSA is never denied here. Phase 2 is camera only.

	// ----------------------------- coalescing ------------------------------
	// The DENIAL always applies to every open — that is the kernel's job and
	// is not negotiable. Only the notification EVENT is coalesced: one camera
	// session is 13 opens in a single second (measured), and 13 identical
	// popups is the same defect the PipeWire layer already has.
	struct coalesce_key ck = {};
	ck.exe_ino = pk.exe_ino;
	ck.exe_dev = pk.exe_dev;
	ck.dev_major = major;

	__u64 now = bpf_ktime_get_ns();
	__u32 suppressed = 0;

	struct coalesce_val *cv = bpf_map_lookup_elem(&coalesce, &ck);
	if (cv) {
		if (now - cv->last_ns < cfg->coalesce_ns) {
			__sync_fetch_and_add(&cv->suppressed, 1);
			return verdict; // enforced, but stay quiet
		}
		suppressed = cv->suppressed;
		cv->suppressed = 0;
		cv->last_ns = now;
		cv->denied = denied;
	} else {
		struct coalesce_val nv = {};
		nv.last_ns = now;
		nv.denied = denied;
		bpf_map_update_elem(&coalesce, &ck, &nv, BPF_ANY);
	}

	// ------------------------------- report --------------------------------
	struct dev_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return verdict; // ring full: drop the event, never change the verdict

	e->exe_ino = pk.exe_ino;
	e->exe_dev = pk.exe_dev;

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)id;
	e->tgid = (__u32)(id >> 32);

	e->dev_major = major;
	e->dev_minor = DEV_MINOR(rdev);
	e->denied = denied;
	e->suppressed = suppressed;
	e->_pad = 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return verdict;
}
