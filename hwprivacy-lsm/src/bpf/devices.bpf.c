// SPDX-License-Identifier: GPL-3.0-or-later
//
// hwprivacy — hardware device access control (Phase 2: camera enforcement)
//
// Attaches to the LSM hook `security_file_open`.
//
//   CAMERA (major 81, video4linux)  — enforced when enforce_camera is set.
//                                     Denied opens return -EPERM.
//   AUDIO  (major 116, alsa)        — capture nodes enforced when enforce_audio
//                                     is set; playback/control never touched.
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

// Event kinds. `kind` occupies what used to be explicit padding in
// struct dev_event, so adding it did not change the 56-byte wire layout.
#define EV_OPEN 0
#define EV_RELEASE 1

// Permission bits in the policy map value.
#define PERM_CAMERA (1U << 0)
#define PERM_AUDIO (1U << 1) // may open an ALSA CAPTURE node

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
	/* ALSA capture enforcement. Occupies what used to be `_pad`, so the
	 * struct is still 16 bytes and the map needs no redefinition. There is
	 * no #[repr(C)] mirror on the Rust side — config_bytes() in main.rs is
	 * the single writer, and a test pins these offsets. */
	__u32 enforce_audio;
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
	/* EV_OPEN or EV_RELEASE. Was `_pad`; the wire size is unchanged. */
	__u32 kind;
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

// ---------------------------------------------------------------------------
// ALSA capture minors, populated by userspace from DeviceIndex.
//
// WHY A MINOR SET AND NOT THE MAJOR
//
// Denying major 116 outright would deny /usr/bin/pipewire, which opens the
// microphone on behalf of EVERY application — i.e. it would take out all audio
// on the machine. Only capture nodes (`/dev/snd/pcmC*D*c`) are gated; playback,
// control, seq and timer nodes are never touched. On this machine that is one
// minor (pcmC0D0c) against five playback nodes.
//
// A minor ABSENT from this map is not enforced. That direction is deliberate:
// a stale map (a mic hotplugged after the last rescan) under-blocks, and never
// locks the user out of their own audio. Same reasoning as the fail-open on a
// missing config below.
// ---------------------------------------------------------------------------
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);  // device minor
	__type(value, __u8); // presence only
} capture_minors SEC(".maps");

// ---------------------------------------------------------------------------
// Release tracking: which executable holds which camera file, and how many
// camera files each executable currently holds.
//
// WHY THE FILE POINTER IS THE KEY
//
// `security_file_release` runs in whatever context drops the fd. That is
// usually the owning process, but not reliably — and `__fput` can be deferred
// to a kworker entirely. Reading `current` there would attribute a close to the
// wrong task, or to no task at all. The (file -> executable) mapping recorded
// at OPEN time cannot be wrong, whoever does the closing.
//
// WHY A COUNT AND NOT A BOOLEAN
//
// One camera session is 13 opens (measured). Emitting a release on the first
// close would end the session while the application is still recording.
// ---------------------------------------------------------------------------
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); // struct file *
	__type(value, struct policy_key);
} open_files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct policy_key);
	__type(value, __u32);
} open_counts SEC(".maps");

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
	} else if (major == ALSA_MAJOR && cfg->enforce_audio) {
		// The BACKSTOP. Not per-application microphone policy: /dev/snd is
		// opened by the audio server on everyone's behalf, so the kernel sees
		// pipewire, not the app behind it. What this enforces is "only the
		// audio stack may open a capture device", which closes the direct-ALSA
		// bypass (ffmpeg -f alsa recorded freely until now) without claiming an
		// attribution the kernel cannot make. Per-app mic identity stays in
		// layer 1, where it genuinely exists.
		__u32 minor = DEV_MINOR(rdev);
		if (bpf_map_lookup_elem(&capture_minors, &minor)) {
			__u32 *perm = bpf_map_lookup_elem(&policy, &pk);
			if (!perm || !(*perm & PERM_AUDIO)) {
				verdict = -EPERM;
				denied = 1;
			}
		}
	}

	// -------------------------- release tracking ---------------------------
	// Only cameras, and only opens that SUCCEEDED. A denied open never got the
	// device, so it must not contribute a hold that a later close would have
	// to balance — that would leave a session that never ends.
	if (major == V4L2_MAJOR && verdict == 0) {
		__u64 fkey = (__u64)(unsigned long)file;
		if (!bpf_map_update_elem(&open_files, &fkey, &pk, BPF_NOEXIST)) {
			__u32 *cnt = bpf_map_lookup_elem(&open_counts, &pk);
			if (cnt) {
				__sync_fetch_and_add(cnt, 1);
			} else {
				__u32 one = 1;
				bpf_map_update_elem(&open_counts, &pk, &one, BPF_ANY);
			}
		}
		// A full open_files map means we simply do not track this handle.
		// The count stays balanced because the release path only decrements
		// for handles it finds — losing a release is a session that ends
		// late, never one that ends early on somebody else's close.
	}

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
	e->kind = EV_OPEN;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return verdict;
}


// ---------------------------------------------------------------------------
// Release: the camera has been let go.
//
// This is the event the project spent months asserting it could not have.
// Every doc, and the notification text itself, said "hwprivacy cannot tell when
// access ends". For the kernel layer that was true only because nothing was
// attached here — `bpf_lsm_file_release` has been available all along.
//
// It is what makes `while_in_use` mean something for a camera: without an end,
// a session is just `allow` with extra bookkeeping.
// ---------------------------------------------------------------------------
SEC("lsm/file_release")
int BPF_PROG(hwp_file_release, struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	// Same early bail as the open path, and for the same reason: this fires
	// on every close system-wide. Two probe reads before touching a map.
	dev_t rdev = BPF_CORE_READ(inode, i_rdev);
	__u32 major = DEV_MAJOR(rdev);
	if (major != V4L2_MAJOR)
		return 0;

	__u64 fkey = (__u64)(unsigned long)file;
	struct policy_key *pkp = bpf_map_lookup_elem(&open_files, &fkey);
	if (!pkp)
		return 0; // not a handle we recorded (denied open, or map was full)

	struct policy_key pk = *pkp;
	bpf_map_delete_elem(&open_files, &fkey);

	__u32 *cnt = bpf_map_lookup_elem(&open_counts, &pk);
	if (!cnt)
		return 0;

	// Decrement atomically, then re-read.
	//
	// The returning form (`__u32 before = __sync_fetch_and_add(...)`) is what
	// this wants, but BPF only returns from an atomic under ISA v3 and raising
	// the toolchain floor is not a decision worth making for one instruction.
	//
	// The re-read races: two threads closing an executable's last two handles
	// can both observe zero and both emit. That is deliberate — a DUPLICATE
	// release makes the daemon end an already-ended session, which is a no-op,
	// whereas a MISSED release leaves the session open forever, which is the
	// bug this hook exists to prevent. Fail toward ending.
	__sync_fetch_and_add(cnt, -1);

	__u32 *remaining = bpf_map_lookup_elem(&open_counts, &pk);
	if (!remaining || *remaining != 0)
		return 0; // still holding at least one handle

	bpf_map_delete_elem(&open_counts, &pk);

	struct dev_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0; // ring full: the session will end late, not wrongly

	e->exe_ino = pk.exe_ino;
	e->exe_dev = pk.exe_dev;

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)id;
	e->tgid = (__u32)(id >> 32);

	e->dev_major = major;
	e->dev_minor = DEV_MINOR(rdev);
	e->denied = 0;
	e->suppressed = 0;
	e->kind = EV_RELEASE;

	// comm here is whoever closed the fd, which is usually but not always the
	// owning process. The EXECUTABLE above comes from the map and is exact;
	// this is a hint for the log, nothing more.
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
