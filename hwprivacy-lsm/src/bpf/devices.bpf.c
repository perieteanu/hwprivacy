// SPDX-License-Identifier: GPL-3.0-or-later
//
// hwprivacy — hardware device access observer (Phase 1: OBSERVE ONLY)
//
// Attaches to the LSM hook `security_file_open` and reports every open() of a
// video4linux or ALSA device node. This is the layer that sees what the
// PipeWire graph cannot: on 2026-08-04 both of these were measured going
// completely unnoticed by the PipeWire monitoring substrate —
//
//   ffmpeg -f v4l2 -i /dev/video0   ->  90 frames captured, 0 events logged
//   ffmpeg -f alsa -i hw:0,0        ->  3s of mic audio,     0 events logged
//
// Phase 1 contract: this program ALWAYS returns the incoming `ret` unchanged.
// It cannot deny anything. Enforcement arrives in Phase 2, camera first,
// behind an explicit policy map.

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
//
// Deliberately NOT decoding the ALSA minor here: the minor->role mapping
// (capture / playback / control / hwdep) is not a stable arithmetic formula
// across cards. Userspace resolves (major, minor) against a scan of /dev and
// classifies by node name, where it has the full picture and can be tested.
#define V4L2_MAJOR 81
#define ALSA_MAJOR 116

// Kernel dev_t encoding (include/linux/kdev_t.h).
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define DEV_MAJOR(dev) ((__u32)((dev) >> MINORBITS))
#define DEV_MINOR(dev) ((__u32)((dev)&MINORMASK))

// Not TASK_COMM_LEN: vmlinux.h may already define that as an enum.
#define HWP_COMM_LEN 16

// Layout must match `DevEvent` in src/event.rs exactly.
// 8 + 4+4 + 4+4 + 4+4 + 16 = 48 bytes, naturally aligned, no padding.
struct dev_event {
	__u64 exe_ino;
	__u32 exe_dev;
	__u32 pid;
	__u32 tgid;
	__u32 dev_major;
	__u32 dev_minor;
	__u32 denied;
	char comm[HWP_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

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

	struct dev_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return ret; // ring buffer full — drop the event, never the open

	// The policy key. A process cannot lie about which binary it exec'd,
	// which makes this stronger identity than PipeWire's self-declared
	// application.name. It also distinguishes two different Firefox
	// installs that PipeWire reports under the same name.
	e->exe_ino = BPF_CORE_READ(exe, f_inode, i_ino);
	e->exe_dev = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);

	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)id;
	e->tgid = (__u32)(id >> 32);

	e->dev_major = major;
	e->dev_minor = DEV_MINOR(rdev);
	e->denied = 0; // Phase 1: nothing is ever denied

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);

	return ret;
}
