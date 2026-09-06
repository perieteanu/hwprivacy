/* Minimal open() prober for the hwprivacy audio backstop.
 *
 * WHY THIS EXISTS, AND WHY NOT ffmpeg
 *
 * The acceptance test used `ffmpeg -f alsa` and could not tell a DENIAL from a
 * hang: on 2026-09-06 ffmpeg exited 124 (killed by timeout) with no message,
 * and separately reported "Input/output error" where the kernel had returned
 * EPERM. libasound retries, reopens and remaps the device, so by the time an
 * error surfaces the original errno is gone.
 *
 * A backstop test has exactly one question: what did open() return? This asks
 * that and nothing else. No library, no retry, no interpretation.
 *
 * Build:  gcc -o openprobe openprobe.c
 * Usage:  openprobe [/dev/snd/pcmC0D0c]
 * Exit:   0 = opened, 1 = refused (errno printed by name)
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *p = argc > 1 ? argv[1] : "/dev/snd/pcmC0D0c";
    int fd = open(p, O_RDONLY);
    if (fd < 0) { printf("open(%s) FAILED errno=%d (%s)\n", p, errno, strerror(errno)); return 1; }
    printf("open(%s) SUCCEEDED fd=%d\n", p, fd);
    return 0;
}
