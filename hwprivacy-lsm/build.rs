use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/devices.bpf.c";
const VMLINUX: &str = "src/bpf/vmlinux.h";

fn main() {
    // vmlinux.h is generated from the RUNNING kernel's BTF, so it is specific
    // to the machine that built it and is deliberately not committed.
    if !PathBuf::from(VMLINUX).exists() {
        panic!(
            "\n\n{VMLINUX} is missing.\n\n\
             It is generated from your kernel's own BTF and is not committed,\n\
             because it describes the kernel you are building against.\n\n\
             Generate it with:\n    \
             bpftool btf dump file /sys/kernel/btf/vmlinux format c > {VMLINUX}\n\n\
             Requires: bpftool, clang, libbpf-dev, and a kernel built with\n\
             CONFIG_DEBUG_INFO_BTF=y (Debian 13 ships this).\n\n\
             On Debian/Ubuntu:\n    \
             sudo apt install -y clang libbpf-dev bpftool\n"
        );
    }

    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    out.push("devices.skel.rs");

    // Do NOT name a single culprit here. This message used to read "is clang
    // installed?" and was wrong the one time it mattered: CI failed on a rustup
    // rustfmt shim, clang was fine, and the message sent the reader to the
    // healthy dependency. The chained cause below is the evidence; everything
    // above it is a checklist, not a diagnosis.
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap_or_else(|e| {
            panic!(
                "\n\nfailed to build the eBPF skeleton.\n\n\
                 Read the chained cause at the bottom — do not assume clang.\n\
                 Causes that have actually occurred here:\n\n  \
                 - a `rustfmt` on PATH that FAILS. libbpf-cargo skips formatting\n    \
                   when rustfmt is ABSENT, but propagates a non-zero exit. Under\n    \
                   rustup the shim is always present and exits non-zero when the\n    \
                   component is not installed, so a broken rustfmt is worse than\n    \
                   none.  Fix: rustup component add rustfmt\n\n  \
                 - clang missing, or the libbpf headers missing\n\n  \
                 - {VMLINUX} produced by something other than bpftool. pahole\n    \
                   emits a header that looks right and does not compile.\n\n\
                 cause: {e:?}\n"
            )
        });

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={VMLINUX}");
}
