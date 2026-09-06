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

    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .expect("failed to build eBPF skeleton — is clang installed?");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed={VMLINUX}");
}
