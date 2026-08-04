use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

const SRC: &str = "src/bpf/devices.bpf.c";
const VMLINUX: &str = "src/bpf/vmlinux.h";

fn main() {
    // vmlinux.h is generated from the running kernel's BTF by
    // ~/projects/claude-run/hwprivacy-ebpf-toolchain-20260804.sh.
    // It is machine-specific and deliberately not committed.
    if !PathBuf::from(VMLINUX).exists() {
        panic!(
            "\n\n{VMLINUX} is missing.\n\
             Generate it with:\n    \
             bpftool btf dump file /sys/kernel/btf/vmlinux format c > {VMLINUX}\n\
             or just run ~/projects/claude-run/hwprivacy-ebpf-toolchain-20260804.sh\n"
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
