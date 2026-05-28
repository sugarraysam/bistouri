//! Build script for the `profiler` eBPF program.

use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const PROFILER_SRC: &str = "src/bpf/profiler.bpf.c";
const PROFILER_HEADER: &str = "src/bpf/profiler.h";

fn main() {
    println!("cargo:rustc-check-cfg=cfg(frame_pointers_enabled)");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    let rustflags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let has_fp = rustflags
        .split('\u{1f}')
        .any(|flag| flag == "force-frame-pointers=yes" || flag == "-Cforce-frame-pointers=yes");

    if has_fp {
        println!("cargo:rustc-cfg=frame_pointers_enabled");
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("profiler.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(PROFILER_SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(&arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed={PROFILER_SRC}");
    println!("cargo:rerun-if-changed={PROFILER_HEADER}");
}
