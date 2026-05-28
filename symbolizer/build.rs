fn main() {
    println!("cargo:rustc-check-cfg=cfg(frame_pointers_enabled)");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");

    let rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let has_fp = rustflags
        .split('\u{1f}')
        .any(|flag| flag == "force-frame-pointers=yes" || flag == "-Cforce-frame-pointers=yes");

    let has_fp_raw = std::env::var("RUSTFLAGS")
        .unwrap_or_default()
        .contains("force-frame-pointers=yes");

    if has_fp || has_fp_raw {
        println!("cargo:rustc-cfg=frame_pointers_enabled");
    }
}
