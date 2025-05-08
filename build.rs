use std::env;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use libbpf_cargo::SkeletonBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-changed=src/bpf/vmlinux.h");
    let file = File::create("src/bpf/vmlinux.h").unwrap();
    Command::new("bpftool")
        .args(&[
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .stdout(Stdio::from(file))
        .status()
        .unwrap();

    println!("cargo::rerun-if-changed=src/bpf/hs_trace.bpf.c");
    let arch = env::consts::ARCH;
    let target_arch_flag = format!(
        "-D __TARGET_ARCH_{}",
        if arch == "aarch64" {
            "arm64"
        } else if arch == "x86_64" {
            "x86"
        } else {
            // TODO (dan 2025-05-08): handle other arch's
            arch
        }
    );
    let include_flag = format!("-I/usr/include/{}-linux-gnu", arch);

    SkeletonBuilder::new()
        .source("src/bpf/hs_trace.bpf.c")
        .debug(true)
        .clang("clang")
        .clang_args([
            "-D __BPF_TRACING__",
            &target_arch_flag,
            "-Wall",
            &include_flag,
        ])
        .build_and_generate("src/bpf/hs_trace.skel.rs")?;

    println!("cargo:rerun-if-changed=src/bpf/hs_trace.h");
    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/bpf/hs_trace.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()?
        .write_to_file(outdir.join("bindings.rs"))?;

    Ok(())
}
