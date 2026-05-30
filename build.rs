use std::env;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use libbpf_cargo::SkeletonBuilder;

#[path = "src/cli_def.rs"]
mod cli_def;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let cmd = cli_def::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;
    std::fs::write(out_dir.join("fstrace.1"), buffer)?;

    println!("cargo::rerun-if-changed=src/cli_def.rs");
    println!("cargo::rerun-if-env-changed=BUFF_SIZE");
    let buffer = env::var("BUFF_SIZE").unwrap_or_else(|_| "4".into());

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
    let arch_flag = format!("-D __{}__", arch);
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
            "-D__BPF_TRACING__",
            &arch_flag,
            &target_arch_flag,
            "-Wall",
            &include_flag,
            &format!("-DBUFF_SIZE={buffer}"),
        ])
        .build_and_generate("src/bpf/hs_trace.skel.rs")?;

    println!("cargo:rerun-if-changed=src/bpf/hs_trace.h");
    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("src/bpf/hs_trace.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .clang_arg(format!("-DBUFF_SIZE={buffer}"))
        .generate()?
        .write_to_file(outdir.join("bindings.rs"))?;

    Ok(())
}
