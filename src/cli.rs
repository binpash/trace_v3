use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    os::unix::fs::chown,
    path::{Path, PathBuf},
};

use crate::invoker_permissions;

#[derive(Parser, Debug)]
#[command(name = "trace_v3", arg_required_else_help = true)]
pub struct Cli {
    /// Trace output file or "-" for stdout
    #[arg(long, default_value = "-")]
    pub trace_file: String,

    /// Dependency output file or "-" for stdout
    #[arg(long, default_value = "-")]
    pub dep_file: String,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// command to execute
    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install BPF programs and maps
    Install {},
    /// Attach to an existing process by PID
    Attach { pid: i32 },
}

pub type Output = Box<dyn Write + Send>;

pub struct Outputs {
    pub trace_file: Output,
    pub dep_file: Output,
}

impl Outputs {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        Ok(Self {
            trace_file: make_output(&cli.trace_file)?,
            dep_file: make_output(&cli.dep_file)?,
        })
    }
}

fn make_output(target: &str) -> Result<Output> {
    match target {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let (uid, gid) = invoker_permissions()?;

            let set_owner = |path: &Path| {
                chown(path, Some(uid), Some(gid))
                    .expect("Failed to change file ownership to non-sudo user");
            };

            let mut file_path = PathBuf::from(path);

            if !file_path.is_absolute() {
                file_path = std::env::current_dir()?.join(file_path);
            }

            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                    set_owner(&parent);
                }
            }

            let file = File::create(&file_path)?;
            set_owner(&file_path);
            Ok(Box::new(BufWriter::new(file)))
        }
    }
}
