use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use crate::utils::PrivGuard;
pub use crate::cli_def::{Cli, Commands, OutputMode};

pub type Output = Box<dyn Write + Send>;

pub struct StreamOutputs {
    pub read: Output,
    pub write: Output,
    pub deps: Output,
}
impl StreamOutputs {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        Ok(Self {
            read: make_output(&cli.stream_read_file)?,
            write: make_output(&cli.stream_write_file)?,
            deps: make_output(&cli.stream_trace_file)?,
        })
    }
}
pub struct Outputs {
    pub trace_file: Output,
    pub dep_file: Output,
    pub missed_file: Output,
}

impl Outputs {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        Ok(Self {
            trace_file: make_output(&cli.trace_file)?,
            dep_file: make_output(&cli.dep_file)?,
            missed_file: make_output(&cli.missed_file)?,
        })
    }
}

fn make_output(target: &str) -> Result<Output> {
    match target {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let _guard = PrivGuard::drop_to_user()?;

            let mut file_path = PathBuf::from(path);

            if !file_path.is_absolute() {
                file_path = std::env::current_dir()?.join(file_path);
            }

            if let Some(parent) = file_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }

            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)?;

            Ok(Box::new(BufWriter::new(file)))
        }
    }
}
