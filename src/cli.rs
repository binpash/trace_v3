use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use crate::utils::PrivGuard;



#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OutputMode {
    Summary,
    Stream,
    Both,
}



#[derive(Parser, Debug)]
#[command(name = "trace_v3", arg_required_else_help = true)]
pub struct Cli {
    /// Trace output file or "-" for stdout
    #[arg(long, default_value = "-")]
    pub trace_file: String,

    /// Dependency output file or "-" for stdout
    #[arg(long, default_value = "-")]
    pub dep_file: String,

    /// Missed event count output file or "-" for stdout
    #[arg(long, default_value = "-")]
    pub missed_file: String,

    /// Output mode: summary (default), stream, or both
    #[arg(long, value_enum, default_value = "summary")]
    pub mode: OutputMode,

    /// Enable streaming of READ events ("R <path>")
    #[arg(long)]
    pub stream_read: bool,

    /// Where to write streamed READ events, or "-" for stdout
    #[arg(long, default_value = "-")]
    pub stream_read_file: String,

    /// Enable streaming of WRITE events ("W <path>")
    #[arg(long)]
    pub stream_write: bool,

    /// Where to write streamed WRITE events, or "-" for stdout
    #[arg(long, default_value = "-")]
    pub stream_write_file: String,

    /// Enable streaming of dependency events (separate stream if desired)
    #[arg(long)]
    pub stream_trace: bool,

    /// Where to write streamed dependency events, or "-" for stdout
    #[arg(long, default_value = "-")]
    pub stream_trace_file: String,

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
