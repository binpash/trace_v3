use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::{
    fs::{self, OpenOptions},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use crate::utils::PrivGuard;

fn parse_ringbuf_size(s: &str) -> Result<usize, String> {
    let (num_str, multiplier) = if s.ends_with('K') || s.ends_with('k') {
        (&s[..s.len() - 1], 1024)
    } else if s.ends_with('M') || s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024)
    } else {
        (s, 1)
    };

    let size: usize = num_str
        .parse()
        .map_err(|_| format!("`{}` isn't a valid number", num_str))?;

    let total_size = size * multiplier;

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    if total_size % page_size != 0 {
        return Err(format!(
            "Ringbuffer size must be a multiple of the page size ({} bytes)",
            page_size
        ));
    }

    if !total_size.is_power_of_two() {
        return Err("Ringbuffer size must be a power of 2".to_string());
    }
    Ok(total_size)
}

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

    /// Size of the ring buffer (e.g. 4M, 1024K, or 4194304). Must be a multiple of page size and a power of 2.
    #[arg(long, value_parser = parse_ringbuf_size, default_value = "4M")]
    pub ringbuf_size: usize,

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
    /// Uninstall BPF programs and maps
    Uninstall {},
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
