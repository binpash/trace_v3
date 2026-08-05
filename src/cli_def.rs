use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

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
#[command(
    name = "fstrace",
    arg_required_else_help = true,
    about = "File dependency tracer using eBPF",
    long_about = "fstrace traces file dependencies for a command using eBPF. \
It attaches to syscall tracepoints and records which files are read and written. \
It can produce summary output at the end of a run and optionally stream events while the command is running."
)]
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

    /// Enable streaming of dependency events
    #[arg(long)]
    pub stream_trace: bool,

    /// Where to write streamed dependency events, or "-" for stdout
    #[arg(long, default_value = "-")]
    pub stream_trace_file: String,

    /// Size of the ring buffer (e.g. 4M, 1024K, or 4194304). Must be a multiple of page size and a power of 2.
    #[arg(long, value_parser = parse_ringbuf_size, default_value = "4M")]
    pub ringbuf_size: usize,

    /// Measure and report data throughput from the ring buffer
    #[arg(long)]
    pub throughput: bool,

    /// Throughput output file or "-" for stdout; implies --throughput
    #[arg(long)]
    pub throughput_file: Option<String>,

    /// Throughput sampling interval in seconds (default: 1.0)
    #[arg(long, default_value = "1.0")]
    pub throughput_interval: f64,

    /// Suppress all events until the traced program opens the exec-marker path
    /// (/var/fstrace/initialized). Wrappers like `try` open it right before
    /// exec'ing the real program so their sandbox setup is not traced.
    #[arg(long)]
    pub exec_marker: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Command to execute
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

#[allow(dead_code)]
pub fn command() -> clap::Command {
    Cli::command()
}