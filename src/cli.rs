use clap::{Parser, Subcommand};
use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    os::unix::fs::chown,
    path::Path,
};

use crate::find_sudo_invoker;

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
    pub fn from_cli(cli: &Cli) -> io::Result<Self> {
        Ok(Self {
            trace_file: make_output(&cli.trace_file)?,
            dep_file: make_output(&cli.dep_file)?,
        })
    }
}

/*
        // 2. Fix: Use create_dir_all so it doesn't crash if parents are missing.
        // We check !exists() to avoid overwriting permissions if it's already there (optional).
        if !output_path.exists() {
            fs::create_dir_all(&output_path).expect("Could not create output root");
            set_owner(&output_path);
        }
        // 3. Create the specific sub-directory
        let output_dir = output_path.join((sorted_logs[0].0).to_string());

        // Use create_dir_all for safety
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir).expect("could not create specific output dir");
            set_owner(&output_dir);
        }

        // 4. Create and chown the logs file
        let log_path = output_dir.join("logs");
        let mut log_file = fs::File::create(&log_path).unwrap();
        set_owner(&log_path);

*/

fn make_output(target: &str) -> io::Result<Output> {
    match target {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let (uid, gid) = find_sudo_invoker().unwrap();
            let set_owner = |path: &Path| {
                chown(path, Some(uid), Some(gid))
                    .expect("Failed to change file ownership to non-sudo user");
            };

            let path = Path::new(path);

            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                    set_owner(&parent);
                }
            }

            let file = File::create(path)?;
            set_owner(&path);
            Ok(Box::new(BufWriter::new(file)))
        }
    }
}
