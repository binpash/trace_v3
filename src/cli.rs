use clap::{Parser, Subcommand};

use std::{
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::Path,
};

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

    #[arg(trailing_var_arg = true)]
    pub cmd: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install BPF programs and maps
    Install {},
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

fn make_output(target: &str) -> io::Result<Output> {
    match target {
        "-" => Ok(Box::new(io::stdout())),
        path => {
            let path = Path::new(path);

            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }

            let file = File::create(path)?;
            Ok(Box::new(BufWriter::new(file)))
        }
    }
}
