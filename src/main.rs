use clap::{Parser, Subcommand};
use libc::{self, RLIMIT_CORE, rlimit};
use tracing::{error, warn};
use tracing_subscriber::{EnvFilter, fmt};

mod cli;
mod cmd;
mod crypto;
mod net;
mod steg;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long = "dev", default_value_t = false)]
    dev: bool,

    #[arg(long = "verbose", default_value_t = false)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    Inject(cmd::inject::InjectCmd),
    Extract(cmd::extract::ExtractCmd),
}

fn harden_process() {
    unsafe {
        let no_core = rlimit { rlim_cur: 0, rlim_max: 0 };

        if libc::setrlimit(RLIMIT_CORE, &no_core) != 0 {
            error!("Could not disable core dumps");
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                error!("Could not clear the dumpable flag");
            }
        }
    }
}

fn init_logging(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };

    fmt()
        .without_time()
        .with_target(false)
        .with_writer(crate::cli::progress::ProgressLogWriter::new)
        .with_env_filter(EnvFilter::new(level))
        .init();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            err.print()?;
            std::process::exit(2);
        }
    };

    init_logging(cli.verbose);

    if cli.dev {
        warn!("YOU ARE RUNNING IN DEV MODE!!!");
    } else {
        harden_process();
    }

    match cli.command {
        Commands::Inject(cmd) => cmd.run()?,
        Commands::Extract(cmd) => cmd.run()?,
    }

    Ok(())
}
