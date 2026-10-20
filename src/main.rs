use clap::{Parser, Subcommand};
use libc::{self, RLIMIT_CORE, rlimit};

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
    is_dev: bool,
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
            eprintln!("Could not disable core dumps");
        }

        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                eprintln!("Could not clear the dumpable flag");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            err.print()?;
            std::process::exit(2);
        }
    };

    if cli.is_dev {
        println!("WARNING: YOU ARE RUNNING IN DEV MODE!!!");
    } else {
        harden_process();
    }

    match cli.command {
        Commands::Inject(cmd) => cmd.run()?,
        Commands::Extract(cmd) => cmd.run()?,
    }

    Ok(())
}
