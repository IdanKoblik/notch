use clap::{Parser, Subcommand};
use crate::cmd::Cmd;

mod cmd;
mod net;
mod steg;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
   #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inject(cmd::inject::InjectCmd)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inject(cmd) => cmd.run()?,
    }

    Ok(())
}
