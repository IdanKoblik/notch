use clap::{Parser, Subcommand};

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
}

#[derive(Subcommand)]
enum Commands {
    Inject(cmd::inject::InjectCmd),
    Extract(cmd::extract::ExtractCmd),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inject(cmd) => cmd.run()?,
        Commands::Extract(cmd) => cmd.run()?,
    }

    Ok(())
}
