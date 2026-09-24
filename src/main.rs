use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
   #[command(subcommand)]
   command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Test {
        #[arg(short, long)]
        debug: bool,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    Ok(())
}
