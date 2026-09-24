use std::io::Error;
use clap::Args;
use super::Cmd;

#[derive(Args)]
pub struct InjectCmd {
    #[arg(short, long)]
    debug: bool,
}

impl Cmd for InjectCmd {
    fn run(&self) -> Result<(), Error> {
        println!("test");
        Ok(())
    }
}