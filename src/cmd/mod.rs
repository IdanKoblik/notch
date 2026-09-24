use std::io;

pub mod inject;

pub trait Cmd {
    fn run(&self) -> Result<(), io::Error>;
}