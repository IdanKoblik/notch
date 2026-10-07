use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not open terminal for confirmation")]
    ConfirmationUnavailable,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}


pub mod ask;
