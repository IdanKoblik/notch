use std::fs::OpenOptions;
use std::io;

pub fn confirm() -> Result<bool, super::Error> {
    use std::io::{BufRead, Write};

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| super::Error::ConfirmationUnavailable)?;

    let mut tty = io::BufReader::new(tty);
    write!(tty.get_mut(), "Proceed with injection? [y/N] ")?;
    tty.get_mut().flush()?;
    let mut answer = String::new();
    tty.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

