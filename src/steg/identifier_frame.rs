#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Eot,
}

impl Command {
    pub fn encode(&self) -> u16 {
        match self {
            Command::Eot => 0x0001,
        }
    }

    pub fn decode(cmd: u16) -> Option<Self> {
        match cmd {
            0x0001 => Some(Command::Eot),
            _ => None,
        }
    }
}

pub enum IdentifierFrame {
    Raw { auth_tag: u8, value: u8 },
    Cmd(Command),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_round_trip() {
        assert_eq!(Command::decode(Command::Eot.encode()), Some(Command::Eot));
        assert_eq!(Command::decode(0x0002), None);
    }

    #[test]
    fn raw_frame_round_trip() {
        let frame = IdentifierFrame::Raw { auth_tag: 0xAB, value: 0xCD };
        let decoded = IdentifierFrame::decode(frame.encode());
        assert!(matches!(decoded, IdentifierFrame::Raw { auth_tag: 0xAB, value: 0xCD }));
    }

    #[test]
    fn command_encoding_takes_precedence_over_raw_frame() {
        assert!(matches!(IdentifierFrame::decode(0x0001), IdentifierFrame::Cmd(Command::Eot)));
    }
}

impl IdentifierFrame {
    pub fn encode(&self) -> u16 {
        match self {
            IdentifierFrame::Raw { auth_tag, value } => ((*auth_tag as u16) << 8) | (*value as u16),
            IdentifierFrame::Cmd(cmd) => cmd.encode(),
        }
    }

    pub fn decode(raw: u16) -> Self {
        if let Some(cmd) = Command::decode(raw) {
            return IdentifierFrame::Cmd(cmd);
        }

        IdentifierFrame::Raw { auth_tag: (raw >> 8) as u8, value: (raw & 0x00FF) as u8 }
    }
}
