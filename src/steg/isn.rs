#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Ping { value: u16 },
}

impl Command {
    pub fn tag(&self) -> u16 {
        match self {
            Command::Ping { .. } => 0x1,
        }
    }

    pub fn encode(&self) -> u16 {
        let tag = self.tag() << 12;
        let value = match self {
            Command::Ping { value } => *value & 0x0FFF,
        };
        tag | value
    }

    #[allow(unused)]
    pub fn decode(cmd: u16) -> Option<Self> {
        let tag = (cmd >> 12) & 0x0F;
        let value = cmd & 0x0FFF;

        match tag {
            0x1 => Some(Command::Ping { value }),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Flags {
    None = 0x0,
    Start = 0x1,
    End = 0x2,
}

pub struct IsnPacket {
    auth_tag: u8,
    flags: u8,
    index: u8,
    cmd: u16,
}

impl IsnPacket {
    pub fn new(auth_tag: u8, flags: u8, index: u8, cmd: Command) -> Self {
        Self {
            auth_tag,
            flags: flags & 0x0F,
            index: index & 0x0F,
            cmd: cmd.encode(),
        }
    }

    pub fn encode(&self) -> u32 {
        (self.auth_tag as u32) << 24
            | (self.flags as u32) << 20
            | (self.index as u32) << 16
            | (self.cmd as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping(value: u16) -> Command {
        Command::Ping { value }
    }

    #[test]
    fn command_encode_edge_cases() {
        assert_eq!(ping(0).encode(), 0x1000); // min
        assert_eq!(ping(0xABC).encode(), 0x1ABC); // typical
        assert_eq!(ping(0xFFF).encode(), 0x1FFF); // max
        assert_eq!(ping(0x1FFF).encode(), 0x1FFF); // value masked to 12 bits
    }

    #[test]
    fn command_decode_edge_cases() {
        assert_eq!(Command::decode(0x1000), Some(ping(0)));
        assert_eq!(Command::decode(0x1ABC), Some(ping(0xABC)));
        assert_eq!(Command::decode(0x1FFF), Some(ping(0xFFF)));
    }

    #[test]
    fn command_decode_unknown_tag_returns_none() {
        assert_eq!(Command::decode(0x0000), None);
        assert_eq!(Command::decode(0x2000), None);
        assert_eq!(Command::decode(0xFFFF), None);
    }

    #[test]
    fn command_roundtrip() {
        for value in 0..=0x0FFF {
            let cmd = ping(value);
            assert_eq!(Command::decode(cmd.encode()), Some(cmd));
        }
    }

    #[test]
    fn packet_encode_edge_cases() {
        let cmd = ping(0xABC);
        assert_eq!(
            IsnPacket::new(0xAA, Flags::Start as u8, 0x3, cmd).encode(),
            0xAA13_1ABC
        );
        assert_eq!(
            IsnPacket::new(0, Flags::None as u8, 0, ping(0)).encode(),
            0x0000_1000
        );
        assert_eq!(
            IsnPacket::new(0xFF, 0xF, 0xF, ping(0xFFF)).encode(),
            0xFFFF_1FFF
        );
        assert_eq!(
            IsnPacket::new(0, 0xFF, 0xFF, ping(0)).encode(),
            0x00FF_1000
        );
    }
}
