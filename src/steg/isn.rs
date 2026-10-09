#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Ping { value: u16 },
}

impl Command {
    pub fn encode(&self) -> u16 {
        match self {
            Command::Ping { value } => *value,
        }
    }

    #[allow(unused)]
    pub fn decode(cmd: u16) -> Option<Self> {
        Some(Command::Ping { value: cmd })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Flags {
    None = 0x0,
    Start = 0x1,
    End = 0x2,
    Partial = 0x4,
}

pub struct IsnPacket {
    pub auth_tag: u8,
    pub flags: u8,
    pub index: u8,
    pub cmd: u16,
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

    pub fn decode(value: u32) -> Self {
        Self {
            auth_tag: (value >> 24) as u8,
            flags: ((value >> 20) & 0x0f) as u8,
            index: ((value >> 16) & 0x0f) as u8,
            cmd: value as u16,
        }
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
        assert_eq!(ping(0).encode(), 0); // min
        assert_eq!(ping(0xABCD).encode(), 0xABCD); // typical
        assert_eq!(ping(0xFFFF).encode(), 0xFFFF); // max
    }

    #[test]
    fn command_decode_edge_cases() {
        assert_eq!(Command::decode(0), Some(ping(0)));
        assert_eq!(Command::decode(0xABCD), Some(ping(0xABCD)));
        assert_eq!(Command::decode(0xFFFF), Some(ping(0xFFFF)));
    }

    #[test]
    fn command_decode_preserves_all_payload_bits() {
        assert_eq!(Command::decode(0x0000), Some(ping(0)));
        assert_eq!(Command::decode(0xABCD), Some(ping(0xABCD)));
    }

    #[test]
    fn command_roundtrip() {
        for value in 0..=u16::MAX {
            let cmd = ping(value);
            assert_eq!(Command::decode(cmd.encode()), Some(cmd));
        }
    }

    #[test]
    fn packet_encode_edge_cases() {
        let cmd = ping(0xABC);
        assert_eq!(
            IsnPacket::new(0xAA, Flags::Start as u8, 0x3, cmd).encode(),
            0xAA13_0ABC
        );
        assert_eq!(
            IsnPacket::new(0, Flags::None as u8, 0, ping(0)).encode(),
            0x0000_0000
        );
        assert_eq!(
            IsnPacket::new(0xFF, 0xF, 0xF, ping(0xFFF)).encode(),
            0xFFFF_0FFF
        );
        assert_eq!(IsnPacket::new(0, 0xFF, 0xFF, ping(0)).encode(), 0x00FF_0000);
    }

    #[test]
    fn packet_decode_roundtrip() {
        let packet = IsnPacket::new(0xA5, 0x7, 0xD, ping(0xBEEF));
        let decoded = IsnPacket::decode(packet.encode());
        assert_eq!(decoded.auth_tag, 0xA5);
        assert_eq!(decoded.flags, 0x7);
        assert_eq!(decoded.index, 0xD);
        assert_eq!(decoded.cmd, 0xBEEF);
    }
}
