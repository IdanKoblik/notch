#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Flags {
    None = 0x0,
    Start = 0x1,
    End = 0x2,
    Partial = 0x4,
}

pub struct IsnFrame {
    pub auth_tag: u8,
    pub flags: u8,
    pub index: u8,
    pub value: u16,
}

impl IsnFrame {
    pub fn new(auth_tag: u8, flags: u8, index: u8, value: u16) -> Self {
        Self { auth_tag, flags: flags & 0x0F, index: index & 0x0F, value }
    }

    pub fn encode(&self) -> u32 {
        (self.auth_tag as u32) << 24
            | (self.flags as u32) << 20
            | (self.index as u32) << 16
            | (self.value as u32)
    }

    pub fn decode(value: u32) -> Self {
        Self {
            auth_tag: (value >> 24) as u8,
            flags: ((value >> 20) & 0x0f) as u8,
            index: ((value >> 16) & 0x0f) as u8,
            value: value as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let frame = IsnFrame::new(0xAB, 0x1F, 0x2E, 0x1234);
        let decoded = IsnFrame::decode(frame.encode());
        assert_eq!(decoded.auth_tag, 0xAB);
        assert_eq!(decoded.flags, 0x0F);
        assert_eq!(decoded.index, 0x0E);
        assert_eq!(decoded.value, 0x1234);
    }

    #[test]
    fn decode_extracts_each_field() {
        let decoded = IsnFrame::decode(0xA56B_CDEF);
        assert_eq!(
            (decoded.auth_tag, decoded.flags, decoded.index, decoded.value),
            (0xA5, 0x06, 0x0B, 0xCDEF)
        );
    }
}
