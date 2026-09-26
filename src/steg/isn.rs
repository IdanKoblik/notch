#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Listen { timestamp: u8, window: u8 },
}

impl Command {
    pub fn tag(&self) -> u16 {
        match self {
            Command::Listen { .. } => 0x1,
        }
    }

    pub fn encode(&self) -> u16 {
        let tag = self.tag() << 12;
        let value = match self {
            Command::Listen { timestamp, window } => {
                (*timestamp as u16) << 4 | (*window as u16 & 0x0F)
            }
        };
        tag | value
    }

    pub fn decode(cmd: u16) -> Option<Self> {
        let tag = (cmd >> 12) & 0x0F;
        let value = cmd & 0x0FFF;

        match tag {
            0x1 => {
                let timestamp = (value >> 4) as u8;
                let window = (value & 0x0F) as u8;
                Some(Command::Listen { timestamp, window })
            }
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Flags {
    None = 0x0,
    Start = 0x1,
    End = 0x2
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
