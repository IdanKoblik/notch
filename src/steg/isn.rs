use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use super::cmd;

pub struct IsnPacket {
    auth_tag: u8,
    flags: u8,
    index: u8,
    cmd: u16,
}

impl IsnPacket {
    pub fn new(auth_tag: u8, flags: u8, index: u8, cmd: cmd::Command) -> Self {
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
