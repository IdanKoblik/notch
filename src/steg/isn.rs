use std::error::Error as StdError;
use std::io::ErrorKind;
use std::io::{self, Write};
use std::net::Ipv4Addr;

use hmac::{KeyInit, Mac};
use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    TransportChannelType, TransportProtocol, TransportReceiver, TransportSender, transport_channel,
};
use thiserror::Error;
use tracing::debug;

use super::Carrier;
use crate::crypto::HmacSha256;
use crate::crypto::auth::Auth;
use crate::crypto::num::{decrypt_u32, encrypt_u32};
use crate::net::capture::CaptureSource;
use crate::net::tcp::{self, construct_tcp_syn, extract_isn, send_syn};
use crate::steg::isn_frame::{Command, Flags, IsnFrame};

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing auth secret")]
    MissingAuth,

    #[error(
        "capture ended before a complete payload was found; output may be incomplete or corrupted"
    )]
    MissingEndMarker,

    #[error("authenticated ISN sequence space is exhausted")]
    SequenceSpaceExhausted,

    #[error("payload chunk must be 2 bytes with authentication or 4 bytes without authentication")]
    InvalidChunkSize,

    #[error("raw transport sockets require CAP_NET_RAW")]
    PermissionDenied,

    #[error("failed to construct TCP packet: {0}")]
    Tcp(#[from] tcp::Error),

    #[error("capture error: {0}")]
    Capture(#[from] pcap::Error),

    #[error("output error: {0}")]
    Io(#[from] io::Error),
}

pub fn packet_tag(mac: &HmacSha256, index: u32, flags: u8, value: u16) -> u8 {
    let mut tagger = mac.clone();
    tagger.update(&index.to_be_bytes());
    tagger.update(&[flags]);
    tagger.update(&value.to_be_bytes());
    tagger.finalize().into_bytes()[0]
}

pub struct IsnCarrier<'a> {
    pub interface: NetworkInterface,
    pub source: Ipv4Addr,
    pub dest: Ipv4Addr,
    pub dest_port: u16,
    pub source_port: u16,

    pub tx: TransportSender,
    pub rx: TransportReceiver,

    pub auth: Option<&'a Auth>,
    index: u32,
}

impl<'a> Carrier<'a> for IsnCarrier<'a> {
    fn send(&mut self, data: &[u8], flags: u8) -> Result<(), Box<dyn StdError>> {
        let isn = match self.auth {
            None => {
                let bytes: [u8; 4] = data.try_into().map_err(|_| Error::InvalidChunkSize)?;
                u32::from_be_bytes(bytes)
            }
            Some(auth) => {
                if self.index == u32::MAX {
                    return Err(Error::SequenceSpaceExhausted.into());
                }
                let bytes: [u8; 2] = data.try_into().map_err(|_| Error::InvalidChunkSize)?;
                let raw = u16::from_be_bytes(bytes);
                let auth_tag = packet_tag(&auth.mac, self.index, flags, raw);
                let packet =
                    IsnFrame::new(auth_tag, flags, self.index as u8, Command::Ping { value: raw });
                encrypt_u32(packet.encode(), &auth.secret)
            }
        };

        let tcp = construct_tcp_syn(self.source, self.dest, self.source_port, self.dest_port, isn)?;
        send_syn(&mut self.tx, &tcp, self.dest)?;
        if self.auth.is_some() {
            self.index += 1;
        }

        debug!("isn: 0x{isn:08x}");
        Ok(())
    }

    fn extract(&mut self, capture: &mut CaptureSource) -> Result<(), Box<dyn StdError>> {
        let auth = self.auth.ok_or(Error::MissingAuth)?;
        let filter = format!("tcp dst port {}", self.dest_port);
        capture.filter(&filter, true)?;

        let mut expected_index = 0u32;
        let mut started = false;
        let mut stdout = io::stdout().lock();
        loop {
            let Some(packet) = capture.next_packet()? else {
                if capture.is_live() {
                    continue;
                }
                return Err(Error::MissingEndMarker.into());
            };
            let Some(isn) = extract_isn(&packet) else {
                continue;
            };
            let decoded = IsnFrame::decode(decrypt_u32(isn, &auth.secret));
            if u32::from(decoded.index) != (expected_index & 0x0f) {
                continue;
            }
            if packet_tag(&auth.mac, expected_index, decoded.flags, decoded.cmd) != decoded.auth_tag
            {
                continue;
            }

            if !started {
                if decoded.flags & Flags::Start as u8 == 0 {
                    continue;
                }
                started = true;
            }
            let Command::Ping { value } =
                Command::decode(decoded.cmd).ok_or(Error::MissingEndMarker)?;
            let bytes = value.to_be_bytes();
            if decoded.flags & Flags::Partial as u8 != 0 {
                stdout.write_all(&bytes[..1])?;
            } else {
                stdout.write_all(&bytes)?;
            }
            expected_index = expected_index.wrapping_add(1);
            if decoded.flags & Flags::End as u8 != 0 {
                stdout.flush()?;
                return Ok(());
            }
        }
    }

    fn get_chunk_size(&self) -> usize {
        if self.auth.is_some() { 2 } else { 4 }
    }
}

impl<'a> IsnCarrier<'a> {
    pub fn new(
        interface: NetworkInterface,
        source: Ipv4Addr,
        dest: Ipv4Addr,
        dest_port: u16,
        source_port: u16,
        auth: Option<&'a Auth>,
    ) -> Result<Self, Error> {
        let protocol =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (tx, rx) = transport_channel(4096, protocol).map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                Error::PermissionDenied
            } else {
                Error::Io(error)
            }
        })?;

        Ok(Self { interface, source, dest, dest_port, source_port, tx, rx, auth, index: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mac() -> HmacSha256 {
        HmacSha256::new_from_slice(b"test key").unwrap()
    }

    #[test]
    fn packet_tag_is_deterministic() {
        let mac = test_mac();
        assert_eq!(packet_tag(&mac, 7, 0x01, 0x1234), packet_tag(&mac, 7, 0x01, 0x1234));
    }

    #[test]
    fn packet_tag_covers_sequence_flags_and_payload() {
        let mac = test_mac();
        let original = packet_tag(&mac, 7, 0x01, 0x1234);

        assert_ne!(original, packet_tag(&mac, 8, 0x01, 0x1234));
        assert_ne!(original, packet_tag(&mac, 7, 0x02, 0x1234));
        assert_ne!(original, packet_tag(&mac, 7, 0x01, 0x1235));
    }
}
