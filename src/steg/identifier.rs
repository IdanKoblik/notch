use hmac::Mac;
use pnet::packet::icmp::{IcmpCode, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{TransportChannelType, TransportSender, transport_channel};
use std::error::Error as StdError;
use std::io::{self, ErrorKind, Write};
use std::net::Ipv4Addr;
use thiserror::Error;

use crate::crypto::HmacSha256;
use crate::crypto::auth::Auth;
use crate::crypto::num::{decrypt_u16, encrypt_u16};
use crate::net::capture::CaptureSource;
use crate::net::icmp::{construct_icmp, extract_echo_request, send_icmp};
use crate::steg::Carrier;
use crate::steg::identifier_frame::{Command, IdentifierFrame};
use crate::steg::isn_frame::Flags;
use tracing::debug;

#[derive(Debug, Error)]
pub enum Error {
    #[error("payload chunk must be 2 bytes with authentication or 4 bytes without authentication")]
    InvalidChunkSize,

    #[error("destination address is not set")]
    MissingDest,

    #[error("raw transport sockets require CAP_NET_RAW")]
    PermissionDenied,

    #[error("authenticated ISN sequence space is exhausted")]
    SequenceSpaceExhausted,

    #[error(
        "capture ended before an ICMP end marker was found; output may be incomplete or corrupted"
    )]
    MissingEndMarker,

    #[error("output error: {0}")]
    Io(#[from] io::Error),

    #[error("ICMP error: {0}")]
    Icmp(#[from] crate::net::icmp::Error),
}

pub struct IdentifierCarrier<'a> {
    pub dest: Option<Ipv4Addr>,

    pub tx: TransportSender,
    pub auth: Option<&'a Auth>,

    index: u16,
}

fn packet_tag(mac: &HmacSha256, index: u16, value: u8) -> u8 {
    let mut tagger = mac.clone();
    tagger.update(&index.to_be_bytes());
    tagger.update(&value.to_be_bytes());
    tagger.finalize().into_bytes()[0]
}

impl<'a> Carrier<'a> for IdentifierCarrier<'a> {
    fn send(&mut self, data: &[u8], flags: u8) -> Result<(), Box<dyn StdError>> {
        let dest = self.dest.ok_or(Error::MissingDest)?;
        if self.index == u16::MAX {
            return Err(Error::SequenceSpaceExhausted.into());
        }

        let identifier = match self.auth {
            None => {
                let bytes: [u8; 2] = data.try_into().map_err(|_| Error::InvalidChunkSize)?;
                u16::from_be_bytes(bytes)
            }
            Some(auth) => {
                let bytes: [u8; 1] = data.try_into().map_err(|_| Error::InvalidChunkSize)?;
                let raw = u8::from_be_bytes(bytes);
                let auth_tag = packet_tag(&auth.mac, self.index, raw);
                let frame = IdentifierFrame::Raw { auth_tag, value: raw };
                encrypt_u16(frame.encode(), &auth.secret)
            }
        };

        let icmp = construct_icmp(identifier, self.index, IcmpCode(0), IcmpTypes::EchoRequest)?;
        send_icmp(&mut self.tx, &icmp, dest)?;
        debug!("icmp identifier: 0x{identifier:04x}");
        self.index = self.index.wrapping_add(1);

        if flags & Flags::End as u8 != 0 {
            self.send_end_marker(dest)?;
        }

        Ok(())
    }

    fn extract(&mut self, capture: &mut CaptureSource) -> Result<(), Box<dyn StdError>> {
        let mut expected_index = 0u16;
        let mut stdout = io::stdout().lock();
        capture.filter("icmp", true)?;

        loop {
            let Some(packet) = capture.next_packet()? else {
                if capture.is_live() {
                    continue;
                }
                return Err(Error::MissingEndMarker.into());
            };

            let Some((identifier, sequence)) = extract_echo_request(&packet) else {
                continue;
            };

            if sequence == u16::MAX {
                let frame = match self.auth {
                    Some(auth) => IdentifierFrame::decode(decrypt_u16(identifier, &auth.secret)),
                    None => IdentifierFrame::decode(identifier),
                };
                if matches!(frame, IdentifierFrame::Cmd(Command::Eot)) {
                    stdout.flush()?;
                    return Ok(());
                }
                continue;
            }

            if sequence != expected_index {
                continue;
            }

            let value = match self.auth {
                Some(auth) => {
                    let raw_frame = decrypt_u16(identifier, &auth.secret);
                    let auth_tag = (raw_frame >> 8) as u8;
                    let value = raw_frame as u8;
                    if packet_tag(&auth.mac, expected_index, value) != auth_tag {
                        continue;
                    }
                    stdout.write_all(&[value])?;
                    expected_index = expected_index.wrapping_add(1);
                    continue;
                }
                None => identifier.to_be_bytes(),
            };
            stdout.write_all(&value)?;
            expected_index = expected_index.wrapping_add(1);
        }
    }

    fn get_chunk_size(&self) -> usize {
        if self.auth.is_some() { 1 } else { 2 }
    }
}

impl<'a> IdentifierCarrier<'a> {
    fn send_end_marker(&mut self, dest: Ipv4Addr) -> Result<(), Error> {
        let frame = IdentifierFrame::Cmd(Command::Eot).encode();
        let identifier = match self.auth {
            Some(auth) => encrypt_u16(frame, &auth.secret),
            None => frame,
        };
        let packet = construct_icmp(identifier, u16::MAX, IcmpCode(0), IcmpTypes::EchoRequest)?;
        send_icmp(&mut self.tx, &packet, dest)?;
        debug!("icmp end marker: 0x{identifier:04x}");
        Ok(())
    }

    pub fn new(dest: Option<Ipv4Addr>, auth: Option<&'a Auth>) -> Result<Self, Error> {
        let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, _) = transport_channel(4096, protocol).map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                Error::PermissionDenied
            } else {
                Error::Io(error)
            }
        })?;

        Ok(Self { dest, tx, auth, index: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::KeyInit;

    fn test_mac() -> HmacSha256 {
        HmacSha256::new_from_slice(b"test key").unwrap()
    }

    #[test]
    fn packet_tag_is_deterministic() {
        let mac = test_mac();
        assert_eq!(packet_tag(&mac, 7, 0x12), packet_tag(&mac, 7, 0x12));
    }

    #[test]
    fn packet_tag_covers_sequence_and_payload() {
        let mac = test_mac();
        let original = packet_tag(&mac, 7, 0x12);
        assert_ne!(original, packet_tag(&mac, 8, 0x12));
        assert_ne!(original, packet_tag(&mac, 7, 0x13));
    }
}
