use std::net::{IpAddr, Ipv4Addr};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, IcmpTypes, checksum};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::TransportSender;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to create ICMP packet")]
    PacketCreation,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn construct_icmp(
    identifier: u16,
    sequence: u16,
    code: IcmpCode,
    icmp_type: IcmpType,
) -> Result<Vec<u8>, Error> {
    let mut icmp_buffer = vec![0u8; 8];
    {
        let mut icmp_packet =
            MutableEchoRequestPacket::new(&mut icmp_buffer).ok_or(Error::PacketCreation)?;
        icmp_packet.set_icmp_type(icmp_type);
        icmp_packet.set_icmp_code(code);
        icmp_packet.set_identifier(identifier);
        icmp_packet.set_sequence_number(sequence);
        icmp_packet.set_checksum(0);
    }

    let checksum = checksum(&IcmpPacket::new(&icmp_buffer).ok_or(Error::PacketCreation)?);
    MutableEchoRequestPacket::new(&mut icmp_buffer)
        .ok_or(Error::PacketCreation)?
        .set_checksum(checksum);

    Ok(icmp_buffer)
}

pub fn extract_echo_request(data: &[u8]) -> Option<(u16, u16)> {
    let ethernet = EthernetPacket::new(data)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }

    let icmp = IcmpPacket::new(ipv4.payload())?;
    if icmp.get_icmp_type() != IcmpTypes::EchoRequest || icmp.get_icmp_code() != IcmpCode(0) {
        return None;
    }

    let echo = EchoRequestPacket::new(icmp.packet())?;
    Some((echo.get_identifier(), echo.get_sequence_number()))
}

pub fn send_icmp(
    tx: &mut TransportSender,
    packet_bytes: &[u8],
    dest_ip: Ipv4Addr,
) -> Result<(), Error> {
    let packet = IcmpPacket::new(packet_bytes).ok_or(Error::PacketCreation)?;
    tx.send_to(packet, IpAddr::V4(dest_ip))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::icmp::{IcmpTypes, echo_request::EchoRequestPacket};

    #[test]
    fn constructs_echo_request_with_expected_fields_and_checksum() {
        let bytes = construct_icmp(0x1234, 0x5678, IcmpCode(0), IcmpTypes::EchoRequest).unwrap();
        let packet = EchoRequestPacket::new(&bytes).unwrap();
        assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(packet.get_icmp_code(), IcmpCode(0));
        assert_eq!(packet.get_identifier(), 0x1234);
        assert_eq!(packet.get_sequence_number(), 0x5678);
        assert_eq!(packet.get_checksum(), checksum(&IcmpPacket::new(&bytes).unwrap()));
    }

    #[test]
    fn creates_minimum_size_icmp_packet() {
        let bytes = construct_icmp(0, 0, IcmpCode(0), IcmpTypes::EchoRequest).unwrap();
        assert_eq!(bytes.len(), 8);
    }
}
