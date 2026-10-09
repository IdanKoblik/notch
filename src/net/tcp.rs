use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::transport::TransportSender;
use std::net::{IpAddr, Ipv4Addr};
use std::vec::Vec;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to create TCP packet")]
    PacketCreation,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn construct_tcp_syn(
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    isn: u32,
) -> Result<Vec<u8>, Error> {
    let mut tcp_buffer = vec![0u8; 20];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).ok_or(Error::PacketCreation)?;

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(dest_port);

    tcp_packet.set_sequence(isn);
    tcp_packet.set_acknowledgement(0); // 0 for SYN packet
    tcp_packet.set_data_offset(5); // 32-bit header (20 bytes / 4 = 5)
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0); // Common TCP window value

    let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &dest_ip);
    tcp_packet.set_checksum(checksum);

    Ok(tcp_buffer)
}

pub fn send_syn(
    tx: &mut TransportSender,
    packet_bytes: &[u8],
    dest_ip: Ipv4Addr,
) -> Result<(), Error> {
    let packet = TcpPacket::new(packet_bytes).ok_or(Error::PacketCreation)?;
    tx.send_to(packet, IpAddr::V4(dest_ip))?;

    Ok(())
}

/// Returns the sequence number from a captured Ethernet/IPv4 TCP SYN packet.
/// Non-IPv4, non-TCP, non-SYN, and malformed frames are ignored.
pub fn extract_isn(data: &[u8]) -> Option<u32> {
    let ethernet = EthernetPacket::new(data)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = TcpPacket::new(ipv4.payload())?;
    if tcp.get_flags() & TcpFlags::SYN == 0 || tcp.get_flags() & TcpFlags::ACK != 0 {
        return None;
    }
    Some(tcp.get_sequence())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_ipv4_tcp(flags: u8, sequence: u32) -> [u8; 54] {
        let mut bytes = [0u8; 54];
        bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
        bytes[23] = 6;
        bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        bytes[46] = 0x50;
        bytes[47] = flags;
        bytes
    }

    #[test]
    fn extracts_sequence_from_tcp_syn() {
        assert_eq!(
            extract_isn(&ethernet_ipv4_tcp(TcpFlags::SYN, 0x1234_5678)),
            Some(0x1234_5678)
        );
    }

    #[test]
    fn ignores_non_syn_and_syn_ack_packets() {
        assert_eq!(extract_isn(&ethernet_ipv4_tcp(0x10, 7)), None);
        assert_eq!(
            extract_isn(&ethernet_ipv4_tcp(TcpFlags::SYN | TcpFlags::ACK, 7)),
            None
        );
    }

    #[test]
    fn ignores_non_ipv4_and_malformed_frames() {
        let mut packet = ethernet_ipv4_tcp(TcpFlags::SYN, 7);
        packet[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert_eq!(extract_isn(&packet), None);
        assert_eq!(extract_isn(&[0; 3]), None);
    }
}
