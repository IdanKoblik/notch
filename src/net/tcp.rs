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
    isn: u32
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
