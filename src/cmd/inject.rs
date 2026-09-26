use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use clap::Args;
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, TransportSender};
use super::Cmd;
use crate::net::tcp::construct_tcp_syn;
use crate::steg::isn::IsnPacket;
use crate::steg::cmd::Command;

fn parse_interface(s: &str) -> Result<datalink::NetworkInterface, String> {
    pnet::datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == s)
        .ok_or_else(|| format!("network interface not found: {s}"))
}

#[derive(Args)]
pub struct InjectCmd {
    #[arg(long)]
    dest: Ipv4Addr,

    #[arg(long = "port", default_value_t = 6769)]
    dest_port: u16,

    #[arg(long, default_value_t = 6769)]
    source_port: u16,

    #[arg(short, long, value_parser = parse_interface)]
    interface: NetworkInterface,

    // TODO
    //#[arg(short, long)]
    //payload: String,
}

impl Cmd for InjectCmd {
    fn run(&self) -> Result<(), Error> {
        let now = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards :O")
            .as_secs()
        ) as u8;

        let cmd = Command::Listen { timestamp: now, window: 12 }; // TODO Not hardcoded
        let flags: u8 = 0; // TODO
        let index: u8 = 0; // TODO

        let packet = IsnPacket::new(0x0, flags, index, cmd); // TODO auth
        let isn = packet.encode();

        let source = self.interface.ips.iter().find_map(|ip| {
            match ip {
                ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            }
        }).expect("TODO custom error");

        let tcp = construct_tcp_syn(source, self.dest, self.source_port, self.dest_port, isn) .map_err(|e| Error::new(ErrorKind::Other, e))?;
        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));

        eprintln!("isn: 0x{isn:08x}");
        eprintln!("tcp: {}", tcp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
        let (mut tx, _rx) = transport_channel(4096, protocol).map_err(|e| {
            if e.kind() == ErrorKind::PermissionDenied {
                Error::new(
                    ErrorKind::PermissionDenied,
                    "raw transport sockets need CAP_NET_RAW: run with `sudo`, or grant it once \
                     with `sudo setcap cap_net_raw+ep ./notch`",
                )
            } else {
                e
            }
        })?;
        send_syn(&mut tx, &tcp, self.dest)?;

        Ok(())
    }
}

fn send_syn(
    tx: &mut TransportSender,
    packet_bytes: &[u8],
    dest_ip: Ipv4Addr,
) -> Result<(), Error> {
    let packet = TcpPacket::new(packet_bytes) .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "malformed TCP packet"))?;
    tx.send_to(packet, IpAddr::V4(dest_ip))?;

    Ok(())
}
