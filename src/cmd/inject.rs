use std::env;
use std::io::{ErrorKind};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use clap::Args;
use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol, TransportSender};
use sha2::{Digest, Sha256};
use hmac::{Hmac, KeyInit, Mac};
use crate::crypto::num::encrypt_u32;
use crate::net::tcp::{TcpError, construct_tcp_syn};
use crate::steg::isn::{Flags, IsnPacket, Command};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InjectCmdError {
    #[error("missing auth secret")]
    MissingSecret,

    #[error("source ip is missing")]
    MissingSourceIp,

    #[error("raw transport sockets require CAP_NET_RAW")]
    PermissionDenied,

    #[error("invalid HMAC secret length")]
    InvalidSecretLength,

    #[error("malformed TCP packet")]
    InvalidTCP,

    #[error("failed to construct TCP packet: {0}")]
    Tcp(#[from] TcpError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

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

type HmacSha256 = Hmac<Sha256>;

impl InjectCmd {
    pub fn run(&self) -> Result<(), InjectCmdError> {
        let now = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards :O")
            .as_secs()
        ) as u8;

        let source = self.interface.ips.iter().find_map(|ip| {
            match ip {
                ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            }
        }).ok_or(InjectCmdError::MissingSourceIp)?;

        let raw_secret = env::var("SECRET").map_err(|_| InjectCmdError::MissingSecret)?;
        let secret: [u8; 32] = Sha256::digest(raw_secret.as_bytes()).into();

        let mut mac = HmacSha256::new_from_slice(&secret).map_err(|_| InjectCmdError::InvalidSecretLength)?;

        let protocol = TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, _rx) = transport_channel(4096, protocol)
            .map_err(|e| match e.kind() {
                ErrorKind::PermissionDenied => InjectCmdError::PermissionDenied,
                _ => InjectCmdError::Io(e),
            })?;

        for index in 1..=3 {
            mac.update(&[index]);
            let auth_tag = mac.clone().finalize().into_bytes()[index as usize];

            let flags = match index {
                1 => Flags::Start,
                3 => Flags::End,
                _ => Flags::None,
            };

            let cmd = Command::Listen { timestamp: now, window: 12 }; // TODO Not hardcoded
            let packet = IsnPacket::new(auth_tag, flags as u8, index, cmd);
            let raw_isn = packet.encode();
            let isn = encrypt_u32(raw_isn, &secret);

            let tcp = construct_tcp_syn(source, self.dest, self.source_port, self.dest_port, isn)?;
            eprintln!("isn: 0x{isn:08x}");
            eprintln!("tcp: {}", tcp.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
            send_syn(&mut tx, &tcp, self.dest)?;
        }

        Ok(())
    }
}

fn send_syn(
    tx: &mut TransportSender,
    packet_bytes: &[u8],
    dest_ip: Ipv4Addr,
) -> Result<(), InjectCmdError> {
    let packet = TcpPacket::new(packet_bytes).ok_or(InjectCmdError::InvalidTCP)?;
    tx.send_to(packet, IpAddr::V4(dest_ip))?;

    Ok(())
}
