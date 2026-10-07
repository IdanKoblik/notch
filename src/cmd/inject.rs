use crate::cli::ask::confirm;
use crate::cmd::inject::CovertChannel::SynIsn;
use crate::cmd::inject::OutputFormat::Pcap;
use crate::crypto::num::encrypt_u32;
use crate::net::ip::{find_ipv4, parse_interface};
use crate::net::tcp::{self, construct_tcp_syn, send_syn};
use crate::steg::isn::{Command, Flags, IsnPacket};
use clap::{Args, ValueEnum};
use hmac::{Hmac, KeyInit, Mac};
use pcap::{Active, Capture};
use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{TransportChannelType, TransportProtocol, transport_channel};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::ErrorKind;
use std::io::prelude::Read;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::{env, fs::OpenOptions, io};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing auth secret")]
    MissingSecret,

    #[error("source ip is missing")]
    MissingSourceIp,

    #[error("raw transport sockets require CAP_NET_RAW")]
    PermissionDenied,

    #[error("invalid HMAC secret length")]
    InvalidSecretLength,

    #[error("payload ended with an incomplete command; expected {0} bytes per command")]
    IncompletePayload(usize),

    #[error("packet rate must be a finite, nonnegative value")]
    InvalidPacketRate,

    #[error("failed to construct TCP packet: {0}")]
    Tcp(#[from] tcp::Error),

    #[error("CLI error")]
    Cli(#[from] crate::cli::Error),

    #[error("Pcap error {0}")]
    Pcap(#[from] pcap::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    None,
    Pcap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CovertChannel {
    #[value(name = "syn-isn")]
    SynIsn
}

#[derive(Args)]
pub struct InjectCmd {
    #[arg(long)]
    dest: Ipv4Addr,

    #[arg(long = "port", default_value_t = 6769)]
    dest_port: u16,

    #[arg(long = "source-port", default_value_t = 6769)]
    source_port: u16,

    #[arg(short, long, value_parser = parse_interface)]
    interface: NetworkInterface,

    #[arg(long = "no-auth", default_value_t = false)]
    no_auth: bool,

    #[arg(
        long,
        default_value = "",
        help = "Payload to inject. Alternatively, pipe the payload through stdin."
    )]
    payload: String,

    /// Maximum packets per second, 0 sends without pacing.
    #[arg(long, default_value_t = 0.0)]
    rate: f64,

    #[arg(long, default_value_t = false)]
    verbose: bool,

    #[arg(long = "output", value_enum, default_value_t = OutputFormat::None)]
    output_format: OutputFormat,

    #[arg(long, value_enum, default_value_t = CovertChannel::SynIsn)]
    channel: CovertChannel,
}

type HmacSha256 = Hmac<Sha256>;

impl InjectCmd {
    fn print_details(&self, source: Ipv4Addr) {
        eprintln!("Injection details:");
        eprintln!("  source: {} ({})", source, self.interface.name);
        eprintln!("  destination: {}:{}", self.dest, self.dest_port);
        eprintln!("  source port: {}", self.source_port);
        eprintln!( "  authentication: {}",
            if self.no_auth { "disabled" } else { "enabled" }
        );
        eprintln!(
            "  payload: {}",
            if self.payload.is_empty() {
                "standard input"
            } else {
                self.payload.as_str()
            }
        );
    }

    fn get_network_cap(&self, interface_name: &str) -> Result<(Capture<Active>, Capture<Active>), pcap::Error> {
        let mut rx_cap = Capture::from_device(interface_name)?
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true) // Delivers packets instantly
            .open()?;

        if self.channel == SynIsn {
            rx_cap.filter("tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0", true)?;
        }

        rx_cap.filter(format!("tcp port {}", self.source_port).as_str(), true)?;

        let mut tx_cap = Capture::from_device(interface_name)?
            .open()?;

        Ok((rx_cap, tx_cap))
    }

    pub fn run(&self) -> Result<(), Error> {
        if !self.rate.is_finite() || self.rate < 0.0 {
            return Err(Error::InvalidPacketRate);
        }

        let source = find_ipv4(&self.interface).ok_or(Error::MissingSourceIp)?;

        self.print_details(source);

        let chunk_size = if self.no_auth { 4 } else { 2 };
        if self.payload.is_empty() {
            eprintln!("  packets: unknown (payload is read from standard input)");
        } else {
            let bytes = std::fs::metadata(&self.payload)?.len();
            eprintln!(
                "  packets: {} complete commands ({} payload bytes / {} bytes per packet)",
                bytes / chunk_size as u64,
                bytes,
                chunk_size
            );
            if bytes % chunk_size as u64 != 0 {
                eprintln!(
                    "  note: trailing incomplete payload bytes will cause an error after complete commands are sent"
                );
            }
        }

        if self.rate == 0.0 {
            eprintln!("  packet pacing: none (maximum send rate; potentially high network noise)");
            eprintln!("WARNING: this injection is unpaced and may create high network noise.");
        }

        if !confirm()? {
            eprintln!("injection cancelled");
            return Ok(());
        }

        let protocol =
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
        let (mut tx, _rx) = transport_channel(4096, protocol).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => Error::PermissionDenied,
            _ => Error::Io(e),
        })?;

        let mut src: Box<dyn Read> = if self.payload.is_empty() {
            Box::new(io::stdin().lock())
        } else {
            Box::new(File::open(&self.payload)?)
        };

        let mut mac = None;
        let mut secret: Option<[u8; 32]> = None;
        if !self.no_auth {
            let raw_secret = env::var("SECRET").map_err(|_| Error::MissingSecret)?;
            let secret_bytes: [u8; 32] = Sha256::digest(raw_secret.as_bytes()).into();
            mac = Some(
                HmacSha256::new_from_slice(&secret_bytes)
                    .map_err(|_| Error::InvalidSecretLength)?,
            );
            secret = Some(secret_bytes);
        }

        let mut index: u8 = 0;
        let mut first = true;
        let mut packets_sent: u64 = 0;
        let packet_period = if self.rate > 0.0 {
            Some(
                Duration::try_from_secs_f64(1.0 / self.rate)
                    .map_err(|_| Error::InvalidPacketRate)?,
            )
        } else {
            None
        };
        let mut next_packet = Instant::now();

        loop {
            let mut current = vec![0u8; chunk_size];
            let n = read_command(&mut src, &mut current)?;
            if n == 0 {
                break;
            }

            if n != chunk_size {
                return Err(Error::IncompletePayload(chunk_size));
            }

            let is_last = n < chunk_size;
            let flags = if first {
                Flags::Start
            } else if is_last {
                Flags::End
            } else {
                Flags::None
            };

            let isn = if self.no_auth {
                u32::from_be_bytes(current[..4].try_into().unwrap())
            } else {
                let raw = u16::from_be_bytes(current[..2].try_into().unwrap());

                let mut m = mac.as_ref().unwrap().clone();
                m.update(&[index]);

                let auth_tag = m.finalize().into_bytes()[index as usize];

                let cmd = Command::Ping { value: raw };
                let packet = IsnPacket::new(auth_tag, flags as u8, index, cmd);

                index = index.wrapping_add(1);

                let raw_isn = packet.encode();
                encrypt_u32(raw_isn, &secret.unwrap())
            };

            let tcp = construct_tcp_syn(source, self.dest, self.source_port, self.dest_port, isn)?;

            if self.verbose {
                eprintln!("isn: 0x{isn:08x}");
                eprintln!(
                    "tcp: {}",
                    tcp.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }

            send_syn(&mut tx, &tcp, self.dest)?;
            packets_sent += 1;

            if let Some(period) = packet_period {
                next_packet += period;
                let now = Instant::now();
                if now < next_packet {
                    std::thread::sleep(next_packet - now);
                } else {
                    // Do not build up a backlog if sending falls behind.
                    next_packet = now;
                }
            }

            first = false;
            if is_last {
                break;
            }
        }

        eprintln!("sent {packets_sent} packets");
        Ok(())
    }
}

fn read_command(src: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match src.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
