use crate::cli::ask::confirm;
use crate::cli::progress::make_progress;
use crate::cmd::inject::OutputFormat::Pcap;
use crate::crypto::auth::Auth;
use crate::crypto::num::encrypt_u32;
use crate::net::ip::{find_ipv4, parse_interface};
use crate::net::pcap_capture::PcapCapture;
use crate::net::tcp::{self, construct_tcp_syn, send_syn};
use crate::steg::isn_frame::Flags;
use crate::steg::{Carrier, CovertChannel, create_carrier};
use clap::{Args, ValueEnum};
use hmac::KeyInit;
use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{TransportChannelType, TransportProtocol, transport_channel};
use sha2::Digest;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::io::prelude::Read;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("source ip is missing")]
    MissingSourceIp,

    #[error("raw transport sockets require CAP_NET_RAW")]
    PermissionDenied,

    #[error("packet rate must be a finite, nonnegative value")]
    InvalidPacketRate,

    #[error("Auth error {0}")]
    Auth(#[from] crate::crypto::auth::Error),

    #[error("failed to construct TCP packet: {0}")]
    Tcp(#[from] tcp::Error),

    #[error("CLI error {0}")]
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

#[derive(Args)]
#[command(
    about = "Inject a payload into network traffic using a covert channel.",
    override_usage = "notch inject [OPTIONS] --dest <DEST> --interface <INTERFACE>"
)]
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

    #[arg(long = "output", value_enum, default_value_t = OutputFormat::None)]
    output_format: OutputFormat,

    #[arg(long, value_enum, default_value_t = CovertChannel::SynIsn)]
    channel: CovertChannel,

    #[arg(long = "confirm", default_value_t = false, help = "Automatically confirm injection.")]
    confirmed: bool,
}

impl InjectCmd {
    fn print_details(&self, source: Ipv4Addr) {
        eprintln!("Injection details:");
        eprintln!("  source: {} ({})", source, self.interface.name);
        eprintln!("  destination: {}:{}", self.dest, self.dest_port);
        eprintln!("  source port: {}", self.source_port);
        eprintln!("  authentication: {}", if self.no_auth { "disabled" } else { "enabled" });
        eprintln!(
            "  payload: {}",
            if self.payload.is_empty() { "standard input" } else { self.payload.as_str() }
        );
    }

    pub fn run(&self) -> Result<(), Error> {
        if !self.rate.is_finite() || self.rate < 0.0 {
            return Err(Error::InvalidPacketRate);
        }

        let auth = if self.no_auth {
            None
        } else {
            let auth = Auth::new()?;
            Some(auth)
        };

        let source = find_ipv4(&self.interface).ok_or(Error::MissingSourceIp)?;
        self.print_details(source);

        let mut carrier = create_carrier(
            self.channel,
            self.interface.clone(),
            source,
            self.dest,
            self.dest_port,
            self.source_port,
            auth.as_ref(),
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        let chunk_size = carrier.get_chunk_size();
        let total_bytes = if self.payload.is_empty() {
            None
        } else {
            Some(std::fs::metadata(&self.payload)?.len())
        };
        if self.payload.is_empty() {
            eprintln!("  packets: unknown (payload is read from standard input)");
        } else {
            let bytes = total_bytes.unwrap();
            eprintln!(
                "  packets: {} commands ({} payload bytes / {} bytes per packet)",
                bytes.div_ceil(chunk_size as u64),
                bytes,
                chunk_size
            );
            if bytes % chunk_size as u64 != 0 {
                eprintln!("  note: the final command will be zero-padded to {chunk_size} bytes");
            }
        }

        if self.rate == 0.0 {
            eprintln!("  packet pacing: none (maximum send rate; potentially high network noise)");
            eprintln!("WARNING: this injection is unpaced and may create high network noise.");
        }

        if !self.confirmed && !confirm()? {
            eprintln!("injection cancelled");
            return Ok(());
        }

        let mut pcap_output = if self.output_format == Pcap {
            let path = "inject.pcap";
            eprintln!("writing injected packets to {path}");
            let filter = format!(
                "tcp and src host {source} and dst host {} and src port {} and dst port {}",
                self.dest, self.source_port, self.dest_port
            );
            Some(PcapCapture::start(&self.interface.name, &filter, path)?)
        } else {
            None
        };

        let mut src: Box<dyn Read> = if self.payload.is_empty() {
            Box::new(io::stdin().lock())
        } else {
            Box::new(File::open(&self.payload)?)
        };

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
        let progress = make_progress(total_bytes);

        loop {
            let mut current = vec![0u8; chunk_size];
            let n = read_buffer(&mut src, &mut current)?;
            if n == 0 {
                break;
            }

            let is_last = n < chunk_size;
            let flags = (if first { Flags::Start as u8 } else { Flags::None as u8 })
                | if is_last { Flags::End as u8 } else { 0 }
                | if is_last && n < chunk_size { Flags::Partial as u8 } else { 0 };

            carrier.send(&current, flags).map_err(|error| io::Error::other(error.to_string()))?;

            packets_sent += 1;
            progress.inc(n as u64);
            progress.set_message(format!("{packets_sent} packets"));

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

        if let Some(output) = pcap_output.take() {
            output.finish()?;
        }
        progress.finish_and_clear();
        eprintln!("sent {packets_sent} packets");
        Ok(())
    }
}

fn read_buffer(src: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
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
