use crate::cli::ask::confirm;
use crate::cli::progress::make_progress;
use crate::cmd::inject::OutputFormat::Pcap;
use crate::crypto::auth::Auth;
use crate::net::ip::{find_ipv4, parse_interface};
use crate::net::pcap_capture::PcapCapture;
use crate::net::tcp;
use crate::steg::isn_frame::Flags;
use crate::steg::{CovertChannel, create_carrier};
use clap::{Args, ValueEnum};
use pnet::datalink::NetworkInterface;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::io::prelude::Read;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum Error {
    #[error("source ip is missing")]
    MissingSourceIp,

    #[error("packet rate must be a finite, nonnegative value")]
    InvalidPacketRate,

    #[error("--port and --source-port are only available with --channel syn-isn")]
    IcmpPortsUnsupported,

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
    #[arg(long = "dest", help = "Destination IPv4 address.")]
    dest: Ipv4Addr,

    #[arg(long = "port", help = "Destination TCP port (syn-isn channel only).")]
    dest_port: Option<u16>,

    #[arg(long = "source-port", help = "Source TCP port (syn-isn channel only).")]
    source_port: Option<u16>,

    #[arg(short, long = "interface", value_parser = parse_interface, help = "Network interface to send through.")]
    interface: NetworkInterface,

    #[arg(long = "no-auth", default_value_t = false, help = "Disable authentication.")]
    no_auth: bool,

    #[arg(
        long = "payload",
        default_value = "",
        help = "Payload to inject. Alternatively, pipe the payload through stdin."
    )]
    payload: String,

    #[arg(
        long = "rate",
        default_value_t = 0.0,
        help = "Maximum packets per second; 0 sends without pacing."
    )]
    rate: f64,

    #[arg(long = "output", value_enum, default_value_t = OutputFormat::None, help = "Write injected packets to a capture file.")]
    output_format: OutputFormat,

    #[arg(long = "channel", value_enum, default_value_t = CovertChannel::SynIsn, help = "Covert channel to use.")]
    channel: CovertChannel,

    #[arg(
        long = "confirm",
        default_value_t = false,
        help = "Skip the injection confirmation prompt."
    )]
    confirmed: bool,
}

impl InjectCmd {
    fn print_details(&self, source: Ipv4Addr) {
        eprintln!(" Injection details:");
        eprintln!("   source={source} interface={}", self.interface.name);
        eprintln!("   destination={}", self.dest);
        if self.channel == CovertChannel::SynIsn {
            eprintln!("   destination_port={}", self.dest_port.unwrap_or(6769));
            eprintln!("   source_port={}", self.source_port.unwrap_or(6769));
        }
        eprintln!("   authentication={}", if self.no_auth { "disabled" } else { "enabled" });
        eprintln!(
            "   payload={}",
            if self.payload.is_empty() { "standard input" } else { &self.payload }
        );
    }

    pub fn run(&self) -> Result<(), Error> {
        if self.channel == CovertChannel::Icmp
            && (self.dest_port.is_some() || self.source_port.is_some())
        {
            return Err(Error::IcmpPortsUnsupported);
        }

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
            Some(source),
            Some(self.dest),
            self.dest_port.unwrap_or(6769),
            self.source_port.unwrap_or(6769),
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
            info!("packets: unknown (payload is read from standard input)");
        } else {
            let bytes = total_bytes.unwrap();
            info!(
                "packets: {} packets ({} payload bytes / {} bytes per packet)",
                bytes.div_ceil(chunk_size as u64),
                bytes,
                chunk_size
            );
            if bytes % chunk_size as u64 != 0 {
                info!("the final packet will be zero-padded to {chunk_size} bytes");
            }
        }

        if self.rate == 0.0 {
            warn!("packet pacing: none (maximum send rate; potentially high network noise)");
            warn!("this injection is unpaced and may create high network noise");
        }

        if !self.confirmed && !confirm()? {
            error!("injection cancelled");
            return Ok(());
        }

        let mut pcap_output = if self.output_format == Pcap {
            let path = "inject.pcap";
            info!("writing injected packets to {path}");
            let filter = match self.channel {
                CovertChannel::SynIsn => format!(
                    "tcp and src host {source} and dst host {} and src port {} and dst port {}",
                    self.dest,
                    self.source_port.unwrap_or(6769),
                    self.dest_port.unwrap_or(6769)
                ),
                CovertChannel::Icmp => {
                    format!("icmp and src host {source} and dst host {}", self.dest)
                }
            };
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
        let _progress_log_guard = crate::cli::progress::route_logs_to(&progress);

        let mut current = vec![0u8; chunk_size];
        let mut n = read_buffer(&mut src, &mut current)?;
        while n > 0 {
            let mut next = vec![0u8; chunk_size];
            let next_n = if n == chunk_size { read_buffer(&mut src, &mut next)? } else { 0 };
            let is_last = n < chunk_size || next_n == 0;
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
            current = next;
            n = next_n;
        }

        if let Some(output) = pcap_output.take() {
            output.finish()?;
        }
        progress.finish_and_clear();
        info!("injection complete: {packets_sent} packets sent");
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
