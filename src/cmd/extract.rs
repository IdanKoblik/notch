use crate::crypto::num::decrypt_u32;
use crate::net::ip::parse_interface;
use crate::net::tcp::extract_isn;
use crate::steg::isn::{Command, Flags, IsnPacket};
use clap::Args;
use hmac::{Hmac, KeyInit, Mac};
use pcap::{Active, Capture, Offline};
use pnet::datalink::NetworkInterface;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::PathBuf;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("capture error: {0}")]
    Capture(#[from] pcap::Error),

    #[error("invalid authenticated packet")]
    InvalidPacket,

    #[error("capture ended before a complete payload was found")]
    MissingEndMarker,

    #[error("provide --pcap or --interface for live capture")]
    MissingCaptureSource,

    #[error("output error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Args)]
#[command(about = "Extract an authenticated payload from TCP SYN packets.")]
pub struct ExtractCmd {
    #[arg(short, long, value_parser = parse_interface, required_unless_present = "pcap")]
    interface: Option<NetworkInterface>,

    #[arg(long, value_name = "FILE")]
    pcap: Option<PathBuf>,

    #[arg(long, default_value_t = 6769)]
    port: u16,

    #[arg(long, required = true)]
    secret: String,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

impl ExtractCmd {
    pub fn run(&self) -> Result<(), Error> {
        let key: [u8; 32] = Sha256::digest(self.secret.as_bytes()).into();
        let mut capture = if let Some(path) = &self.pcap {
            if self.verbose {
                eprintln!("reading packets from {}", path.display());
            }
            CaptureSource::File(Capture::from_file(path)?)
        } else if let Some(interface) = &self.interface {
            if self.verbose {
                eprintln!("capturing authenticated SYN packets on {}", interface.name);
            }
            CaptureSource::Live(
                Capture::from_device(interface.name.as_str())?
                    .promisc(true)
                    .snaplen(65535)
                    .open()?,
            )
        } else {
            return Err(Error::MissingCaptureSource);
        };
        let filter = format!("tcp dst port {}", self.port);
        capture.filter(&filter, true)?;
        if self.verbose {
            eprintln!("using capture filter: {filter}");
        }

        let mut expected_index = 0u8;
        let mut started = false;
        let mut stdout = io::stdout().lock();
        loop {
            let Some(packet) = capture.next_packet()? else {
                return Err(Error::MissingEndMarker);
            };
            let Some(isn) = extract_isn(&packet) else {
                continue;
            };
            let decoded = IsnPacket::decode(decrypt_u32(isn, &key));
            if decoded.index != (expected_index & 0x0f) {
                if self.verbose {
                    eprintln!(
                        "ignoring SYN with unexpected packet index {} (expected {})",
                        decoded.index,
                        expected_index & 0x0f
                    );
                }
                continue;
            }

            let mut mac = HmacSha256::new_from_slice(&key).expect("SHA-256 key is valid");
            mac.update(&[expected_index]);
            if mac.finalize().into_bytes()[expected_index as usize] != decoded.auth_tag {
                if self.verbose {
                    eprintln!(
                        "ignoring SYN with invalid authentication tag at packet {}",
                        expected_index
                    );
                }
                continue;
            }

            if !started {
                if decoded.flags & Flags::Start as u8 == 0 {
                    continue;
                }
                started = true;
            }
            let Command::Ping { value } =
                Command::decode(decoded.cmd).ok_or(Error::InvalidPacket)?;
            let bytes = value.to_be_bytes();
            if decoded.flags & Flags::Partial as u8 != 0 {
                stdout.write_all(&bytes[..1])?;
            } else {
                stdout.write_all(&bytes)?;
            }
            if self.verbose {
                eprintln!(
                    "extracted packet {} ({} byte{})",
                    expected_index,
                    if decoded.flags & Flags::Partial as u8 != 0 {
                        1
                    } else {
                        2
                    },
                    if decoded.flags & Flags::Partial as u8 != 0 {
                        ""
                    } else {
                        "s"
                    }
                );
            }
            expected_index = expected_index.wrapping_add(1);
            if decoded.flags & Flags::End as u8 != 0 {
                stdout.flush()?;
                if self.verbose {
                    eprintln!("received end marker");
                }
                return Ok(());
            }
        }
    }
}

enum CaptureSource {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl CaptureSource {
    fn filter(&mut self, filter: &str, optimize: bool) -> Result<(), pcap::Error> {
        match self {
            Self::Live(capture) => capture.filter(filter, optimize),
            Self::File(capture) => capture.filter(filter, optimize),
        }
    }

    fn next_packet(&mut self) -> Result<Option<Vec<u8>>, pcap::Error> {
        match self {
            Self::Live(capture) => capture
                .next_packet()
                .map(|packet| Some(packet.data.to_vec())),
            Self::File(capture) => match capture.next_packet() {
                Ok(packet) => Ok(Some(packet.data.to_vec())),
                Err(pcap::Error::NoMorePackets) => Ok(None),
                Err(error) => Err(error),
            },
        }
    }
}
