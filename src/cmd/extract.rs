use crate::crypto::auth::Auth;
use crate::net::capture::CaptureSource;
use crate::net::ip::parse_interface;
use crate::steg::{CovertChannel, create_carrier};
use clap::Args;
use pcap::Capture;
use pnet::datalink::NetworkInterface;
use std::io;
use std::path::PathBuf;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum Error {
    #[error("capture error: {0}")]
    Capture(#[from] pcap::Error),

    #[error("provide --pcap or --interface for live capture")]
    MissingCaptureSource,

    #[error("Auth error {0}")]
    Auth(#[from] crate::crypto::auth::Error),

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

    #[arg(long = "source-port", default_value_t = 6769)]
    source_port: u16,

    #[arg(long = "port", default_value_t = 6769)]
    dest_port: u16,

    #[arg(long, value_enum, default_value_t = CovertChannel::SynIsn)]
    channel: CovertChannel,
}

impl ExtractCmd {
    pub fn run(&self) -> Result<(), Error> {
        let mut capture = if let Some(path) = &self.pcap {
            info!("reading packets from {}", path.display());
            CaptureSource::File(Capture::from_file(path)?)
        } else if let Some(interface) = &self.interface {
            info!("capturing authenticated packets on {}", interface.name);
            CaptureSource::Live(
                Capture::from_device(interface.name.as_str())?
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(1000)
                    .open()?,
            )
        } else {
            return Err(Error::MissingCaptureSource);
        };

        let auth = Some(Auth::new()?);
        let mut carrier = create_carrier(
            self.channel,
            None,
            None,
            self.dest_port,
            self.source_port,
            auth.as_ref(),
        )
        .map_err(|error| io::Error::other(error.to_string()))?;

        carrier.extract(&mut capture).map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }
}
