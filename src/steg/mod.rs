use pnet::datalink::NetworkInterface;
use std::error::Error as StdError;
use std::net::Ipv4Addr;

use crate::crypto::auth::Auth;
use crate::net::capture::CaptureSource;

pub mod isn;
pub mod isn_frame;

pub trait Carrier<'a>: Sized {
    type Error: StdError + 'static;

    fn new(
        interface: NetworkInterface,
        source: Ipv4Addr,
        dest: Ipv4Addr,
        dest_port: u16,
        source_port: u16,
        auth: Option<&'a Auth>,
    ) -> Result<Self, Self::Error>;

    fn send(&mut self, data: &[u8], flags: u8) -> Result<(), Self::Error>;
    fn extract(&mut self, capture: &mut CaptureSource) -> Result<(), Self::Error>;
}

fn send<'a, C: Carrier<'a>>(
    carrier: &mut C,
    data: &[u8],
    flags: u8,
) -> Result<(), Box<dyn StdError>> {
    carrier.send(data, flags)?;
    Ok(())
}

fn extract<'a, C: Carrier<'a>>(
    carrier: &mut C,
    capture: &mut CaptureSource,
) -> Result<(), Box<dyn StdError>> {
    carrier.extract(capture)?;
    Ok(())
}
