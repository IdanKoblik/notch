use clap::ValueEnum;
use pnet::datalink::NetworkInterface;
use std::error::Error as StdError;
use std::net::Ipv4Addr;

use crate::crypto::auth::Auth;
use crate::net::capture::CaptureSource;
use crate::steg::isn::IsnCarrier;

pub mod isn;
pub mod isn_frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CovertChannel {
    #[value(name = "syn-isn")]
    SynIsn,
}

pub trait Carrier<'a> {
    fn send(&mut self, data: &[u8], flags: u8) -> Result<(), Box<dyn StdError>>;
    fn extract(&mut self, capture: &mut CaptureSource) -> Result<(), Box<dyn StdError>>;

    fn get_chunk_size(&self) -> usize;
}

pub fn create_carrier<'a>(
    channel: CovertChannel,
    interface: NetworkInterface,
    source: Ipv4Addr,
    dest: Ipv4Addr,
    dest_port: u16,
    source_port: u16,
    auth: Option<&'a Auth>,
) -> Result<Box<dyn Carrier<'a> + 'a>, Box<dyn StdError>> {
    match channel {
        CovertChannel::SynIsn => {
            Ok(Box::new(IsnCarrier::new(interface, source, dest, dest_port, source_port, auth)?))
        }
    }
}

//pub fn create_carrier<'a>() -> Result<Box<dyn Carrier<'a> + 'a>, Box<dyn StdError>> {
//}

// fn send<'a, C: Carrier<'a>>(
//     carrier: &mut C,
//     data: &[u8],
//     flags: u8,
// ) -> Result<(), Box<dyn StdError>> {
//     carrier.send(data, flags)?;
//     Ok(())
// }
//
// fn extract<'a, C: Carrier<'a>>(
//     carrier: &mut C,
//     capture: &mut CaptureSource,
// ) -> Result<(), Box<dyn StdError>> {
//     carrier.extract(capture)?;
//     Ok(())
// }
