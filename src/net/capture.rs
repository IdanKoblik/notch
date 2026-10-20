use pcap::{Active, Capture, Offline};

pub enum CaptureSource {
    Live(Capture<Active>),
    File(Capture<Offline>),
}

impl CaptureSource {
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }

    pub fn filter(&mut self, filter: &str, optimize: bool) -> Result<(), pcap::Error> {
        match self {
            Self::Live(capture) => capture.filter(filter, optimize),
            Self::File(capture) => capture.filter(filter, optimize),
        }
    }

    pub fn next_packet(&mut self) -> Result<Option<Vec<u8>>, pcap::Error> {
        match self {
            Self::Live(capture) => match capture.next_packet() {
                Ok(packet) => Ok(Some(packet.data.to_vec())),
                Err(pcap::Error::TimeoutExpired) => Ok(None),
                Err(error) => Err(error),
            },
            Self::File(capture) => match capture.next_packet() {
                Ok(packet) => Ok(Some(packet.data.to_vec())),
                Err(pcap::Error::NoMorePackets) => Ok(None),
                Err(error) => Err(error),
            },
        }
    }
}
