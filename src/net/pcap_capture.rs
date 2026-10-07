use pcap::{Active, Capture, Savefile};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};

pub struct PcapCapture {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<(), pcap::Error>>>,
}

impl PcapCapture {
    pub fn start(interface: &str, filter: &str, path: &str) -> Result<Self, pcap::Error> {
        let mut capture = Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .open()?
            .setnonblock()?;
        capture.filter(filter, true)?;
        let output = capture.savefile(path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::sync_channel(0);
        let worker = thread::spawn(move || capture_to_file(capture, output, worker_stop, ready_tx));
        ready_rx
            .recv()
            .map_err(|_| pcap::Error::PcapError("capture worker failed to start".into()))?;

        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }

    pub fn finish(mut self) -> Result<(), pcap::Error> {
        self.stop.store(true, Ordering::Release);
        self.join()
    }

    fn join(&mut self) -> Result<(), pcap::Error> {
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .unwrap_or_else(|_| Err(pcap::Error::PcapError("capture worker panicked".into()))),
            None => Ok(()),
        }
    }
}

impl Drop for PcapCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.join();
    }
}

fn capture_to_file(
    mut capture: Capture<Active>,
    mut output: Savefile,
    stop: Arc<AtomicBool>,
    ready: mpsc::SyncSender<()>,
) -> Result<(), pcap::Error> {
    let mut ready = Some(ready);
    loop {
        match capture.next_packet() {
            Ok(packet) => output.write(&packet),
            Err(pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired)
                if stop.load(Ordering::Acquire) =>
            {
                return output.flush();
            }
            Err(pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired) => {
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}
