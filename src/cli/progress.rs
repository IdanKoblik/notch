use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

static ACTIVE_PROGRESS: OnceLock<Mutex<Option<ProgressBar>>> = OnceLock::new();

fn active_progress() -> &'static Mutex<Option<ProgressBar>> {
    ACTIVE_PROGRESS.get_or_init(|| Mutex::new(None))
}

pub struct ProgressLogWriter(Vec<u8>);

impl ProgressLogWriter {
    pub fn new() -> Self {
        Self(Vec::new())
    }
}

impl Write for ProgressLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ProgressLogWriter {
    fn drop(&mut self) {
        let line = String::from_utf8_lossy(&self.0);
        let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if line.is_empty() {
            return;
        }

        let progress = active_progress().lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(progress) = progress {
            progress.println(line);
        } else {
            eprintln!("{line}");
        }
    }
}

pub struct ProgressLogGuard;

impl Drop for ProgressLogGuard {
    fn drop(&mut self) {
        *active_progress().lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

pub fn route_logs_to(progress: &ProgressBar) -> ProgressLogGuard {
    *active_progress().lock().unwrap_or_else(|e| e.into_inner()) = Some(progress.clone());
    ProgressLogGuard
}

pub fn make_progress(total_bytes: Option<u64>) -> ProgressBar {
    let progress = total_bytes.map_or_else(ProgressBar::new_spinner, ProgressBar::new);
    let style = if total_bytes.is_some() {
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} {msg}",
        )
    } else {
        ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {bytes} {msg}")
    }
    .expect("valid progress bar template")
    .progress_chars("=>-");
    progress.set_style(style);
    if total_bytes.is_none() {
        progress.enable_steady_tick(Duration::from_millis(100));
    }
    progress
}

#[cfg(test)]
mod tests {
    use super::make_progress;

    #[test]
    fn known_payload_progress_tracks_bytes() {
        let progress = make_progress(Some(12));

        assert_eq!(progress.length(), Some(12));
        progress.inc(5);
        assert_eq!(progress.position(), 5);
    }

    #[test]
    fn unknown_payload_uses_spinner_progress() {
        let progress = make_progress(None);

        assert_eq!(progress.length(), None);
        progress.inc(5);
        assert_eq!(progress.position(), 5);
        progress.finish_and_clear();
    }
}
