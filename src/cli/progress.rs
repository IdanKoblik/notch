use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

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
