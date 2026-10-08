import logging

def setup_logging(level: int = logging.INFO) -> None:
    """Consistent, readable logging for the orchestrator and analyzer."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-5s | %(name)-12s | %(message)s",
        datefmt="%H:%M:%S",
    )
    # Keep noisy third-party DEBUG chatter (matplotlib font scan, etc.) out of -v.
    for noisy in ("matplotlib", "PIL", "scapy.runtime"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
