"""Pure statistics over a list of TCP ISNs (one uint32 per SYN).

Three checks, all answering one question: do these ISNs look random (a real OS)
or not (notch hid data in them)?

  - byte_entropy        how unpredictable the ISN bytes are      (random ~8.0)
  - chi_square          how far the byte distribution is from flat (random ~255)
  - printable_fraction  share of ISN bytes that are typeable ASCII (random ~0.37)

No pcap, no matplotlib here, so these are trivially unit-testable.
"""
import struct

import numpy as np


def isn_bytes(isns: list[int]) -> np.ndarray:
    """Flat uint8 array of all ISN bytes (4 per ISN, big-endian)."""
    raw = b"".join(struct.pack("!I", x) for x in isns)
    return np.frombuffer(raw, dtype=np.uint8)


def byte_entropy(isns: list[int]) -> float:
    """Shannon entropy of the ISN bytes, in bits. Random ~8.0, text ~4.3."""
    counts = np.bincount(isn_bytes(isns), minlength=256)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def chi_square(isns: list[int]) -> float:
    """Chi-square of the byte histogram against a flat distribution.

    Small (~255) when every byte value is equally likely; huge when a few values
    dominate (text). Scales with sample size, so compare within a run.
    """
    counts = np.bincount(isn_bytes(isns), minlength=256)
    expected = counts.sum() / 256.0
    return float(((counts - expected) ** 2 / expected).sum())


def printable_fraction(isns: list[int]) -> float:
    """Fraction of ISN bytes in the printable ASCII range 0x20..0x7e.

    Random ~0.37; a text payload ~1.0.
    """
    b = isn_bytes(isns)
    return float(np.mean((b >= 0x20) & (b <= 0x7E)))
