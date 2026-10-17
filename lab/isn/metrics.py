import struct

import numpy as np


def isn_bytes(isns: list[int]) -> np.ndarray:
    raw = b"".join(struct.pack("!I", x) for x in isns)
    return np.frombuffer(raw, dtype=np.uint8)


def byte_entropy(isns: list[int]) -> float:
    counts = np.bincount(isn_bytes(isns), minlength=256)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def chi_square(isns: list[int]) -> float:
    counts = np.bincount(isn_bytes(isns), minlength=256)
    expected = counts.sum() / 256.0
    return float(((counts - expected) ** 2 / expected).sum())


def printable_fraction(isns: list[int]) -> float:
    b = isn_bytes(isns)
    return float(np.mean((b >= 0x20) & (b <= 0x7E)))
