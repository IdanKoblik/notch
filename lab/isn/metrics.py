import numpy as np


def value_bytes(values: list[int], width: int) -> np.ndarray:
    if width < 1:
        raise ValueError("width must be positive")
    mask = (1 << (width * 8)) - 1
    raw = b"".join((value & mask).to_bytes(width, "big") for value in values)
    return np.frombuffer(raw, dtype=np.uint8)


def isn_bytes(isns: list[int]) -> np.ndarray:
    return value_bytes(isns, 4)


def identifier_bytes(identifiers: list[int]) -> np.ndarray:
    return value_bytes(identifiers, 2)


def byte_entropy(isns: list[int]) -> float:
    return entropy(isn_bytes(isns))


def entropy(data: np.ndarray) -> float:
    counts = np.bincount(data, minlength=256)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def chi_square(isns: list[int]) -> float:
    return byte_chi_square(isn_bytes(isns))


def byte_chi_square(data: np.ndarray) -> float:
    counts = np.bincount(data, minlength=256)
    expected = counts.sum() / 256.0
    return float(((counts - expected) ** 2 / expected).sum())


def printable_fraction(isns: list[int]) -> float:
    return byte_printable_fraction(isn_bytes(isns))


def byte_printable_fraction(data: np.ndarray) -> float:
    b = data
    return float(np.mean((b >= 0x20) & (b <= 0x7E)))
