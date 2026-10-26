"""Basic randomness checks for ICMP echo identifiers in a pcap."""

import argparse
import json
import logging
from pathlib import Path

from isn import metrics, setup_logging
from plot import plot_randomness

log = logging.getLogger("icmp.analyze")

ENTROPY_MIN = 7.0
CHI_MAX = 1000.0
PRINTABLE_MAX = 0.60


def read_identifiers(pcap: str) -> list[int]:
    from scapy.all import ICMP, rdpcap

    identifiers = []
    for packet in rdpcap(pcap):
        if ICMP not in packet:
            continue
        icmp = packet[ICMP]
        if int(icmp.type) == 8 and int(icmp.code) == 0 and int(icmp.seq) != 0xFFFF:
            identifiers.append(int(icmp.id))
    return identifiers


def analyze(pcap: str, out_dir: str = "results") -> dict:
    identifiers = read_identifiers(pcap)
    if not identifiers:
        raise SystemExit(f"no ICMP echo requests in {pcap}")

    data = metrics.identifier_bytes(identifiers)
    entropy = metrics.entropy(data)
    chi_square = metrics.byte_chi_square(data)
    printable = metrics.byte_printable_fraction(data)
    covert = entropy < ENTROPY_MIN or chi_square > CHI_MAX or printable > PRINTABLE_MAX
    verdict = (
        "COVERT: ICMP identifiers look payload-shaped"
        if covert
        else "clean: ICMP identifiers look random"
    )

    log.info("loaded %d ICMP echo requests from %s", len(identifiers), pcap)
    log.info("entropy         = %.2f bits  (random ~8.0)", entropy)
    log.info("chi-square      = %.0f       (random ~255)", chi_square)
    log.info("printable bytes = %.0f%%      (random ~37%%)", printable * 100)
    log.warning("VERDICT -> %s", verdict)

    result = {
        "pcap": pcap,
        "echo_requests": len(identifiers),
        "entropy_bits": round(entropy, 3),
        "chi_square": round(chi_square, 1),
        "printable_fraction": round(printable, 3),
        "covert": covert,
        "verdict": verdict,
    }

    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap).stem
    (output_dir / f"{stem}.json").write_text(json.dumps(result, indent=2) + "\n")
    plot_randomness(
        identifiers, 2, entropy, chi_square, printable, covert,
        output_dir / f"{stem}.png", "ICMP identifier",
    )
    log.info("wrote %s.json and %s.png to %s/", stem, stem, output_dir)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", help="capture containing ICMP echo requests")
    parser.add_argument("--out", default="results", help="directory for JSON and PNG output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    analyze(args.pcap, args.out)


if __name__ == "__main__":
    main()
