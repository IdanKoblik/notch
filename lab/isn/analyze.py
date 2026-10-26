import argparse
import json
import logging
from pathlib import Path

from . import metrics, setup_logging
from plot import plot_randomness

log = logging.getLogger("isn.analyze")

# thresholds (tune freely)
ENTROPY_MIN = 7.0       # below this, ISN bytes are too predictable
CHI_MAX = 1000.0        # above this, the byte histogram is too far from flat
PRINTABLE_MAX = 0.60    # above this, too many bytes are typeable ASCII


def read_isns(pcap: str) -> list[int]:
    from scapy.all import TCP, rdpcap  # imported here so metrics stays pcap-free

    isns: list[int] = []
    for pkt in rdpcap(pcap):
        if TCP not in pkt:
            continue
        flags = int(pkt[TCP].flags)
        if (flags & 0x02) and not (flags & 0x10):
            isns.append(int(pkt[TCP].seq))
    return isns


def analyze(pcap: str, out_dir: str = "results") -> dict:
    isns = read_isns(pcap)
    if not isns:
        raise SystemExit(f"no TCP SYN packets in {pcap}")
    n = len(isns)

    H = metrics.byte_entropy(isns)
    X = metrics.chi_square(isns)
    P = metrics.printable_fraction(isns)
    log.info("loaded %d SYNs from %s", n, pcap)
    log.info("entropy         = %.2f bits  (random ~8.0)", H)
    log.info("chi-square      = %.0f       (random ~255)", X)
    log.info("printable ASCII = %.0f%%      (random ~37%%)", P * 100)

    covert = H < ENTROPY_MIN or X > CHI_MAX or P > PRINTABLE_MAX
    verdict = ("COVERT: ISN is not random - payload hidden in the sequence number"
               if covert else "clean: ISN looks random")
    log.warning("VERDICT -> %s", verdict)

    result = {
        "pcap": pcap, "syns": n,
        "entropy_bits": round(H, 3),
        "chi_square": round(X, 1),
        "printable_fraction": round(P, 3),
        "covert": covert,
        "verdict": verdict,
    }

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap).stem
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2))
    plot_randomness(isns, 4, H, X, P, covert, out / f"{stem}.png", "TCP ISN")
    log.info("wrote %s.json and %s.png to %s/", stem, stem, out_dir)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="ISN steganalysis on a pcap of SYNs")
    ap.add_argument("pcap")
    ap.add_argument("--out", default="results", help="output dir for json + png")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    setup_logging(logging.DEBUG if args.verbose else logging.INFO)
    analyze(args.pcap, args.out)


if __name__ == "__main__":
    main()
