import argparse
import json
import logging
from pathlib import Path

from . import metrics, setup_logging

log = logging.getLogger("isn.analyze")

# thresholds (tune freely)
ENTROPY_MIN = 7.0       # below this, ISN bytes are too predictable
CHI_MAX = 1000.0        # above this, the byte histogram is too far from flat
PRINTABLE_MAX = 0.60    # above this, too many bytes are typeable ASCII


def read_isns(pcap: str) -> list[int]:
    """Pull the sequence number (ISN) out of every SYN (SYN set, ACK clear)."""
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
    _plot(isns, H, X, P, covert, out / f"{stem}.png")
    log.info("wrote %s.json and %s.png to %s/", stem, stem, out_dir)
    return result


_RED, _TEAL, _GREY = "#d1495b", "#2e86ab", "#9aa7b2"

def _plot(isns, H, X, P, covert, path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception as e:  # analysis still works without plots
        log.warning("skipping graphs (matplotlib unavailable: %s)", e)
        return

    fig = plt.figure(figsize=(13, 5.2))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.25, 1])
    ax_s, ax_m = fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[0, 1])

    # --- left: captured ISNs vs a random reference (band vs cloud) ---
    ref = np.random.randint(0, 2 ** 32, size=len(isns))
    ax_s.scatter(range(len(ref)), ref, s=7, color=_GREY, alpha=0.45,
                 label="a real (random) ISN", edgecolors="none")
    ax_s.scatter(range(len(isns)), isns, s=7, color=_RED if covert else _TEAL,
                 label="your capture", edgecolors="none")
    ax_s.axhspan(0x20202020, 0x7E7E7E7E, color="#f2a154", alpha=0.15)
    ax_s.text(len(isns) * 0.5, 0x51000000, "typed text lands in this band",
              ha="center", va="center", fontsize=9, color="#9c6316")
    ax_s.set_ylim(0, 2 ** 32)
    ax_s.set_yticks([0, 2 ** 31, 2 ** 32], ["0", "2.1 B", "4.3 B"])
    ax_s.set_xlabel("packet #")
    ax_s.set_ylabel("sequence number (ISN)")
    ax_s.set_title("Where the sequence numbers sit", fontweight="bold", loc="left")
    ax_s.legend(loc="upper right", framealpha=0.9, fontsize=9)
    for sp in ("top", "right"):
        ax_s.spines[sp].set_visible(False)

    # --- right: three suspicion meters (left = random/safe, right = hidden) ---
    def clip01(v):
        return float(max(0.0, min(1.0, v)))

    rows = [
        ("Entropy", f"{H:.1f} bits", clip01((8.0 - H) / 4.0), H < ENTROPY_MIN, "~8.0"),
        ("Printable chars", f"{P * 100:.0f}%", clip01((P - 0.37) / 0.63), P > PRINTABLE_MAX, "~37%"),
        ("Byte spread (χ²)", f"{X:,.0f}",
         clip01((np.log10(max(X, 1)) - np.log10(255)) / (np.log10(30000) - np.log10(255))),
         X > CHI_MAX, "~255"),
    ]
    ax_m.set_xlim(0, 1)
    ax_m.set_ylim(0, 1)
    ax_m.axis("off")
    ax_m.set_title("Randomness checks", fontweight="bold", loc="left")
    ys = [0.74, 0.46, 0.18] # three evenly-spaced rows, vertically centered
    for (name, val, pos, susp, rnd), y in zip(rows, ys):
        color = _RED if susp else _TEAL
        x0, x1 = 0.02, 0.98
        ax_m.plot([x0, x1], [y, y], color="#e6eaee", lw=9,
                  solid_capstyle="round", zorder=1)
        ax_m.text(x0, y + 0.085, name, fontsize=11, fontweight="bold")
        mark = "✗ looks hidden" if susp else "✓ looks random"
        ax_m.text(x1, y + 0.085, f"{val}   {mark}", ha="right", fontsize=10,
                  color=color, fontweight="bold")
        ax_m.text(x0, y - 0.085, f"random {rnd}", fontsize=8, color="#7a8690", va="top")
        ax_m.text(x1, y - 0.085, "hidden text", ha="right", fontsize=8,
                  color="#7a8690", va="top")

    verdict = "COVERT — data hidden in the ISN" if covert else "CLEAN — ISN looks random"
    fig.suptitle(verdict, fontsize=15, fontweight="bold",
                 color=_RED if covert else _TEAL)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(path, dpi=100)
    plt.close(fig)


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
