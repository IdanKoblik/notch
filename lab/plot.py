"""Shared scorecard plot for covert values of different widths."""

import logging
from pathlib import Path

log = logging.getLogger("lab.plot")

ENTROPY_MIN = 7.0
CHI_MAX = 1000.0
PRINTABLE_MAX = 0.60

RED, TEAL, GREY = "#d1495b", "#2e86ab", "#9aa7b2"


def plot_randomness(
    values: list[int],
    width_bytes: int,
    entropy: float,
    chi_square: float,
    printable_fraction: float,
    covert: bool,
    path: Path,
    value_name: str,
) -> None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception as error:  # Analysis still works when plotting dependencies are absent.
        log.warning("skipping graph (matplotlib unavailable: %s)", error)
        return

    maximum = 1 << (width_bytes * 8)
    low_text = int.from_bytes(b"\x20" * width_bytes, "big")
    high_text = int.from_bytes(b"\x7e" * width_bytes, "big")
    color = RED if covert else TEAL

    figure = plt.figure(figsize=(13, 5.2))
    grid = figure.add_gridspec(1, 2, width_ratios=[1.25, 1])
    values_axis = figure.add_subplot(grid[0, 0])
    meters_axis = figure.add_subplot(grid[0, 1])

    reference = np.random.randint(0, maximum, size=len(values))
    positions = range(len(values))
    values_axis.scatter(
        positions, reference, s=7, color=GREY, alpha=0.45,
        label="random reference", edgecolors="none",
    )
    values_axis.scatter(
        positions, values, s=7, color=color,
        label="your capture", edgecolors="none",
    )
    values_axis.axhspan(low_text, high_text, color="#f2a154", alpha=0.15)
    values_axis.text(
        len(values) * 0.5, (low_text + high_text) / 2,
        "printable text values", ha="center", va="center",
        fontsize=9, color="#9c6316",
    )
    values_axis.set_ylim(0, maximum)
    middle_label = "2.1 B" if width_bytes == 4 else f"{maximum // 2:,}"
    top_label = "4.3 B" if width_bytes == 4 else f"{maximum - 1:,}"
    values_axis.set_yticks([0, maximum // 2, maximum], ["0", middle_label, top_label])
    values_axis.set_xlabel("packet #")
    values_axis.set_ylabel(value_name)
    values_axis.set_title("Where the packet values sit", fontweight="bold", loc="left")
    values_axis.legend(loc="upper right", framealpha=0.9, fontsize=9)
    for spine in ("top", "right"):
        values_axis.spines[spine].set_visible(False)

    def clip01(value: float) -> float:
        return float(max(0.0, min(1.0, value)))

    rows = [
        ("Entropy", f"{entropy:.1f} bits", clip01((8.0 - entropy) / 4.0),
         entropy < ENTROPY_MIN, "~8.0"),
        ("Printable chars", f"{printable_fraction * 100:.0f}%",
         clip01((printable_fraction - 0.37) / 0.63),
         printable_fraction > PRINTABLE_MAX, "~37%"),
        ("Byte spread (χ²)", f"{chi_square:,.0f}",
         clip01((np.log10(max(chi_square, 1)) - np.log10(255)) /
                (np.log10(30000) - np.log10(255))),
         chi_square > CHI_MAX, "~255"),
    ]
    meters_axis.set_xlim(0, 1)
    meters_axis.set_ylim(0, 1)
    meters_axis.axis("off")
    meters_axis.set_title("Randomness checks", fontweight="bold", loc="left")
    for (name, value, position, suspicious, random_hint), y in zip(rows, [0.74, 0.46, 0.18]):
        meter_color = RED if suspicious else TEAL
        left, right = 0.02, 0.98
        meters_axis.plot(
            [left, right], [y, y], color="#e6eaee", lw=9,
            solid_capstyle="round", zorder=1,
        )
        meters_axis.scatter([left + position * (right - left)], [y], s=55,
                            color=meter_color, zorder=2)
        meters_axis.text(left, y + 0.085, name, fontsize=11, fontweight="bold")
        state = "✗ looks hidden" if suspicious else "✓ looks random"
        meters_axis.text(right, y + 0.085, f"{value}   {state}", ha="right", fontsize=10,
                         color=meter_color, fontweight="bold")
        meters_axis.text(left, y - 0.085, f"random {random_hint}", fontsize=8,
                         color="#7a8690", va="top")
        meters_axis.text(right, y - 0.085, "hidden text", ha="right", fontsize=8,
                         color="#7a8690", va="top")

    verdict = "COVERT" if covert else "CLEAN"
    figure.suptitle(
        f"{verdict} — {value_name} " + ("looks payload-shaped" if covert else "looks random"),
        fontsize=15, fontweight="bold", color=color,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.94))
    figure.savefig(path, dpi=100)
    plt.close(figure)
