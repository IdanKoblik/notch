#!/usr/bin/env python3
"""
Prerequisites (once):
    sudo ./qemu/bridge-up.sh sender         # host tap + bridge
    ./qemu/run.sh sender                     # build the image once, then Ctrl-a x
"""
import argparse
import logging
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pexpect

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from isn import setup_logging          # noqa: E402
from isn.analyze import analyze        # noqa: E402

log = logging.getLogger("orchestrator")

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", default="sender", help="VM role / defconfig name")
    ap.add_argument("--mode", choices=["no-auth", "auth"], default="no-auth")
    ap.add_argument("--channel", default="syn-isn", help="notch covert channel")
    ap.add_argument("--dest", default="192.168.100.11", help="injection destination IP")
    ap.add_argument("--vm-iface", default="eth0", help="interface inside the VM")
    ap.add_argument("--tap", default="tap-sender", help="host tap to capture on")
    ap.add_argument("--rate", type=float, default=0.0, help="packets/sec (0 = max)")
    ap.add_argument("--secret", default="lab-secret", help="SECRET for --mode auth")
    ap.add_argument("--message", default="HELLO FROM NOTCH - HIDDEN MESSAGE. ",
                    help="payload chunk written inside the VM")
    ap.add_argument("--repeat", type=int, default=45,
                    help="how many times to repeat --message (more = more SYNs)")
    ap.add_argument("--pcap", default=None, help="capture path (default: captures/<ts>.pcap)")
    ap.add_argument("--boot-timeout", type=int, default=120)
    ap.add_argument("--no-analyze", action="store_true", help="capture only, skip analysis")
    ap.add_argument("--gui", action="store_true", help="open a QEMU window (watch/debug the VM)")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args()


def inject_cmd(a: argparse.Namespace) -> str:
    cmd = (f"notch inject --dest {a.dest} -i {a.vm_iface} "
           f"--channel {a.channel} --payload /tmp/p.txt")
    if a.mode == "no-auth":
        cmd += " --no-auth"
    if a.rate > 0:
        cmd += f" --rate {a.rate}"
    if a.mode == "auth":
        cmd = f"SECRET='{a.secret}' " + cmd
    return cmd


def run(a: argparse.Namespace) -> None:
    pcap = Path(a.pcap) if a.pcap else LAB / "captures" / f"{a.role}-{a.mode}-{datetime.now():%Y%m%d-%H%M%S}.pcap"
    pcap.parent.mkdir(parents=True, exist_ok=True)

    log.info("capturing %s -> %s", a.tap, pcap)
    cap = subprocess.Popen(["sudo", "tcpdump", "-i", a.tap, "-U", "-w", str(pcap), "tcp"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    console_fh = None
    try:
        # QEMU still runs -nographic (pexpect needs the serial on stdio), but the
        # noisy boot/kernel console goes to a FILE, not your terminal, unless -v.
        console_path = pcap.with_suffix(".console.log")
        console_fh = open(console_path, "w")
        env = "GUI=1 " if a.gui else ""
        log.info("booting VM (role=%s, gui=%s); console -> %s", a.role, a.gui, console_path)
        vm = pexpect.spawn(f"bash -lc '{env}NO_BUILD=1 {LAB}/qemu/run.sh {a.role}'",
                           encoding="utf-8", timeout=a.boot_timeout)
        vm.logfile_read = sys.stdout if a.verbose else console_fh

        vm.expect(f"{a.role} login:")
        vm.sendline("root")
        vm.expect_exact("# ")

        log.info("writing payload (%d x %d bytes) into the VM", a.repeat, len(a.message))
        vm.sendline(f"i=0; while [ $i -lt {a.repeat} ]; do printf '%s' '{a.message}'; "
                    f"i=$((i+1)); done > /tmp/p.txt")
        vm.expect_exact("# ")

        log.info("waiting for eth0 link, pinning %s", a.dest)
        vm.sendline('while [ "$(cat /sys/class/net/eth0/carrier 2>/dev/null)" != 1 ]; do sleep 0.2; done')
        vm.expect_exact("# ", timeout=30)
        vm.sendline(f"arp -s {a.dest} 02:00:00:00:00:11")
        vm.expect_exact("# ")

        cmd = inject_cmd(a)
        log.info("inject: %s", cmd)
        vm.sendline(cmd)
        vm.expect(r"Proceed with injection\? \[y/N\]")
        vm.sendline("y")
        vm.expect_exact("# ", timeout=60)
        log.info("injection complete")

        vm.sendline("poweroff")
        vm.expect(pexpect.EOF, timeout=60)
    finally:
        log.info("stopping capture")
        cap.send_signal(signal.SIGINT)
        cap.wait()
        if console_fh is not None:
            console_fh.close()

    if a.no_analyze:
        log.info("capture saved (analysis skipped): %s", pcap)
        return
    analyze(str(pcap), out_dir=str(LAB / "results"))


def main() -> None:
    a = parse_args()
    setup_logging(logging.DEBUG if a.verbose else logging.INFO)
    run(a)

if __name__ == "__main__":
    main()
