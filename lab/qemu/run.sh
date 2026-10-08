#!/usr/bin/env bash
#
# run.sh — build notch, bake it into a Buildroot rootfs via the BR2_EXTERNAL
#          tree in this directory, and boot the resulting image under QEMU.
#
# The directory holding external.desc is the Buildroot external tree, so its
# configs/<role>_defconfig and board/<role>/ are discovered by Buildroot when
# BR2_EXTERNAL points here.
#
# Usage:
#   qemu/run.sh <role> [-- <extra qemu args>...]
#
#   <role>   board/config name (e.g. "sender"); requires
#            configs/<role>_defconfig and board/<role>/ in the external tree.
#
# Environment:
#   BUILDROOT   path to a Buildroot source checkout (required unless NO_BUILD=1)
#   BR_OUTPUT   Buildroot output dir    (default: <repo>/target/buildroot/<role>)
#   NOTCH_BIN   cargo binary to install (default: notch)
#   QEMU        qemu binary             (default: qemu-system-x86_64)
#   QEMU_MEM    guest memory            (default: 512M)
#   NO_BUILD=1  skip cargo + Buildroot and boot the existing image as-is
#
set -euo pipefail

die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '>> %s\n' "$*" >&2; }

# --- args ---------------------------------------------------------------------
ROLE="${1:-}"
[ -n "$ROLE" ] || die "usage: $0 <role> [-- <extra qemu args>...]"
shift
QEMU_EXTRA=()
if [ "${1:-}" = "--" ]; then
  shift
  QEMU_EXTRA=("$@")
fi

# --- paths --------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXTERNAL="$(dirname "$SCRIPT_DIR")"        # BR2_EXTERNAL tree (holds external.desc)
[ -f "$EXTERNAL/external.desc" ] || die "no external.desc beside $EXTERNAL — not a Buildroot external tree"
ROOT="$(git -C "$EXTERNAL" rev-parse --show-toplevel)"  # cargo workspace root

NOTCH_BIN="${NOTCH_BIN:-notch}"
QEMU="${QEMU:-qemu-system-x86_64}"
QEMU_MEM="${QEMU_MEM:-512M}"
BR_OUTPUT="${BR_OUTPUT:-$ROOT/target/buildroot/$ROLE}"

DEFCONFIG="$EXTERNAL/configs/${ROLE}_defconfig"
OVERLAY="$EXTERNAL/board/$ROLE/rootfs"
[ -f "$DEFCONFIG" ]   || die "missing defconfig: $DEFCONFIG"
[ -d "$EXTERNAL/board/$ROLE" ] || die "missing board dir: $EXTERNAL/board/$ROLE"

IMG_DIR="$EXTERNAL/images/$ROLE"
KERNEL="$IMG_DIR/bzImage"
FS="$IMG_DIR/rootfs.ext2"

# --- build --------------------------------------------------------------------
if [ "${NO_BUILD:-0}" != "1" ]; then
  info "cargo build --release ($NOTCH_BIN)"
  cargo build --release --manifest-path "$ROOT/Cargo.toml" --bin "$NOTCH_BIN"

  info "installing $NOTCH_BIN into overlay: $OVERLAY/usr/bin/"
  mkdir -p "$OVERLAY/usr/bin"
  install -m 0755 "$ROOT/target/release/$NOTCH_BIN" "$OVERLAY/usr/bin/$NOTCH_BIN"

  # Locate Buildroot: explicit $BUILDROOT wins, else probe common checkout spots.
  if [ -z "${BUILDROOT:-}" ]; then
    for cand in "$HOME/Projects/buildroot" "$ROOT/../buildroot" "$HOME/buildroot" "$HOME/src/buildroot"; do
      if [ -f "$cand/Makefile" ]; then BUILDROOT="$cand"; info "found Buildroot: $BUILDROOT"; break; fi
    done
  fi
  [ -n "${BUILDROOT:-}" ] || die "Buildroot not found. Set BUILDROOT=/path/to/buildroot (or NO_BUILD=1 to boot the existing image)."
  [ -f "$BUILDROOT/Makefile" ] || die "BUILDROOT=$BUILDROOT is not a Buildroot checkout (no Makefile)."

  # Only (re)configure when there is no .config yet, or the defconfig changed.
  # Buildroot does not rebuild packages on a config change by itself, so
  # rewriting .config every run only adds churn; skip it when already current.
  if [ ! -f "$BR_OUTPUT/.config" ] || [ "$DEFCONFIG" -nt "$BR_OUTPUT/.config" ]; then
    info "buildroot: configuring ${ROLE}_defconfig (O=$BR_OUTPUT)"
    make -C "$BUILDROOT" BR2_EXTERNAL="$EXTERNAL" O="$BR_OUTPUT" "${ROLE}_defconfig"
  else
    info "buildroot: .config already current, skipping defconfig"
  fi

  # Do NOT pass a top-level -j: Buildroot's top-level make is not parallel-safe
  # (it races the kernel's arch/x86/boot/compressed link). Each package is
  # already built in parallel via BR2_JLEVEL (0 = auto = nproc+1).
  info "buildroot: building image"
  make -C "$BUILDROOT" O="$BR_OUTPUT"

  info "publishing images -> $IMG_DIR"
  mkdir -p "$IMG_DIR"
  cp -f "$BR_OUTPUT/images/bzImage"     "$KERNEL"
  cp -f "$BR_OUTPUT/images/rootfs.ext2" "$FS"
fi

# --- boot ---------------------------------------------------------------------
[ -f "$KERNEL" ] || die "missing kernel: $KERNEL (run without NO_BUILD=1 to build it)"
[ -f "$FS" ]     || die "missing rootfs: $FS (run without NO_BUILD=1 to build it)"

TAP="tap-$ROLE"
if [ ! -e "/sys/class/net/$TAP" ]; then
  die "host tap '$TAP' not found. Create the isolated bridge + taps once, as root:
       sudo $SCRIPT_DIR/bridge-up.sh $ROLE
     then re-run this as your normal user. Do NOT 'sudo' this script — it builds
     with your Rust toolchain, which root does not have."
fi

ACCEL=()
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu host)
  info "using KVM acceleration"
fi

# Display: headless on the terminal by default; GUI=1 opens a QEMU window while
# keeping the serial console on stdio (so pexpect/automation still drives it).
# 'quiet loglevel=3' keeps kernel printk (e.g. e1000 link-up) from interleaving
# with — and corrupting — commands typed on the serial console by automation.
APPEND="rootwait root=/dev/vda console=ttyS0 quiet loglevel=3"
DISPLAY_ARGS=(-nographic)
if [ "${GUI:-0}" = "1" ]; then
  APPEND="$APPEND console=tty0"     # also render the console in the graphical window
  DISPLAY_ARGS=(-serial stdio)      # window shown by the default UI; serial -> stdio
  info "GUI mode: opening a QEMU window (serial still on stdio)"
fi

info "booting $ROLE: $KERNEL + $FS"
exec "$QEMU" \
  "${ACCEL[@]}" \
  -m "$QEMU_MEM" \
  -kernel "$KERNEL" \
  -append "$APPEND" \
  -drive "file=$FS,format=raw,if=virtio" \
  -netdev "tap,id=net0,ifname=$TAP,script=no,downscript=no" \
  -device "e1000,netdev=net0" \
  "${DISPLAY_ARGS[@]}" \
  "${QEMU_EXTRA[@]}"
