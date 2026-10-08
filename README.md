# Notch

> **For learning purposes.** This project demonstrates network steganography and
> can be used as an offensive tool. Use it only on systems and networks you are
> authorized to test. You are responsible for how you use it and for complying
> with applicable laws; use it at your own risk.

Work-in-progress network steganography tool. Prebuilt downloads,
when available, are published on [GitHub Releases](https://github.com/IdanKoblik/notch/releases).

## Injection Methods

| Method                | Status      | Details                                                                       |
| --------------------- | ----------- | ----------------------------------------------------------------------------- |
| TCP SYN ISN injection | Available   | Encodes payload data in the Initial Sequence Number (ISN) of TCP SYN packets. |
| ICMP                  | TODO        | Planned transport method.                                                     |

> Authenticated injection - Uses `SECRET` to authenticate encoded data.  
>

## Build

Prefer not to build from source? Grab a prebuilt binary for your platform from
the [GitHub Releases](https://github.com/IdanKoblik/notch/releases) page, make
it executable (`chmod +x notch`), and skip the rest of this section.

Otherwise, install Rust and build with Cargo:

```sh
cargo build --release
```

## Inject a payload

The payload is read from standard input by default. Each authenticated packet
encodes two payload bytes; use `--no-auth` to encode four bytes per packet.
Authenticated mode requires the `SECRET` environment variable.

```sh
printf '\x12\x34' | sudo -E target/release/notch inject \
  --dest 192.0.2.10 --interface eth0
```

To read payload bytes from a file instead, pass its path with `--payload`:

```sh
sudo -E SECRET='shared secret' target/release/notch inject \
  --dest 192.0.2.10 --interface eth0 --payload payload.bin --rate 10
```

The sender displays the injection details and asks for confirmation before
sending. Raw TCP packet transmission requires `CAP_NET_RAW` (often provided by
running with `sudo`).

Run `notch inject --help` for all options. This project is in active development;
there is no receiver command yet.

## QEMU lab

The `lab/` directory is a [Buildroot](https://buildroot.org/) `BR2_EXTERNAL`
tree that boots `notch` inside QEMU VMs on an isolated L2 network. Three scripts
in `lab/qemu/` drive it:

| Script            | Run as | Purpose                                                                                   |
| ----------------- | ------ | ----------------------------------------------------------------------------------------- |
| `bridge-up.sh`    | root   | Create the isolated bridge `br-notch` and per-node tap(s), owned by your user.            |
| `run.sh`          | you    | Build `notch`, bake it into the role's rootfs via Buildroot, and boot it under QEMU.      |
| `bridge-down.sh`  | root   | Remove the tap(s) and the bridge once empty.                                              |

Typical session (from `lab/`):

```sh
sudo ./qemu/bridge-up.sh sender     # once per boot session; creates tap-sender
./qemu/run.sh sender                # as your user — do NOT sudo (it builds with your Rust toolchain)
sudo ./qemu/bridge-down.sh sender   # tear down when done
```

## Formatting & linting

A repo pre-commit hook (`.githooks/pre-commit`) checks
formatting before each commit — enable it with:

```bash
git config core.hooksPath .githooks
```
